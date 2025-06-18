// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/mman.h>

#include <linux/memfd.h>
#include <linux/dma-buf.h>
#include <linux/udmabuf.h>

#include "liburing.h"
#include "helpers.h"

enum {
	RQ_ALLOC_USER,
	RQ_ALLOC_KERNEL,

	__RQ_ALLOC_MAX,
};

static long page_size;
#define AREA_SIZE (8192 * page_size)

#define REQ_TYPE_SHIFT	3
#define REQ_TYPE_MASK	((1UL << REQ_TYPE_SHIFT) - 1)

enum {
	AREA_TYPE_NORMAL,
	AREA_TYPE_HUGE_PAGES,
	AREA_TYPE_DMABUF,
	__AREA_TYPE_MAX,
};

enum {
	REQ_TYPE_ACCEPT		= 1,
	REQ_TYPE_RX		= 2,
};

static int cfg_port = 8000;
static const char *cfg_ifname;
static int cfg_queue_id = -1;
static bool cfg_verify_data = false;
static size_t cfg_size = 0;
static unsigned cfg_rq_alloc_mode = RQ_ALLOC_USER;
static unsigned cfg_area_type = AREA_TYPE_NORMAL;
static struct sockaddr_in6 cfg_addr;

static void *area_ptr;
static void *ring_ptr;
static size_t ring_size;
static struct io_uring_zcrx_rq rq_ring;
static unsigned long area_token;
static int connfd;
static bool stop;
static size_t received;
static __u32 zcrx_id;

static int dmabuf_fd;
static int memfd;

static inline size_t get_refill_ring_size(unsigned int rq_entries)
{
	ring_size = rq_entries * sizeof(struct io_uring_zcrx_rqe);
	/* add space for the header (head/tail/etc.) */
	ring_size += page_size;
	return T_ALIGN_UP(ring_size, page_size);
}

static void zcrx_populate_area_udmabuf(struct io_uring_zcrx_area_reg *area_reg)
{
	struct udmabuf_create create;
	int ret, devfd;

	devfd = open("/dev/udmabuf", O_RDWR);
	if (devfd < 0)
		t_error(1, devfd, "Failed to open udmabuf dev");

	memfd = memfd_create("udmabuf-test", MFD_ALLOW_SEALING);
	if (memfd < 0)
		t_error(1, memfd, "Failed to open udmabuf dev");

	ret = fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0)
		t_error(1, 0, "Failed to set seals");

	ret = ftruncate(memfd, AREA_SIZE);
	if (ret == -1)
		t_error(1, 0, "Failed to resize udmabuf");

	memset(&create, 0, sizeof(create));
	create.memfd = memfd;
	create.offset = 0;
	create.size = AREA_SIZE;
	dmabuf_fd = ioctl(devfd, UDMABUF_CREATE, &create);
	if (dmabuf_fd < 0)
		t_error(1, dmabuf_fd, "Failed to create udmabuf");

	area_ptr = mmap(NULL, AREA_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
			dmabuf_fd, 0);
	if (area_ptr == MAP_FAILED)
		t_error(1, 0, "Failed to mmap udmabuf");

	memset(area_reg, 0, sizeof(*area_reg));
	area_reg->addr = 0; /* offset into dmabuf */
	area_reg->len = AREA_SIZE;
	area_reg->flags |= IORING_ZCRX_AREA_DMABUF;
	area_reg->dmabuf_fd = dmabuf_fd;

	close(devfd);
}

static void zcrx_populate_area(struct io_uring_zcrx_area_reg *area_reg)
{
	unsigned flags = MAP_PRIVATE | MAP_ANONYMOUS;
	unsigned prot = PROT_READ | PROT_WRITE;

	if (cfg_area_type == AREA_TYPE_DMABUF) {
		zcrx_populate_area_udmabuf(area_reg);
		return;
	}
	if (cfg_area_type == AREA_TYPE_NORMAL) {
		area_ptr = mmap(NULL, AREA_SIZE, prot,
				flags, 0, 0);
	} else if (cfg_area_type == AREA_TYPE_HUGE_PAGES) {
		area_ptr = mmap(NULL, AREA_SIZE, prot,
				flags | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
	}

	if (area_ptr == MAP_FAILED)
		t_error(1, 0, "mmap(): area allocation failed");

	memset(area_reg, 0, sizeof(*area_reg));
	area_reg->addr = uring_ptr_to_u64(area_ptr);
	area_reg->len = AREA_SIZE;
	area_reg->flags = 0;
}

static void setup_zcrx(struct io_uring *ring)
{
	struct io_uring_zcrx_area_reg area_reg;
	unsigned int ifindex;
	unsigned int rq_entries = 4096;
	unsigned rq_flags = 0;
	int ret;

	ifindex = if_nametoindex(cfg_ifname);
	if (!ifindex)
		t_error(1, 0, "bad interface name: %s", cfg_ifname);

	ring_size = get_refill_ring_size(rq_entries);
	ring_ptr = NULL;
	if (cfg_rq_alloc_mode == RQ_ALLOC_USER) {
		ring_ptr = mmap(NULL, ring_size,
				PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE,
				0, 0);
		if (ring_ptr == MAP_FAILED)
			t_error(1, 0, "mmap(): refill ring");
		rq_flags |= IORING_MEM_REGION_TYPE_USER;
	}

	struct io_uring_region_desc region_reg = {
		.size = ring_size,
		.user_addr = uring_ptr_to_u64(ring_ptr),
		.flags = rq_flags,
	};

	zcrx_populate_area(&area_reg);

	struct io_uring_zcrx_ifq_reg reg = {
		.if_idx = ifindex,
		.if_rxq = cfg_queue_id,
		.rq_entries = rq_entries,
		.area_ptr = uring_ptr_to_u64(&area_reg),
		.region_ptr = uring_ptr_to_u64(&region_reg),
	};

	ret = io_uring_register_ifq(ring, &reg);
	if (ret)
		t_error(1, 0, "io_uring_register_ifq(): %d", ret);

	if (cfg_rq_alloc_mode == RQ_ALLOC_KERNEL) {
		ring_ptr = mmap(NULL, ring_size,
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE,
				ring->ring_fd, region_reg.mmap_offset);
		if (ring_ptr == MAP_FAILED)
			t_error(1, 0, "mmap(): refill ring");
	}

	rq_ring.khead = (unsigned int *)((char *)ring_ptr + reg.offsets.head);
	rq_ring.ktail = (unsigned int *)((char *)ring_ptr + reg.offsets.tail);
	rq_ring.rqes = (struct io_uring_zcrx_rqe *)((char *)ring_ptr + reg.offsets.rqes);
	rq_ring.rq_tail = 0;
	rq_ring.ring_entries = reg.rq_entries;

	zcrx_id = reg.zcrx_id;
	area_token = area_reg.rq_area_token;
}

static void add_accept(struct io_uring *ring, int sockfd)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_accept(sqe, sockfd, NULL, NULL, 0);
	sqe->user_data = REQ_TYPE_ACCEPT;
}

static void add_recvzc(struct io_uring *ring, int sockfd, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, sockfd, NULL, len, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;
	sqe->zcrx_ifq_idx = zcrx_id;
	sqe->user_data = REQ_TYPE_RX;
}

static void process_accept(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	if (cqe->res < 0)
		t_error(1, 0, "accept()");
	if (connfd)
		t_error(1, 0, "Unexpected second connection");

	connfd = cqe->res;
	add_recvzc(ring, connfd, cfg_size);
}

static void verify_data(char *data, size_t size, unsigned long seq)
{
	int i;

	if (!cfg_verify_data)
		return;

	for (i = 0; i < size; i++) {
		char expected = 'a' + (seq + i) % 26;

		if (data[i] != expected)
			t_error(1, 0, "payload mismatch at %i: expected %i vs got %i, seq %li",
				i, expected, data[i], seq);
	}
}

static void process_recvzc(struct io_uring __attribute__((unused)) *ring,
			   struct io_uring_cqe *cqe)
{
	unsigned rq_mask = rq_ring.ring_entries - 1;
	struct io_uring_zcrx_cqe *rcqe;
	struct io_uring_zcrx_rqe *rqe;
	uint64_t mask;
	char *data;

	if (!(cqe->flags & IORING_CQE_F_MORE)) {
		if (!cfg_size || cqe->res != 0)
			t_error(1, 0, "invalid final recvzc ret %i", cqe->res);
		if (received != cfg_size)
			t_error(1, 0, "total receive size mismatch %lu / %lu",
				received, cfg_size);
		stop = true;
		return;
	}
	if (cqe->res < 0)
		t_error(1, 0, "recvzc(): %d", cqe->res);

	rcqe = (struct io_uring_zcrx_cqe *)(cqe + 1);
	mask = (1ULL << IORING_ZCRX_AREA_SHIFT) - 1;
	data = (char *)area_ptr + (rcqe->off & mask);

	verify_data(data, cqe->res, received);
	received += cqe->res;

	/* processed, return back to the kernel */
	rqe = &rq_ring.rqes[rq_ring.rq_tail & rq_mask];
	rqe->off = (rcqe->off & ~IORING_ZCRX_AREA_MASK) | area_token;
	rqe->len = cqe->res;
	io_uring_smp_store_release(rq_ring.ktail, ++rq_ring.rq_tail);
}

static void server_loop(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	unsigned int head, count = 0;

	io_uring_submit_and_wait(ring, 1);

	io_uring_for_each_cqe(ring, head, cqe) {
		switch (cqe->user_data & REQ_TYPE_MASK) {
		case REQ_TYPE_ACCEPT:
			process_accept(ring, cqe);
			break;
		case REQ_TYPE_RX:
			process_recvzc(ring, cqe);
			break;
		default:
			t_error(1, 0, "unknown cqe");
		}
		count++;
	}
	io_uring_cq_advance(ring, count);
}

static void run_server(void)
{
	unsigned int flags = 0;
	struct io_uring ring;
	int fd, enable, ret;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1)
		t_error(1, 0, "socket()");

	enable = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	if (ret < 0)
		t_error(1, 0, "setsockopt(SO_REUSEADDR)");

	ret = bind(fd, (struct sockaddr *)&cfg_addr, sizeof(cfg_addr));
	if (ret < 0)
		t_error(1, 0, "bind()");

	if (listen(fd, 1024) < 0)
		t_error(1, 0, "listen()");

	flags |= IORING_SETUP_COOP_TASKRUN;
	flags |= IORING_SETUP_SINGLE_ISSUER;
	flags |= IORING_SETUP_DEFER_TASKRUN;
	flags |= IORING_SETUP_SUBMIT_ALL;
	flags |= IORING_SETUP_CQE32;

	ret = io_uring_queue_init(512, &ring, flags);
	if (ret)
		t_error(1, ret, "ring init failed");

	setup_zcrx(&ring);
	add_accept(&ring, fd);

	while (!stop)
		server_loop(&ring);
}

static void usage(const char *filepath)
{
	t_error(1, 0, "Usage: %s (-4|-6) -p<port> -i<ifname> -q<rxq_id>", filepath);
}

static void parse_opts(int argc, char **argv)
{
	struct sockaddr_in6 *addr6 = (void *) &cfg_addr;
	int c;

	if (argc <= 1)
		usage(argv[0]);

	while ((c = getopt(argc, argv, "vp:i:q:s:r:A:")) != -1) {
		switch (c) {
		case 'p':
			cfg_port = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 's':
			cfg_size = strtoul(optarg, NULL, 0);
			break;
		case 'q':
			cfg_queue_id = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			cfg_verify_data = true;
			break;
		case 'r':
			cfg_rq_alloc_mode = strtoul(optarg, NULL, 0);
			if (cfg_rq_alloc_mode >= __RQ_ALLOC_MAX)
				t_error(1, 0, "invalid RQ allocation mode");
			break;
		case 'A':
			cfg_area_type = strtoul(optarg, NULL, 0);
			if (cfg_area_type >= __AREA_TYPE_MAX)
				t_error(1, 0, "Invalid area type");
			break;
		}
	}

	memset(addr6, 0, sizeof(*addr6));
	addr6->sin6_family = AF_INET6;
	addr6->sin6_port = htons(cfg_port);
	addr6->sin6_addr = in6addr_any;
}

int main(int argc, char **argv)
{
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	parse_opts(argc, argv);
	run_server();
	return 0;
}
