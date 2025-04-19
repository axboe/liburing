// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

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

#include "liburing.h"
#include "helpers.h"

static long page_size;
#define AREA_SIZE (8192 * page_size)
#define SEND_SIZE (512 * 4096)

static int cfg_port = 8000;
static const char *cfg_ifname;
static int cfg_queue_id = -1;
static bool cfg_oneshot;
static int cfg_oneshot_recvs;
static bool cfg_verify_data = false;
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

static inline size_t get_refill_ring_size(unsigned int rq_entries)
{
	ring_size = rq_entries * sizeof(struct io_uring_zcrx_rqe);
	/* add space for the header (head/tail/etc.) */
	ring_size += page_size;
	return T_ALIGN_UP(ring_size, page_size);
}

static void setup_zcrx(struct io_uring *ring)
{
	unsigned int ifindex;
	unsigned int rq_entries = 4096;
	int ret;

	ifindex = if_nametoindex(cfg_ifname);
	if (!ifindex)
		t_error(1, 0, "bad interface name: %s", cfg_ifname);

	area_ptr = mmap(NULL,
			AREA_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			0,
			0);
	if (area_ptr == MAP_FAILED)
		t_error(1, 0, "mmap(): zero copy area");

	ring_size = get_refill_ring_size(rq_entries);
	ring_ptr = mmap(NULL,
			ring_size,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			0,
			0);
	if (ring_ptr == MAP_FAILED)
		t_error(1, 0, "mmap(): refill ring");

	struct io_uring_region_desc region_reg = {
		.size = ring_size,
		.user_addr = (__u64)(unsigned long)ring_ptr,
		.flags = IORING_MEM_REGION_TYPE_USER,
	};

	struct io_uring_zcrx_area_reg area_reg = {
		.addr = (__u64)(unsigned long)area_ptr,
		.len = AREA_SIZE,
		.flags = 0,
	};

	struct io_uring_zcrx_ifq_reg reg = {
		.if_idx = ifindex,
		.if_rxq = cfg_queue_id,
		.rq_entries = rq_entries,
		.area_ptr = (__u64)(unsigned long)&area_reg,
		.region_ptr = (__u64)(unsigned long)&region_reg,
	};

	ret = io_uring_register_ifq(ring, &reg);
	if (ret)
		t_error(1, 0, "io_uring_register_ifq(): %d", ret);

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
	sqe->user_data = 1;
}

static void add_recvzc(struct io_uring *ring, int sockfd)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, sockfd, NULL, 0, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;
	sqe->zcrx_ifq_idx = zcrx_id;
	sqe->user_data = 2;
}

static void add_recvzc_oneshot(struct io_uring *ring, int sockfd, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, sockfd, NULL, len, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;
	sqe->zcrx_ifq_idx = zcrx_id;
	sqe->user_data = 2;
}

static void process_accept(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	if (cqe->res < 0)
		t_error(1, 0, "accept()");
	if (connfd)
		t_error(1, 0, "Unexpected second connection");

	connfd = cqe->res;
	if (cfg_oneshot)
		add_recvzc_oneshot(ring, connfd, page_size);
	else
		add_recvzc(ring, connfd);
}

static void verify_data(char *data, size_t size, unsigned long seq)
{
	int i;

	if (!cfg_verify_data)
		return;

	for (i = 0; i < size; i++) {
		char expected = 'a' + (seq + i) % 26;

		if (data[i] != expected)
			t_error(1, 0, "payload mismatch at %i", i);
	}
}

static void process_recvzc(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	unsigned rq_mask = rq_ring.ring_entries - 1;
	struct io_uring_zcrx_cqe *rcqe;
	struct io_uring_zcrx_rqe *rqe;
	uint64_t mask;
	char *data;

	if (cqe->res < 0)
		t_error(1, 0, "recvzc(): %d", cqe->res);

	if (cqe->res == 0 && cqe->flags == 0 && cfg_oneshot_recvs == 0) {
		stop = true;
		return;
	}

	if (cfg_oneshot) {
		if (cqe->res == 0 && cqe->flags == 0 && cfg_oneshot_recvs) {
			add_recvzc_oneshot(ring, connfd, page_size);
			cfg_oneshot_recvs--;
		}
	} else if (!(cqe->flags & IORING_CQE_F_MORE)) {
		add_recvzc(ring, connfd);
	}

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
		if (cqe->user_data == 1)
			process_accept(ring, cqe);
		else if (cqe->user_data == 2)
			process_recvzc(ring, cqe);
		else
			t_error(1, 0, "unknown cqe");
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

	while ((c = getopt(argc, argv, "vp:i:q:o:")) != -1) {
		switch (c) {
		case 'p':
			cfg_port = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			cfg_ifname = optarg;
			break;
		case 'o': {
			cfg_oneshot = true;
			cfg_oneshot_recvs = strtoul(optarg, NULL, 0);
			break;
		}
		case 'q':
			cfg_queue_id = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			cfg_verify_data = true;
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
