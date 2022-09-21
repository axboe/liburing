/* SPDX-License-Identifier: MIT */
/* based on linux-kernel/tools/testing/selftests/net/msg_zerocopy.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "liburing.h"

#define ZC_TAG 0xfffffffULL
#define MAX_SUBMIT_NR 512

static bool cfg_reg_ringfd = true;
static bool cfg_fixed_files = 1;
static bool cfg_zc = 1;
static int  cfg_nr_reqs = 8;
static bool cfg_fixed_buf = 1;

static int  cfg_family		= PF_UNSPEC;
static int  cfg_payload_len;
static int  cfg_port		= 8000;
static int  cfg_runtime_ms	= 4200;

static socklen_t cfg_alen;
static struct sockaddr_storage cfg_dst_addr;

static char payload[IP_MAXPACKET] __attribute__((aligned(4096)));

static unsigned long gettimeofday_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static void do_setsockopt(int fd, int level, int optname, int val)
{
	if (setsockopt(fd, level, optname, &val, sizeof(val)))
		error(1, errno, "setsockopt %d.%d: %d", level, optname, val);
}

static void setup_sockaddr(int domain, const char *str_addr,
			   struct sockaddr_storage *sockaddr)
{
	struct sockaddr_in6 *addr6 = (void *) sockaddr;
	struct sockaddr_in *addr4 = (void *) sockaddr;

	switch (domain) {
	case PF_INET:
		memset(addr4, 0, sizeof(*addr4));
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(cfg_port);
		if (str_addr &&
		    inet_pton(AF_INET, str_addr, &(addr4->sin_addr)) != 1)
			error(1, 0, "ipv4 parse error: %s", str_addr);
		break;
	case PF_INET6:
		memset(addr6, 0, sizeof(*addr6));
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(cfg_port);
		if (str_addr &&
		    inet_pton(AF_INET6, str_addr, &(addr6->sin6_addr)) != 1)
			error(1, 0, "ipv6 parse error: %s", str_addr);
		break;
	default:
		error(1, 0, "illegal domain");
	}
}

static int do_setup_tx(int domain, int type, int protocol)
{
	int fd;

	fd = socket(domain, type, protocol);
	if (fd == -1)
		error(1, errno, "socket t");

	do_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, 1 << 21);

	if (connect(fd, (void *) &cfg_dst_addr, cfg_alen))
		error(1, errno, "connect");
	return fd;
}

static inline struct io_uring_cqe *wait_cqe_fast(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	unsigned head;
	int ret;

	io_uring_for_each_cqe(ring, head, cqe)
		return cqe;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret)
		error(1, ret, "wait cqe");
	return cqe;
}

static void do_tx(int domain, int type, int protocol)
{
	unsigned long packets = 0;
	unsigned long bytes = 0;
	struct io_uring ring;
	struct iovec iov;
	uint64_t tstop;
	int i, fd, ret;
	int compl_cqes = 0;

	fd = do_setup_tx(domain, type, protocol);

	ret = io_uring_queue_init(512, &ring, IORING_SETUP_COOP_TASKRUN);
	if (ret)
		error(1, ret, "io_uring: queue init");

	if (cfg_fixed_files) {
		ret = io_uring_register_files(&ring, &fd, 1);
		if (ret < 0)
			error(1, ret, "io_uring: files registration");
	}
	if (cfg_reg_ringfd) {
		ret = io_uring_register_ring_fd(&ring);
		if (ret < 0)
			error(1, ret, "io_uring: io_uring_register_ring_fd");
	}

	iov.iov_base = payload;
	iov.iov_len = cfg_payload_len;

	ret = io_uring_register_buffers(&ring, &iov, 1);
	if (ret)
		error(1, ret, "io_uring: buffer registration");

	tstop = gettimeofday_ms() + cfg_runtime_ms;
	do {
		struct io_uring_sqe *sqe;
		struct io_uring_cqe *cqe;
		unsigned buf_idx = 0;
		unsigned msg_flags = MSG_WAITALL;

		for (i = 0; i < cfg_nr_reqs; i++) {
			sqe = io_uring_get_sqe(&ring);

			if (!cfg_zc)
				io_uring_prep_send(sqe, fd, payload,
						   cfg_payload_len, 0);
			else {
				io_uring_prep_send_zc(sqe, fd, payload,
						     cfg_payload_len, msg_flags, 0);
				if (cfg_fixed_buf) {
					sqe->ioprio |= IORING_RECVSEND_FIXED_BUF;
					sqe->buf_index = buf_idx;
				}
			}
			sqe->user_data = 1;
			if (cfg_fixed_files) {
				sqe->fd = 0;
				sqe->flags |= IOSQE_FIXED_FILE;
			}
		}

		ret = io_uring_submit(&ring);
		if (ret != cfg_nr_reqs)
			error(1, ret, "submit");

		for (i = 0; i < cfg_nr_reqs; i++) {
			cqe = wait_cqe_fast(&ring);

			if (cqe->flags & IORING_CQE_F_NOTIF) {
				if (cqe->flags & IORING_CQE_F_MORE)
					error(1, -EINVAL, "F_MORE notif");
				compl_cqes--;
				i--;
				io_uring_cqe_seen(&ring, cqe);
				continue;
			}
			if (cqe->flags & IORING_CQE_F_MORE)
				compl_cqes++;

			if (cqe->res >= 0) {
				packets++;
				bytes += cqe->res;
			} else if (cqe->res == -ECONNREFUSED || cqe->res == -EPIPE ||
				   cqe->res == -ECONNRESET) {
				fprintf(stderr, "Connection failure");
				goto out_fail;
			} else if (cqe->res != -EAGAIN) {
				error(1, cqe->res, "send failed");
			}
			io_uring_cqe_seen(&ring, cqe);
		}
	} while (gettimeofday_ms() < tstop);

out_fail:
	shutdown(fd, SHUT_RDWR);
	if (close(fd))
		error(1, errno, "close");

	fprintf(stderr, "tx=%lu (MB=%lu), tx/s=%lu (MB/s=%lu)\n",
			packets, bytes >> 20,
			packets / (cfg_runtime_ms / 1000),
			(bytes >> 20) / (cfg_runtime_ms / 1000));

	while (compl_cqes) {
		struct io_uring_cqe *cqe = wait_cqe_fast(&ring);

		io_uring_cqe_seen(&ring, cqe);
		compl_cqes--;
	}
	io_uring_queue_exit(&ring);
}

static void do_test(int domain, int type, int protocol)
{
	int i;

	for (i = 0; i < IP_MAXPACKET; i++)
		payload[i] = 'a' + (i % 26);

	do_tx(domain, type, protocol);
}

static void usage(const char *filepath)
{
	error(1, 0, "Usage: %s [-n<N>] [-z<val>] [-s<payload size>] "
		    "(-4|-6) [-t<time s>] -D<dst_ip> udp", filepath);
}

static void parse_opts(int argc, char **argv)
{
	const int max_payload_len = sizeof(payload) -
				    sizeof(struct ipv6hdr) -
				    sizeof(struct tcphdr) -
				    40 /* max tcp options */;
	int c;
	char *daddr = NULL;

	if (argc <= 1)
		usage(argv[0]);

	cfg_payload_len = max_payload_len;

	while ((c = getopt(argc, argv, "46D:p:s:t:n:z:b:k")) != -1) {
		switch (c) {
		case '4':
			if (cfg_family != PF_UNSPEC)
				error(1, 0, "Pass one of -4 or -6");
			cfg_family = PF_INET;
			cfg_alen = sizeof(struct sockaddr_in);
			break;
		case '6':
			if (cfg_family != PF_UNSPEC)
				error(1, 0, "Pass one of -4 or -6");
			cfg_family = PF_INET6;
			cfg_alen = sizeof(struct sockaddr_in6);
			break;
		case 'D':
			daddr = optarg;
			break;
		case 'p':
			cfg_port = strtoul(optarg, NULL, 0);
			break;
		case 's':
			cfg_payload_len = strtoul(optarg, NULL, 0);
			break;
		case 't':
			cfg_runtime_ms = 200 + strtoul(optarg, NULL, 10) * 1000;
			break;
		case 'n':
			cfg_nr_reqs = strtoul(optarg, NULL, 0);
			break;
		case 'z':
			cfg_zc = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			cfg_fixed_buf = strtoul(optarg, NULL, 0);
			break;
		}
	}

	if (cfg_nr_reqs > MAX_SUBMIT_NR)
		error(1, 0, "-n: submit batch nr exceeds max (%d)", MAX_SUBMIT_NR);
	if (cfg_payload_len > max_payload_len)
		error(1, 0, "-s: payload exceeds max (%d)", max_payload_len);

	setup_sockaddr(cfg_family, daddr, &cfg_dst_addr);

	if (optind != argc - 1)
		usage(argv[0]);
}

int main(int argc, char **argv)
{
	const char *cfg_test;

	parse_opts(argc, argv);

	cfg_test = argv[argc - 1];
	if (!strcmp(cfg_test, "tcp"))
		do_test(cfg_family, SOCK_STREAM, 0);
	else if (!strcmp(cfg_test, "udp"))
		do_test(cfg_family, SOCK_DGRAM, 0);
	else
		error(1, 0, "unknown cfg_test %s", cfg_test);

	return 0;
}
