/* SPDX-License-Identifier: MIT */
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
#include "helpers.h"

#define MAX_MSG	128

#define PORT	10200
#define HOST	"127.0.0.1"
#define HOSTV6	"::1"

#define ZC_TAG 10000
#define BUFFER_OFFSET 41

#ifndef ARRAY_SIZE
	#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif

static char *tx_buffer, *rx_buffer;
static struct iovec buffers_iov[3];

static bool check_cq_empty(struct io_uring *ring)
{
	struct io_uring_cqe *cqe = NULL;
	int ret;

	ret = io_uring_peek_cqe(ring, &cqe); /* nothing should be there */
	return ret == -EAGAIN;
}

static int test_basic_send(struct io_uring *ring, int sock_tx, int sock_rx)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int msg_flags = 0;
	unsigned zc_flags = 0;
	int payload_size = 100;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send_zc(sqe, sock_tx, tx_buffer, payload_size,
			      msg_flags, zc_flags);
	sqe->user_data = 1;

	ret = io_uring_submit(ring);
	assert(ret == 1);
	ret = io_uring_wait_cqe(ring, &cqe);
	assert(!ret);
	assert(cqe->user_data == 1);
	if (ret == -EINVAL) {
		assert(!(cqe->flags & IORING_CQE_F_MORE));
		return T_EXIT_SKIP;
	}
	assert(cqe->res == payload_size);
	assert(cqe->flags & IORING_CQE_F_MORE);
	io_uring_cqe_seen(ring, cqe);

	ret = io_uring_wait_cqe(ring, &cqe);
	assert(!ret);
	assert(cqe->user_data == 1);
	assert(cqe->flags & IORING_CQE_F_NOTIF);
	assert(!(cqe->flags & IORING_CQE_F_MORE));
	io_uring_cqe_seen(ring, cqe);
	assert(check_cq_empty(ring));

	ret = recv(sock_rx, rx_buffer, payload_size, MSG_TRUNC);
	assert(ret == payload_size);
	return T_EXIT_PASS;
}

static int test_send_faults(struct io_uring *ring, int sock_tx, int sock_rx)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int msg_flags = 0;
	unsigned zc_flags = 0;
	int payload_size = 100;
	int ret, i;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send_zc(sqe, sock_tx, (void *)1UL, payload_size,
			      msg_flags, zc_flags);
	sqe->user_data = 1;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send_zc(sqe, sock_tx, (void *)1UL, payload_size,
			      msg_flags, zc_flags);
	sqe->user_data = 2;
	io_uring_prep_send_set_addr(sqe, (const struct sockaddr *)1UL,
				    sizeof(struct sockaddr_in6));

	ret = io_uring_submit(ring);
	assert(ret == 2);

	for (i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		assert(!ret);
		assert(cqe->user_data <= 2);
		assert(cqe->res == -EFAULT);
		assert(!(cqe->flags & IORING_CQE_F_MORE));
		io_uring_cqe_seen(ring, cqe);
	}
	assert(check_cq_empty(ring));
	return T_EXIT_PASS;
}

static int prepare_ip(struct sockaddr_storage *addr, int *sock_client, int *sock_server,
		      bool ipv6, bool client_connect, bool msg_zc, bool tcp)
{
	int family, addr_size;
	int ret, val;
	int listen_sock = -1;
	int sock;

	memset(addr, 0, sizeof(*addr));
	if (ipv6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;

		family = AF_INET6;
		saddr->sin6_family = family;
		saddr->sin6_port = htons(PORT);
		addr_size = sizeof(*saddr);
	} else {
		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;

		family = AF_INET;
		saddr->sin_family = family;
		saddr->sin_port = htons(PORT);
		saddr->sin_addr.s_addr = htonl(INADDR_ANY);
		addr_size = sizeof(*saddr);
	}

	/* server sock setup */
	if (tcp) {
		sock = listen_sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	} else {
		sock = *sock_server = socket(family, SOCK_DGRAM, 0);
	}
	if (sock < 0) {
		perror("socket");
		return 1;
	}
	val = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	val = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

	ret = bind(sock, (struct sockaddr *)addr, addr_size);
	if (ret < 0) {
		perror("bind");
		return 1;
	}
	if (tcp) {
		ret = listen(sock, 128);
		assert(ret != -1);
	}

	if (ipv6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;

		inet_pton(AF_INET6, HOSTV6, &(saddr->sin6_addr));
	} else {
		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;

		inet_pton(AF_INET, HOST, &saddr->sin_addr);
	}

	/* client sock setup */
	if (tcp) {
		*sock_client = socket(family, SOCK_STREAM, IPPROTO_TCP);
		assert(client_connect);
	} else {
		*sock_client = socket(family, SOCK_DGRAM, 0);
	}
	if (*sock_client < 0) {
		perror("socket");
		return 1;
	}
	if (client_connect) {
		ret = connect(*sock_client, (struct sockaddr *)addr, addr_size);
		if (ret < 0) {
			perror("connect");
			return 1;
		}
	}
	if (msg_zc) {
		val = 1;
		if (setsockopt(*sock_client, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val))) {
			perror("setsockopt zc");
			return 1;
		}
	}
	if (tcp) {
		*sock_server = accept(listen_sock, NULL, NULL);
		if (!*sock_server) {
			fprintf(stderr, "can't accept\n");
			return 1;
		}
		close(listen_sock);
	}
	return 0;
}

static int do_test_inet_send(struct io_uring *ring, int sock_client, int sock_server,
			     bool fixed_buf, struct sockaddr_storage *addr,
			     size_t send_size, bool cork, bool mix_register,
			     int buf_idx, bool force_async)
{
	const unsigned zc_flags = 0;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int nr_reqs = cork ? 5 : 1;
	int i, ret, nr_cqes;
	size_t chunk_size = send_size / nr_reqs;
	size_t chunk_size_last = send_size - chunk_size * (nr_reqs - 1);
	char *buf = buffers_iov[buf_idx].iov_base;
	pid_t p;
	int wstatus;

	assert(send_size <= buffers_iov[buf_idx].iov_len);
	memset(rx_buffer, 0, send_size);

	for (i = 0; i < nr_reqs; i++) {
		bool real_fixed_buf = fixed_buf;
		size_t cur_size = chunk_size;
		int msg_flags = MSG_WAITALL;

		if (mix_register)
			real_fixed_buf = rand() & 1;

		if (cork && i != nr_reqs - 1)
			msg_flags |= MSG_MORE;
		if (i == nr_reqs - 1)
			cur_size = chunk_size_last;

		sqe = io_uring_get_sqe(ring);
		io_uring_prep_send_zc(sqe, sock_client, buf + i * chunk_size,
				      cur_size, msg_flags, zc_flags);
		sqe->user_data = i;

		if (real_fixed_buf) {
			sqe->ioprio |= IORING_RECVSEND_FIXED_BUF;
			sqe->buf_index = buf_idx;
		}
		if (addr) {
			sa_family_t fam = ((struct sockaddr_in *)addr)->sin_family;
			int addr_len = fam == AF_INET ? sizeof(struct sockaddr_in) :
							sizeof(struct sockaddr_in6);

			io_uring_prep_send_set_addr(sqe, (const struct sockaddr *)addr,
						    addr_len);
		}
		if (force_async)
			sqe->flags |= IOSQE_ASYNC;
	}

	ret = io_uring_submit(ring);
	if (ret != nr_reqs) {
		fprintf(stderr, "submit failed, got %i expected %i\n", ret, nr_reqs);
		return 1;
	}

	p = fork();
	if (p == -1) {
		fprintf(stderr, "fork() failed\n");
		return 1;
	} else if (p == 0) {
		size_t bytes_received = 0;

		while (bytes_received != send_size) {
			ret = recv(sock_server,
				   rx_buffer + bytes_received,
				   send_size - bytes_received, 0);
			if (ret <= 0) {
				fprintf(stderr, "recv failed, got %i, errno %i\n",
					ret, errno);
				exit(1);
			}
			bytes_received += ret;
		}

		for (i = 0; i < send_size; i++) {
			if (buf[i] != rx_buffer[i]) {
				fprintf(stderr, "botched data, first mismated byte %i, "
					"%u vs %u\n", i, buf[i], rx_buffer[i]);
				exit(1);
			}
		}
		exit(0);
	}

	nr_cqes = 2 * nr_reqs;
	for (i = 0; i < nr_cqes; i++) {
		int expected = chunk_size;

		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret) {
			fprintf(stderr, "io_uring_wait_cqe failed %i\n", ret);
			return 1;
		}
		if (cqe->user_data >= nr_reqs) {
			fprintf(stderr, "invalid user_data\n");
			return 1;
		}
		if (!(cqe->flags & IORING_CQE_F_NOTIF)) {
			if (cqe->user_data == nr_reqs - 1)
				expected = chunk_size_last;
			if (cqe->res != expected) {
				fprintf(stderr, "invalid cqe->res %d expected %d\n",
						 cqe->res, expected);
				return 1;
			}
		}
		if ((cqe->flags & IORING_CQE_F_MORE) ==
		    (cqe->flags & IORING_CQE_F_NOTIF)) {
			fprintf(stderr, "unexpected cflags %i\n", cqe->flags);
			return 1;
		}
		io_uring_cqe_seen(ring, cqe);
	}

	if (waitpid(p, &wstatus, 0) == (pid_t)-1) {
		perror("waitpid()");
		return 1;
	}
	if (!WIFEXITED(wstatus)) {
		fprintf(stderr, "child failed %i\n", WEXITSTATUS(wstatus));
		return 1;
	}
	if (WEXITSTATUS(wstatus)) {
		fprintf(stderr, "child failed\n");
		return 1;
	}
	return 0;
}

static int test_inet_send(struct io_uring *ring)
{
	struct sockaddr_storage addr;
	int sock_client = -1, sock_server = -1;
	int ret, j, i;

	for (j = 0; j < 16; j++) {
		bool ipv6 = j & 1;
		bool client_connect = j & 2;
		bool msg_zc_set = j & 4;
		bool tcp = j & 8;

		if (tcp && !client_connect)
			continue;

		ret = prepare_ip(&addr, &sock_client, &sock_server, ipv6,
				 client_connect, msg_zc_set, tcp);
		if (ret) {
			fprintf(stderr, "sock prep failed %d\n", ret);
			return 1;
		}

		for (i = 0; i < 256; i++) {
			bool fixed_buf = i & 1;
			struct sockaddr_storage *addr_arg = (i & 2) ? &addr : NULL;
			size_t size = (i & 4) ? 137 : 4096;
			bool cork = i & 8;
			bool mix_register = i & 16;
			bool aligned = i & 32;
			bool large_buf = i & 64;
			int buf_idx = aligned ? 0 : 1;
			bool force_async = i & 128;

			if (!tcp || !large_buf)
				continue;
			if (large_buf) {
				buf_idx = 2;
				size = buffers_iov[buf_idx].iov_len;
				if (!aligned || !tcp)
					continue;
			}
			if (!buffers_iov[buf_idx].iov_base)
				continue;
			if (tcp && cork)
				continue;
			if (mix_register && (!cork || fixed_buf))
				continue;
			if (!client_connect && addr_arg == NULL)
				continue;

			ret = do_test_inet_send(ring, sock_client, sock_server, fixed_buf,
						addr_arg, size, cork, mix_register,
						buf_idx, force_async);
			if (ret) {
				fprintf(stderr, "send failed fixed buf %i, conn %i, addr %i, "
					"cork %i\n",
					fixed_buf, client_connect, !!addr_arg,
					cork);
				return 1;
			}
		}

		close(sock_client);
		close(sock_server);
	}
	return 0;
}

static int test_async_addr(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct sockaddr_storage addr;
	int sock_tx = -1, sock_rx = -1;
	struct __kernel_timespec ts;
	int ret;

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	ret = prepare_ip(&addr, &sock_tx, &sock_rx, true, false, false, false);
	if (ret) {
		fprintf(stderr, "sock prep failed %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_timeout(sqe, &ts, 0, IORING_TIMEOUT_ETIME_SUCCESS);
	sqe->user_data = 1;
	sqe->flags |= IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send_zc(sqe, sock_tx, tx_buffer, 1, 0, 0);
	sqe->user_data = 2;
	io_uring_prep_send_set_addr(sqe, (const struct sockaddr *)&addr,
				    sizeof(struct sockaddr_in6));

	ret = io_uring_submit(ring);
	assert(ret == 2);
	memset(&addr, 0, sizeof(addr));

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "io_uring_wait_cqe failed %i\n", ret);
		return 1;
	}
	if (cqe->user_data != 1 || cqe->res != -ETIME) {
		fprintf(stderr, "invalid timeout res %i %i\n",
			(int)cqe->user_data, cqe->res);
		return 1;
	}
	io_uring_cqe_seen(ring, cqe);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "io_uring_wait_cqe failed %i\n", ret);
		return 1;
	}
	if (cqe->user_data != 2 || cqe->res != 1) {
		fprintf(stderr, "invalid send %i %i\n",
			(int)cqe->user_data, cqe->res);
		return 1;
	}
	io_uring_cqe_seen(ring, cqe);
	ret = recv(sock_rx, rx_buffer, 1, MSG_TRUNC);
	assert(ret == 1);

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "io_uring_wait_cqe failed %i\n", ret);
		return 1;
	}
	assert(cqe->flags & IORING_CQE_F_NOTIF);
	io_uring_cqe_seen(ring, cqe);

	close(sock_tx);
	close(sock_rx);
	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int i, ret, sp[2];
	size_t len;

	if (argc > 1)
		return T_EXIT_SKIP;

	len = 1U << 25; /* 32MB, should be enough to trigger a short send */
	tx_buffer = aligned_alloc(4096, len);
	rx_buffer = aligned_alloc(4096, len);
	if (tx_buffer && rx_buffer) {
		buffers_iov[2].iov_base = tx_buffer;
		buffers_iov[2].iov_len = len;
	} else {
		printf("skip large buffer tests, can't alloc\n");

		len = 8192;
		tx_buffer = aligned_alloc(4096, len);
		rx_buffer = aligned_alloc(4096, len);
	}
	if (!tx_buffer || !rx_buffer) {
		fprintf(stderr, "can't allocate buffers\n");
		return T_EXIT_FAIL;
	}

	buffers_iov[0].iov_base = tx_buffer;
	buffers_iov[0].iov_len = 8192;
	buffers_iov[1].iov_base = tx_buffer + BUFFER_OFFSET;
	buffers_iov[1].iov_len = 8192 - BUFFER_OFFSET - 13;

	ret = io_uring_queue_init(32, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return T_EXIT_FAIL;
	}

	srand((unsigned)time(NULL));
	for (i = 0; i < len; i++)
		tx_buffer[i] = i;
	memset(rx_buffer, 0, len);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0) {
		perror("Failed to create Unix-domain socket pair\n");
		return T_EXIT_FAIL;
	}

	ret = test_basic_send(&ring, sp[0], sp[1]);
	if (ret == T_EXIT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "test_basic_send() failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_send_faults(&ring, sp[0], sp[1]);
	if (ret) {
		fprintf(stderr, "test_send_faults() failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_async_addr(&ring);
	if (ret) {
		fprintf(stderr, "test_async_addr() failed\n");
		return ret;
	}

	ret = t_register_buffers(&ring, buffers_iov, ARRAY_SIZE(buffers_iov));
	if (ret == T_SETUP_SKIP) {
		fprintf(stderr, "can't register bufs, skip\n");
		goto out;
	} else if (ret != T_SETUP_OK) {
		fprintf(stderr, "buffer registration failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_inet_send(&ring);
	if (ret) {
		fprintf(stderr, "test_inet_send() failed\n");
		return ret;
	}
out:
	io_uring_queue_exit(&ring);
	close(sp[0]);
	close(sp[1]);
	return T_EXIT_PASS;
}
