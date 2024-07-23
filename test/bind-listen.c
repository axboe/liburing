/* SPDX-License-Identifier: MIT */
/*
 * Configure and operate a TCP socket solely with io_uring.
 */
#include <stdio.h>
#include <string.h>
#include <liburing.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include "liburing.h"
#include "helpers.h"

static void msec_to_ts(struct __kernel_timespec *ts, unsigned int msec)
{
        ts->tv_sec = msec / 1000;
        ts->tv_nsec = (msec % 1000) * 1000000;
}

const char *magic = "Hello World!";

enum {
	SRV_INDEX = 0,
	CLI_INDEX,
	CONN_INDEX,
};

static int connect_client(struct io_uring *ring, unsigned short peer_port)
{

	struct __kernel_timespec ts;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int head, ret, submitted = 0;
	struct sockaddr_in peer_addr;
 	socklen_t addr_len = sizeof(peer_addr);

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = peer_port;
	peer_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_socket_direct(sqe, AF_INET, SOCK_STREAM, 0,
				    CLI_INDEX, 0);
	sqe->flags |= IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_connect(sqe, CLI_INDEX, (struct sockaddr*) &peer_addr, addr_len);
	sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_send(sqe, CLI_INDEX, magic, strlen(magic), 0);
	sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;

	submitted = ret = io_uring_submit(ring);
	if (ret < 0)
		return T_SETUP_SKIP;

	msec_to_ts(&ts, 300);
	ret = io_uring_wait_cqes(ring, &cqe, submitted, &ts, NULL);
	if (ret < 0)
		return T_SETUP_SKIP;

	io_uring_for_each_cqe(ring, head, cqe) {
		ret = cqe->res;
		if (ret < 0)
			return T_SETUP_SKIP;
	} io_uring_cq_advance(ring, submitted);

	return T_SETUP_OK;
}

static int setup_srv(struct io_uring *ring, struct sockaddr_in *server_addr)
{
	int val;
	int submitted;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct __kernel_timespec ts;
	int head;

	int ret;

	memset(server_addr, 0, sizeof(struct sockaddr_in));
	server_addr->sin_family = AF_INET;
	server_addr->sin_port = htons(8000);
	server_addr->sin_addr.s_addr = htons(INADDR_ANY);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_socket_direct(sqe, AF_INET, SOCK_STREAM, 0, SRV_INDEX, 0);
	sqe->flags |= IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	val = 1;
	io_uring_prep_cmd_sock(sqe, SOCKET_URING_OP_SETSOCKOPT, 0, SOL_SOCKET,
			       SO_REUSEADDR, &val, sizeof(val));
	sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_bind(sqe, SRV_INDEX, (struct sockaddr *) server_addr,
			   sizeof(struct sockaddr_in));
	sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_listen(sqe, SRV_INDEX, 1);
	sqe->flags |= IOSQE_FIXED_FILE;

	submitted = ret = io_uring_submit(ring);
	if (ret < 0) {
		fprintf(stderr, "submission failed. %d\n", ret);
		return T_EXIT_FAIL;
	}

	msec_to_ts(&ts, 300);
	ret = io_uring_wait_cqes(ring, &cqe, ret, &ts, NULL);
	if (ret < 0) {
		fprintf(stderr, "submission failed. %d\n", ret);
		return T_EXIT_FAIL;
	}

	io_uring_for_each_cqe(ring, head, cqe) {
		ret = cqe->res;
		if (ret < 0) {
			fprintf(stderr, "Server startup failed. step %d got %d \n", head, ret);
			return T_EXIT_FAIL;
		}
	} io_uring_cq_advance(ring, submitted);

	return T_SETUP_OK;
}

static int test_good_server()
{
	struct sockaddr_in server_addr;
	struct __kernel_timespec ts;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret;
	int fds[3];
	char buf[1024];

	memset(fds, -1, sizeof(fds));

	ret = t_create_ring(10, &ring, IORING_SETUP_SUBMIT_ALL);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return T_SETUP_SKIP;
	}

	ret = io_uring_register_files(&ring, fds, 3);
	if (ret) {
		fprintf(stderr, "server file register %d\n", ret);
		return T_SETUP_SKIP;
	}

	ret = setup_srv(&ring, &server_addr);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "srv startup failed.\n");
		return T_EXIT_FAIL;
	}

	if (connect_client(&ring, server_addr.sin_port) != T_SETUP_OK) {
		fprintf(stderr, "cli startup failed.\n");
		return T_SETUP_SKIP;
	}

	/* Wait for a request */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_accept_direct(sqe, SRV_INDEX, NULL, NULL, 0, CONN_INDEX);
	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_submit(&ring);
	io_uring_wait_cqe(&ring, &cqe);
	if (cqe->res < 0) {
		fprintf(stderr, "accept failed. %d\n", cqe->res);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(&ring, cqe);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_recv(sqe, CONN_INDEX, buf, BUFSIZ, 0);
	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_submit(&ring);
	io_uring_wait_cqe_timeout(&ring, &cqe, &ts);

	if (cqe->res < 0) {
		fprintf(stderr, "bad receive cqe. %d\n", cqe->res);
		return T_EXIT_FAIL;
	}
	ret = cqe->res;

	io_uring_queue_exit(&ring);

	if (ret != strlen(magic) || strncmp(buf, magic, ret)) {
		fprintf(stderr, "didn't receive expected string. Got %d '%s'\n", ret, buf);
		return T_EXIT_FAIL;
	}
	fprintf(stderr, "expected string. Got %d '%s'\n", ret, buf);
	return T_EXIT_PASS;
}

int test_bad_bind()
{
	int sock;
	struct sockaddr_in server_addr;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int err;
	int ret = T_EXIT_FAIL;

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8001);
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);

	err = t_create_ring(1, &ring, 0);
	if (err < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return T_SETUP_SKIP;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);

	/* Bind with size 0 */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_bind(sqe, sock, (struct sockaddr *) &server_addr, 0);
	err = io_uring_submit(&ring);
	if (err < 0)
		goto fail;

	err = io_uring_wait_cqe(&ring, &cqe);
	if (err)
		goto fail;

	if (cqe->res != -EINVAL)
		goto fail;
	io_uring_cqe_seen(&ring, cqe);

	/* Bind with bad fd */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_bind(sqe, 0, (struct sockaddr *) &server_addr,  sizeof(struct sockaddr_in));
	err = io_uring_submit(&ring);
	if (err < 0)
		goto fail;

	err = io_uring_wait_cqe(&ring, &cqe);
	if (err)
		goto fail;
	if (cqe->res != -ENOTSOCK)
		goto fail;
	io_uring_cqe_seen(&ring, cqe);

	ret = T_EXIT_PASS;

	/* bind with weird value */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_bind(sqe, sock, (struct sockaddr *) &server_addr,  sizeof(struct sockaddr_in));
	sqe->rw_flags = 1;
	err = io_uring_submit(&ring);
	if (err < 0)
		goto fail;

	err = io_uring_wait_cqe(&ring, &cqe);
	if (err)
		goto fail;
	if (cqe->res != -EINVAL)
		goto fail;
	io_uring_cqe_seen(&ring, cqe);

	ret = T_EXIT_PASS;

fail:
	io_uring_queue_exit(&ring);
	if (sock)
		close(sock);
	return ret;
}

int test_bad_listen()
{
	int sock;
	struct sockaddr_in server_addr;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int err;
	int ret = T_EXIT_FAIL;

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8001);
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);

	err = t_create_ring(1, &ring, 0);
	if (err < 0) {
		fprintf(stderr, "queue_init: %d\n", err);
		return T_SETUP_SKIP;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (!sock) {
		fprintf(stderr, "bad sock\n");
		goto fail;
	}
	if (bind(sock, (struct sockaddr *) &server_addr,  sizeof(struct sockaddr_in))) {
		fprintf(stderr, "bad bind\n");
		goto fail;
	}

	/* listen on bad sock */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_listen(sqe, 0, 1);
	err = io_uring_submit(&ring);
	if (err < 0)
		goto fail;

	err = io_uring_wait_cqe(&ring, &cqe);
	if (err)
		goto fail;

	if (cqe->res != -ENOTSOCK)
		goto fail;
	io_uring_cqe_seen(&ring, cqe);

	/* listen with weird parameters */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_listen(sqe, sock, 1);
	sqe->addr2 = 0xffffff;
	err = io_uring_submit(&ring);
	if (err < 0)
		goto fail;

	err = io_uring_wait_cqe(&ring, &cqe);
	if (err)
		goto fail;

	if (cqe->res != -EINVAL)
		goto fail;
	io_uring_cqe_seen(&ring, cqe);

	ret = T_EXIT_PASS;
fail:
	io_uring_queue_exit(&ring);
	if (sock)
		close(sock);
	return ret;
}

int main(int argc, char *argv[])
{
	struct io_uring_probe *probe;
	int failures = 0;
	if (argc > 1)
		return 0;

	/*
	 * This test is not supported in older kernels. Check for
	 * OP_LISTEN, since that is the last feature required to support
	 * it.
	 */
	probe = io_uring_get_probe();
	if (!probe)
		return 1;
	if (!io_uring_opcode_supported(probe, IORING_OP_LISTEN))
		return T_EXIT_SKIP;

	failures += test_good_server();
	failures += test_bad_bind();
	failures += test_bad_listen();

	if (!failures)
		return T_EXIT_PASS;
	return T_EXIT_FAIL;
}
