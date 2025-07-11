/* SPDX-License-Identifier: MIT */
/*
 * Description: Test flagging of IORING_CQE_F_SOCK_FULL on a socket
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "liburing.h"
#include "helpers.h"

static int use_port = 10202;
#define HOST	"127.0.0.1"

struct recv_data {
	pthread_barrier_t startup;
	pthread_barrier_t receives;
	pthread_barrier_t finish;
	int pollfirst;
	unsigned int ring_flags;
	int port;
};

static int recv_prep(struct recv_data *rd, int *sock)
{
	struct sockaddr_in saddr;
	int sockfd, ret, val;
	socklen_t len;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(rd->port);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	val = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("bind");
		goto err;
	}

	ret = listen(sockfd, 1);
	if (ret < 0) {
		perror("listen");
		goto err;
	}

	pthread_barrier_wait(&rd->startup);

	ret = listen(sockfd, 1);
	len = sizeof(saddr);
	ret = accept(sockfd, (struct sockaddr *)&saddr, &len);
	if (ret < 0) {
		perror("accept");
		goto err;
	}

	close(sockfd);
	*sock = ret;
	return 0;
err:
	close(sockfd);
	return 1;
}

static void *recv_fn(void *data)
{
	struct recv_data *rd = data;
	int ret, sock;
	char *buf;

	ret = recv_prep(rd, &sock);
	if (ret) {
		fprintf(stderr, "recv_prep failed: %d\n", ret);
		pthread_barrier_wait(&rd->receives);
		goto err;
	}

	pthread_barrier_wait(&rd->receives);
	buf = malloc(32768);
	do {
		ret = recv(sock, buf, 32768, MSG_DONTWAIT);
		if (ret > 0)
			continue;
		if (ret <= 0)
			break;
	} while (1);

	free(buf);
	close(sock);
	ret = 0;
err:
	pthread_barrier_wait(&rd->finish);
	return (void *)(intptr_t)ret;
}

static int do_send(struct recv_data *rd)
{
	struct sockaddr_in saddr;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret, len;
	socklen_t optlen;
	char *buf;

	pthread_barrier_wait(&rd->startup);

	buf = malloc(4096);
	memset(buf, 0x5a, 4096);

	ret = io_uring_queue_init(1, &ring, rd->ring_flags);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(rd->port);
	inet_pton(AF_INET, HOST, &saddr.sin_addr);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		goto err2;
	}

	ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		goto err;
	}

	/* Limit socket buffer send size */
	optlen = sizeof(len);
	len = 4096;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &len, optlen);
	if (ret < 0) {
		perror("setsockopt");
		goto err;
	}

	do {
		sqe = io_uring_get_sqe(&ring);
		io_uring_prep_send(sqe, sockfd, buf, 4096, MSG_DONTWAIT);
		sqe->user_data = 1;

		ret = io_uring_submit(&ring);
		if (ret <= 0) {
			fprintf(stderr, "submit failed: %d\n", ret);
			goto err;
		}

		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait: %d\n", ret);
			goto err;
		}
		if (cqe->flags & IORING_CQE_F_SOCK_FULL) {
			fprintf(stderr, "SOCK_FULL seen prematurely!\n");
			goto err;
		}
		if (cqe->res < 0) {
			/* socket now full */
			if (cqe->res == -EAGAIN) {
				io_uring_cqe_seen(&ring, cqe);
				break;
			}
			fprintf(stderr, "cqe res: %d\n", cqe->res);
			goto err;
		}
		/* if a short write, repeat until -EAGAIN is seen */
		io_uring_cqe_seen(&ring, cqe);
	} while (1);

	/*
	 * submit send on known full socket. this will go through the poll
	 * machinery, waiting for POLLOUT.
	 */
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_send(sqe, sockfd, buf, 4096, MSG_WAITALL);
	if (rd->pollfirst)
		sqe->ioprio = IORING_RECVSEND_POLL_FIRST;
	sqe->user_data = 1;

	io_uring_submit(&ring);

	/*
	 * Kick receive side to start freeing up socket space
	 */
	pthread_barrier_wait(&rd->receives);

	/*
	 * Wait for previous send to complete. That should have
	 * IORING_CQE_F_SOCK_FULL set, if the kernel supports this kind
	 * of notification.
	 */
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait: %d\n", ret);
		goto err;
	}
	if (cqe->res != 4096) {
		fprintf(stdout, "Unexpected send result: %d\n", cqe->res);
		io_uring_cqe_seen(&ring, cqe);
		goto err;
	}
	if (cqe->flags & IORING_CQE_F_SOCK_FULL)
		fprintf(stdout, "SOCK_FULL seen, kernel supports it (f=%x, p=%d)\n", rd->ring_flags, rd->pollfirst);
	else
		fprintf(stdout, "SOCK_FULL not set (f=%x, p=%d)\n", rd->ring_flags, rd->pollfirst);
	io_uring_cqe_seen(&ring, cqe);
	
	free(buf);
	close(sockfd);
	io_uring_queue_exit(&ring);
	return 0;
err:
	close(sockfd);
err2:
	io_uring_queue_exit(&ring);
	return 1;
}

static int test(unsigned int ring_flags, int pollfirst)
{
	pthread_t recv_thread;
	struct recv_data rd;
	int ret;
	void *retval;

	pthread_barrier_init(&rd.startup, NULL, 2);
	pthread_barrier_init(&rd.receives, NULL, 2);
	pthread_barrier_init(&rd.finish, NULL, 2);
	rd.pollfirst = pollfirst;
	rd.ring_flags = ring_flags;
	rd.port = use_port++;

	ret = pthread_create(&recv_thread, NULL, recv_fn, &rd);
	if (ret) {
		fprintf(stderr, "Thread create failed: %d\n", ret);
		return 1;
	}

	do_send(&rd);
	pthread_barrier_wait(&rd.finish);
	pthread_join(recv_thread, &retval);
	return (intptr_t)retval;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test(0, 0);
	if (ret) {
		fprintf(stderr, "test 0 0 failed\n");
		return ret;
	}

	ret = test(0, 1);
	if (ret) {
		fprintf(stderr, "test 0 1 failed\n");
		return ret;
	}

	ret = test(IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_SINGLE_ISSUER, 0);
	if (ret) {
		fprintf(stderr, "test defer 0 failed\n");
		return ret;
	}

	ret = test(IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_SINGLE_ISSUER, 1);
	if (ret) {
		fprintf(stderr, "test defer 1 failed\n");
		return ret;
	}


	return T_EXIT_PASS;
}
