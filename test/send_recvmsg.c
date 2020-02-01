/*
 * Simple test case showing using sendmsg and recvmsg through io_uring
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "liburing.h"

static char str[] = "This is a test of sendmsg and recvmsg over io_uring!";

#define MAX_MSG	128

#define PORT	10200
#define HOST	"127.0.0.1"

static int recv_prep(struct io_uring *ring, struct iovec *iov)
{
	struct sockaddr_in saddr;
	struct msghdr msg;
	struct io_uring_sqe *sqe;
	int sockfd, ret;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("bind");
		goto err;
	}

	memset(&msg, 0, sizeof(msg));
        msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recvmsg(sqe, sockfd, &msg, 0);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	return 0;
err:
	close(sockfd);
	return 1;
}

static int do_recvmsg(struct io_uring *ring, struct iovec *iov)
{
	struct io_uring_cqe *cqe;

	io_uring_wait_cqe(ring, &cqe);
	if (cqe->res < 0) {
		fprintf(stderr, "failed cqe: %d\n", cqe->res);
		goto err;
	}

	if (cqe->res -1 != strlen(str)) {
		fprintf(stderr, "got wrong length: %d/%d\n", cqe->res,
							(int) strlen(str) + 1);
		goto err;
	}

	if (strcmp(str, iov->iov_base)) {
		fprintf(stderr, "string mismatch\n");
		goto err;
	}

	return 0;
err:
	return 1;
}

static void *recv_fn(void *data)
{
	pthread_mutex_t *mutex = data;
	char buf[MAX_MSG + 1];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf) - 1,
	};
	struct io_uring ring;
	int ret;

	io_uring_queue_init(1, &ring, 0);

	recv_prep(&ring, &iov);
	pthread_mutex_unlock(mutex);
	ret = do_recvmsg(&ring, &iov);

	io_uring_queue_exit(&ring);
	return (void *)(intptr_t)ret;
}

static int do_sendmsg(void)
{
	struct sockaddr_in saddr;
	struct iovec iov = {
		.iov_base = str,
		.iov_len = sizeof(str),
	};
	struct msghdr msg;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init fail: %d\n", ret);
		return 1;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	inet_pton(AF_INET, HOST, &saddr.sin_addr);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &saddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_sendmsg(sqe, sockfd, &msg, 0);

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (cqe->res < 0) {
		fprintf(stderr, "failed cqe: %d\n", cqe->res);
		goto err;
	}

	close(sockfd);
	return 0;
err:
	close(sockfd);
	return 1;
}

int main(int argc, char *argv[])
{
	pthread_mutexattr_t attr;
	pthread_t recv_thread;
	pthread_mutex_t mutex;
	int ret;
	void *retval;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, 1);
	pthread_mutex_init(&mutex, &attr);
	pthread_mutex_lock(&mutex);

	ret = pthread_create(&recv_thread, NULL, recv_fn, &mutex);
	if (ret) {
		fprintf(stderr, "Thread create failed\n");
		return 1;
	}

	pthread_mutex_lock(&mutex);
	do_sendmsg();
	pthread_join(recv_thread, &retval);
	ret = (int)(intptr_t)retval;

	return ret;
}
