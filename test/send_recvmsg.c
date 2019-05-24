#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../src/liburing.h"

static char str[] = "This is a test of sendmsg and recvmsg over io_uring!";

#define MAX_MSG	128

#define PORT	10200
#define HOST	"127.0.0.1"

static int do_recvmsg(void)
{
        struct sockaddr_in saddr;
        char buf[MAX_MSG + 1];
        struct msghdr msg;
        struct iovec iov;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	char *recv_str;
        int sockfd, ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		printf("queue init fail\n");
		return 1;
	}

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons(PORT);
        bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));

	memset(&msg, 0, sizeof(msg));
        msg.msg_namelen = sizeof(struct sockaddr_in);

	iov.iov_base = buf;
	iov.iov_len = MAX_MSG;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sqe = io_uring_get_sqe(&ring);
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_RECVMSG;
	sqe->fd = sockfd;
	sqe->addr = (uint64_t) &msg;
	sqe->len = 1;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		printf("submit failed\n");
		goto err;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (cqe->res < 0) {
		printf("failed cqe: %d\n", cqe->res);
		goto err;
	}

	if (cqe->res -1 != strlen(str)) {
		printf("got wrong length\n");
		goto err;
	}

        recv_str = msg.msg_iov[0].iov_base;
	if (strcmp(str, recv_str)) {
		printf("string mismatch\n");
		goto err;
	}

	close(sockfd);
	return 0;
err:
	close(sockfd);
	return 1;
}

static int do_sendmsg(void)
{
	struct sockaddr_in saddr;
	struct msghdr msg;
	struct iovec iov;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int sockfd, ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		printf("queue init fail\n");
		return 1;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	inet_pton(AF_INET, HOST, &saddr.sin_addr);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &saddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);

	iov.iov_base = str;
	iov.iov_len = sizeof(str);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sqe = io_uring_get_sqe(&ring);
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_SENDMSG;
	sqe->fd = sockfd;
	sqe->addr = (uint64_t) &msg;
	sqe->len = 1;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		printf("submit failed\n");
		goto err;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (cqe->res < 0) {
		printf("failed cqe: %d\n", cqe->res);
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
	pid_t pid;
	int ret;

	pid = fork();
	switch (pid) {
	case -1:
		printf("fork() failed\n");
		return 1;
	case 0:
		ret = do_sendmsg();
		break;
	default:
		ret = do_recvmsg();
		break;
	}

	return ret;
}
