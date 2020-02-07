/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o io_uring-echo-server io_uring-echo-server.c -luring
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include "liburing.h"

/* adjust these macros to benchmark various operations */
#define POLL_BEFORE_READ 1
#define USE_RECV_SEND 0
#define USE_UNVECTORED_OP 0

#define MAX_CONNECTIONS 1024
#define BACKLOG 128
#define MAX_MESSAGE_LEN 1024

enum {
	ACCEPT,
	POLL,
	READ,
	WRITE,
};

struct conn_info
{
	__u32 fd;
	__u32 type;
};

static char bufs[MAX_CONNECTIONS][MAX_MESSAGE_LEN];

static void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, int flags)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct conn_info conn_i = {
		.fd = fd,
		.type = ACCEPT
	};

	io_uring_prep_accept(sqe, fd, client_addr, client_len, flags);
	memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
	io_uring_submit(ring);
}

#if POLL_BEFORE_READ
static void add_poll(struct io_uring *ring, int fd, int poll_mask)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct conn_info conn_i = {
		.fd = fd,
		.type = POLL
	};

	io_uring_prep_poll_add(sqe, fd, poll_mask);
	memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
	io_uring_submit(ring);
}
#endif

static void add_socket_read(struct io_uring *ring, int fd, size_t size)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct conn_info conn_i = {
		.fd = fd,
		.type = READ
	};

#if USE_UNVECTORED_OP
#	if USE_RECV_SEND
	io_uring_prep_recv(sqe, fd, bufs[fd], size, MSG_NOSIGNAL);
#	else
	io_uring_prep_read(sqe, fd, bufs[fd], size, 0);
#	endif
#else
	struct iovec iov = {
		.iov_base = bufs[fd],
		.iov_len = size,
	};
#	if USE_RECV_SEND
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	io_uring_prep_recvmsg(sqe, fd, &msg, MSG_NOSIGNAL);
#	else
	io_uring_prep_readv(sqe, fd, &iov, 1, 0);
#	endif
#endif

	memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
	io_uring_submit(ring);
}

static void add_socket_write(struct io_uring *ring, int fd, size_t size)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct conn_info conn_i = {
		.fd = fd,
		.type = WRITE
	};

#if USE_UNVECTORED_OP
#	if USE_RECV_SEND
	io_uring_prep_send(sqe, fd, bufs[fd], size, MSG_NOSIGNAL);
#	else
	io_uring_prep_write(sqe, fd, bufs[fd], size, 0);
#	endif
#else
	struct iovec iov = {
		.iov_base = bufs[fd],
		.iov_len = size,
	};
#	if USE_RECV_SEND
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	io_uring_prep_sendmsg(sqe, fd, &msg, MSG_NOSIGNAL);
#	else
	io_uring_prep_writev(sqe, fd, &iov, 1, 0);
#	endif
#endif

	memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
	io_uring_submit(ring);
}

int main(int argc, char *argv[])
{
	int portno, sock_listen_fd, ret;
	struct sockaddr_in serv_addr, client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct io_uring ring;

	if (argc < 2)
	{
		fprintf(stderr, "Please give a port number: ./io_uring_echo_server [port]\n");
		return 1;
	}

	portno = strtol(argv[1], NULL, 10);

	sock_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_listen_fd < 0)
	{
		perror("socket");
		return -1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	ret = bind(sock_listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (ret < 0)
	{
		perror("bind");
		return -1;
	}

	ret = listen(sock_listen_fd, BACKLOG);
	if (ret < 0)
	{
		perror("listen");
		return -1;
	}

	printf("io_uring echo server listening for connections on port: %d\n", portno);


	ret = io_uring_queue_init(BACKLOG, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}


	add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, (socklen_t *)&client_len, 0);

	while (1)
	{
		struct io_uring_cqe *cqe;
		struct conn_info conn_i;
		int result;

		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0)
		{
			fprintf(stderr, "io_uring_wait_cqe: %s\n", strerror(-ret));
			return -1;
		}

		memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));
		result = cqe->res;
		io_uring_cqe_seen(&ring, cqe);

		switch (conn_i.type)
		{
		case ACCEPT:
#if POLL_BEFORE_READ
			add_poll(&ring, result, POLLIN);
#else
			add_socket_read(&ring, result, MAX_MESSAGE_LEN);
#endif
			add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, (socklen_t *)&client_len, 0);
			break;

#if POLL_BEFORE_READ
		case POLL:
			add_socket_read(&ring, conn_i.fd, MAX_MESSAGE_LEN);
			break;
#endif

		case READ:
			if (result <= 0)
				shutdown(conn_i.fd, SHUT_RDWR);
			else
				add_socket_write(&ring, conn_i.fd, result);
			break;

		case WRITE:
#if POLL_BEFORE_READ
			add_poll(&ring, conn_i.fd, POLLIN);
#else
			add_socket_read(&ring, conn_i.fd, MAX_MESSAGE_LEN);
#endif
			break;
		}
	}
}
