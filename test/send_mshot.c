/* SPDX-License-Identifier: MIT */
/*
 * Simple test case showing using send and recv multishot
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

#define MSG_SIZE 128
#define SEQ_SIZE	(MSG_SIZE / sizeof(unsigned long))

#include "liburing.h"
#include "helpers.h"

#define PORT	10202
#define HOST	"127.0.0.1"

#define SEND_BGID	1
#define RECV_BGID	2

static int no_send_mshot;

struct recv_data {
	pthread_barrier_t connect;
	pthread_barrier_t startup;
	pthread_barrier_t barrier;
	pthread_barrier_t finish;
	unsigned long seq;
	int to_recv;
	int accept_fd;
	int abort;
	void *recv_buf;
};

static int recv_prep(struct io_uring *ring, struct recv_data *rd, int *sock)
{
	struct sockaddr_in saddr;
	struct io_uring_sqe *sqe;
	int sockfd, ret, val, use_fd;
	socklen_t socklen;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);

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

	pthread_barrier_wait(&rd->connect);

	socklen = sizeof(saddr);
	use_fd = accept(sockfd, (struct sockaddr *)&saddr, &socklen);
	if (use_fd < 0) {
		perror("accept");
		goto err;
	}

	rd->accept_fd = use_fd;
	pthread_barrier_wait(&rd->startup);
	pthread_barrier_wait(&rd->barrier);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_recv_multishot(sqe, use_fd, NULL, 0, 0);
	sqe->buf_group = RECV_BGID;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->user_data = 2;

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	*sock = sockfd;
	return 0;
err:
	close(sockfd);
	return 1;
}

static int verify_seq(struct recv_data *rd, struct io_uring_cqe *cqe)
{
	unsigned long *seqp;
	void *buf;
	int i;

	if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
		fprintf(stderr, "no buffer for receive?!\n");
		return 0;
	}

	buf = rd->recv_buf + (cqe->flags >> IORING_CQE_BUFFER_SHIFT) * MSG_SIZE;
	seqp = buf;
	for (i = 0; i < SEQ_SIZE; i++) {
		if (rd->seq != *seqp) {
			printf("got seq %lu, wanted %lu\n", *seqp, rd->seq);
			return 0;
		}
		seqp++;
		rd->seq++;
	}

	return 1;
}

static int recv_get_cqe(struct io_uring *ring, struct recv_data *rd,
			struct io_uring_cqe **cqe)
{
	struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 100000000LL };
	int ret;

	do {
		ret = io_uring_wait_cqe_timeout(ring, cqe, &ts);
		if (!ret)
			return 0;
		if (ret == -ETIME) {
			if (rd->abort)
				break;
			continue;
		}
		fprintf(stderr, "wait recv: %d\n", ret);
		break;
	} while (1);

	return 1;
}

static int do_recv(struct io_uring *ring, struct recv_data *rd)
{
	struct io_uring_cqe *cqe;
	int i;

	for (i = 0; i < rd->to_recv; i++) {
		if (recv_get_cqe(ring, rd, &cqe))
			break;
		if (cqe->res == -EINVAL) {
			fprintf(stdout, "recv not supported, skipping\n");
			return 0;
		}
		if (cqe->res < 0) {
			fprintf(stderr, "failed cqe: %d\n", cqe->res);
			goto err;
		}
		if (cqe->res != MSG_SIZE) {
			fprintf(stderr, "got wrong length: %d\n", cqe->res);
			goto err;
		}
		if (!verify_seq(rd, cqe))
			goto err;
		io_uring_cqe_seen(ring, cqe);
	}

	pthread_barrier_wait(&rd->finish);
	return 0;
err:
	pthread_barrier_wait(&rd->finish);
	return 1;
}

static void *recv_fn(void *data)
{
	struct recv_data *rd = data;
	struct io_uring_params p = { };
	struct io_uring ring;
	struct io_uring_buf_ring *br;
	void *buf, *ptr;
	int ret, sock, i;

	p.cq_entries = 4096;
	p.flags = IORING_SETUP_CQSIZE;
	ret = t_create_ring_params(128, &ring, &p);
	if (ret == T_SETUP_SKIP) {
		ret = 0;
		goto err;
	} else if (ret < 0) {
		goto err;
	}

	if (posix_memalign(&buf, 4096, MSG_SIZE * 2048))
		goto err;

	br = io_uring_setup_buf_ring(&ring, 2048, RECV_BGID, 0, &ret);
	if (!br) {
		fprintf(stderr, "failed setting up recv ring %d\n", ret);
		goto err;
	}

	ptr = buf;
	for (i = 0; i < 2048; i++) {
		io_uring_buf_ring_add(br, ptr, MSG_SIZE, i, 2047, i);
		ptr += MSG_SIZE;
	}
	io_uring_buf_ring_advance(br, 2048);
	rd->recv_buf = buf;

	ret = recv_prep(&ring, rd, &sock);
	if (ret) {
		fprintf(stderr, "recv_prep failed: %d\n", ret);
		goto err;
	}

	ret = do_recv(&ring, rd);

	close(sock);
	close(rd->accept_fd);
	io_uring_queue_exit(&ring);
err:
	return (void *)(intptr_t)ret;
}

static int do_send(struct recv_data *rd, int backlog)
{
	struct sockaddr_in saddr;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long seq_buf[SEQ_SIZE], send_seq;
	struct io_uring_params p = { };
	struct io_uring_buf_ring *br;
	int sockfd, ret, len, i;
	socklen_t optlen;
	void *buf, *ptr;

	ret = io_uring_queue_init(128, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return 1;
	}
	if (!(p.features & IORING_FEAT_SEND_BUF_SELECT)) {
		no_send_mshot = 1;
		return 0;
	}

	if (posix_memalign(&buf, 4096, MSG_SIZE * 8))
		return 1;

	br = io_uring_setup_buf_ring(&ring, 8, SEND_BGID, 0, &ret);
	if (!br) {
		if (ret == -EINVAL) {
			no_send_mshot = 1;
			return 0;
		}
		printf("failed setting up send ring %d\n", ret);
		return 1;
	}

	ptr = buf;
	for (i = 0; i < 4; i++) {
		io_uring_buf_ring_add(br, ptr, MSG_SIZE, i, 7, i);
		ptr += MSG_SIZE;
	}
	io_uring_buf_ring_advance(br, 4);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	inet_pton(AF_INET, HOST, &saddr.sin_addr);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		goto err2;
	}

	pthread_barrier_wait(&rd->connect);

	ret = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		perror("connect");
		goto err;
	}

	pthread_barrier_wait(&rd->startup);

	optlen = sizeof(len);
	len = 256 * MSG_SIZE;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &len, optlen);

	getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &len, &optlen);

	/* almost fill queue, leave room for one message */
	send_seq = 0;
	while (backlog) {
		for (i = 0; i < SEQ_SIZE; i++)
			seq_buf[i] = send_seq++;

		ret = send(sockfd, seq_buf, sizeof(seq_buf), MSG_DONTWAIT);
		if (ret < 0) {
			if (errno == EAGAIN) {
				send_seq -= SEQ_SIZE;
				break;
			}
			perror("send");
			return 1;
		} else if (ret != sizeof(seq_buf)) {
			printf("short %d send\n", ret);
			return 1;
		}

		rd->to_recv++;
	}

	ptr = buf;
	for (i = 0; i < 4; i++) {
		unsigned long *pseq = ptr;
		int j;

		for (j = 0; j < SEQ_SIZE; j++)
			pseq[j] = send_seq++;
		ptr += MSG_SIZE;
	}

	/* prepare 4 more messages, sending with multishot */
	rd->to_recv += 4;
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_send(sqe, sockfd, NULL, MSG_SIZE, 0);
	sqe->ioprio = IORING_SEND_MULTISHOT;
	sqe->user_data = 1;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = SEND_BGID;

	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit failed: %d\n", ret);
		goto err;
	}

	pthread_barrier_wait(&rd->barrier);

	for (i = 0; i < 4; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait send: %d\n", ret);
			goto err;
		}
		if (!i && cqe->res == -EINVAL) {
			rd->abort = 1;
			no_send_mshot = 1;
			break;
		}
		/* more should be set on all but the last */
		if (cqe->flags & IORING_CQE_F_MORE) {
			if (i == 3) {
				fprintf(stderr, "MORE set on last send\n");
				goto err;
			}
		} else {
			if (i != 3) {
				fprintf(stderr, "MORE not set on send\n");
				goto err;
			}
		}
		if (cqe->res != MSG_SIZE) {
			fprintf(stderr, "failed cqe: %d\n", cqe->res);
			goto err;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	pthread_barrier_wait(&rd->finish);

	close(sockfd);
	io_uring_queue_exit(&ring);
	return 0;

err:
	close(sockfd);
err2:
	io_uring_queue_exit(&ring);
	pthread_barrier_wait(&rd->finish);
	return 1;
}

static int test(int backlog)
{
	pthread_t recv_thread;
	struct recv_data rd;
	int ret;
	void *retval;

	memset(&rd, 0, sizeof(rd));
	pthread_barrier_init(&rd.connect, NULL, 2);
	pthread_barrier_init(&rd.startup, NULL, 2);
	pthread_barrier_init(&rd.barrier, NULL, 2);
	pthread_barrier_init(&rd.finish, NULL, 2);

	ret = pthread_create(&recv_thread, NULL, recv_fn, &rd);
	if (ret) {
		fprintf(stderr, "Thread create failed: %d\n", ret);
		return 1;
	}

	ret = do_send(&rd, backlog);
	if (no_send_mshot)
		return 0;

	if (ret)
		return ret;

	pthread_join(recv_thread, &retval);
	return (intptr_t)retval;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test(0);
	if (ret) {
		fprintf(stderr, "test 0 failed\n");
		return T_EXIT_FAIL;
	}
	if (no_send_mshot)
		return T_EXIT_SKIP;

	ret = test(1);
	if (ret) {
		fprintf(stderr, "test 1 failed\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}
