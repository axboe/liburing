/*
 * Check that IORING_OP_ACCEPT works, and send some data across to verify we
 * didn't get a junk fd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <liburing.h>

static void queue_send(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe;
	char send_buff[128];
	struct iovec iov;

	iov.iov_base = send_buff;
	iov.iov_len = sizeof(send_buff);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_writev(sqe, fd, &iov, 1, 0);
}

static void queue_recv(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe;
	char recv_buff[128];
	struct iovec iov;

	iov.iov_base = recv_buff;
	iov.iov_len = sizeof(recv_buff);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_readv(sqe, fd, &iov, 1, 0);
}

static int accept_conn(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_accept(sqe, fd, NULL, NULL, 0);

	assert(io_uring_submit(ring) != -1);

	assert(!io_uring_wait_cqe(ring, &cqe));
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

int main(int argc, char *argv[])
{
	struct io_uring m_io_uring;
	struct io_uring_cqe *cqe;
	uint32_t head;
	uint32_t count = 0;
	int done = 0;
	int p_fd[2];

	int32_t recv_s0 = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);

	int32_t val = 1;
	assert(setsockopt(recv_s0, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) != -1);
	assert(setsockopt(recv_s0, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != -1);

	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = 0x1235;
	addr.sin_addr.s_addr = 0x0100007fU;

	assert(bind(recv_s0, (struct sockaddr*)&addr, sizeof(addr)) != -1);
	assert(listen(recv_s0, 128) != -1);

	p_fd[1] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);

	val = 1;
	assert(setsockopt(p_fd[1], IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) != -1);

	int32_t flags = fcntl(p_fd[1], F_GETFL, 0);
	assert(flags != -1);

	flags |= O_NONBLOCK;
	assert(fcntl(p_fd[1], F_SETFL, flags) != -1);

	assert(connect(p_fd[1], (struct sockaddr*)&addr, sizeof(addr)) == -1);

	flags = fcntl(p_fd[1], F_GETFL, 0);
	assert(flags != -1);

	flags &= ~O_NONBLOCK;
	assert(fcntl(p_fd[1], F_SETFL, flags) != -1);

	assert(io_uring_queue_init(32, &m_io_uring, 0) >= 0);

	p_fd[0] = accept_conn(&m_io_uring, recv_s0);
	if (p_fd[0] == -EINVAL) {
		fprintf(stdout, "Accept not supported, skipping\n");
		goto out;
	}
	assert(p_fd[0] >= 0);

	queue_send(&m_io_uring, p_fd[1]);
	queue_recv(&m_io_uring, p_fd[0]);

	assert(io_uring_submit_and_wait(&m_io_uring, 2) != -1);

	while (count < 2) {
		io_uring_for_each_cqe(&m_io_uring, head, cqe) {
			if (cqe->res < 0) {
				fprintf(stderr, "Got cqe res %d\n", cqe->res);
				done = 1;
				break;
			}
			assert(cqe->res == 128);
			count++;
		}

		assert(count <= 2);
		io_uring_cq_advance(&m_io_uring, count);
		if (done)
			goto err;
	}

out:
	io_uring_queue_exit(&m_io_uring);
	return 0;
err:
	io_uring_queue_exit(&m_io_uring);
	return 1;
}
