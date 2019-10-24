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

static int no_accept;

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

static int test(struct io_uring *ring, int accept_should_error)
{
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

	p_fd[0] = accept_conn(ring, recv_s0);
	if (p_fd[0] == -EINVAL) {
		if (accept_should_error)
			goto out;
		fprintf(stdout, "Accept not supported, skipping\n");
		no_accept = 1;
		goto out;
	} else if (p_fd[0] < 0) {
		if (accept_should_error &&
		    (p_fd[0] == -EBADF || p_fd[0] == -EINVAL))
			goto out;
		fprintf(stderr, "Accept got %d\n", p_fd[0]);
		goto err;
	}

	queue_send(ring, p_fd[1]);
	queue_recv(ring, p_fd[0]);

	assert(io_uring_submit_and_wait(ring, 2) != -1);

	while (count < 2) {
		io_uring_for_each_cqe(ring, head, cqe) {
			if (cqe->res < 0) {
				fprintf(stderr, "Got cqe res %d\n", cqe->res);
				done = 1;
				break;
			}
			assert(cqe->res == 128);
			count++;
		}

		assert(count <= 2);
		io_uring_cq_advance(ring, count);
		if (done)
			goto err;
	}

out:
	close(p_fd[0]);
	close(p_fd[1]);
	return 0;
err:
	close(p_fd[0]);
	close(p_fd[1]);
	return 1;
}

static void sig_alrm(int sig)
{
	exit(0);
}

static int test_accept_cancel(void)
{
	struct io_uring m_io_uring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int fd;

	assert(io_uring_queue_init(32, &m_io_uring, 0) >= 0);

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);

	int32_t val = 1;
	assert(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)) != -1);
	assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != -1);

	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = 0x1235;
	addr.sin_addr.s_addr = 0x0100007fU;

	assert(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != -1);
	assert(listen(fd, 128) != -1);

	sqe = io_uring_get_sqe(&m_io_uring);
	io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
	assert(io_uring_submit(&m_io_uring) != -1);

	signal(SIGALRM, sig_alrm);
	alarm(1);
	assert(!io_uring_wait_cqe(&m_io_uring, &cqe));
	io_uring_cqe_seen(&m_io_uring, cqe);

	io_uring_queue_exit(&m_io_uring);
	return 0;
}

static int test_accept(void)
{
	struct io_uring m_io_uring;
	int ret;

	assert(io_uring_queue_init(32, &m_io_uring, 0) >= 0);
	ret = test(&m_io_uring, 0);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

static int test_accept_sqpoll(void)
{
	struct io_uring m_io_uring;
	int ret;

	assert(io_uring_queue_init(32, &m_io_uring, IORING_SETUP_SQPOLL) >= 0);
	ret = test(&m_io_uring, 1);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	ret = test_accept();
	if (ret) {
		fprintf(stderr, "test_accept failed\n");
		return ret;
	}
	if (no_accept)
		return 0;

	ret = test_accept_sqpoll();
	if (ret) {
		fprintf(stderr, "test_accept_sqpoll failed\n");
		return ret;
	}

	ret = test_accept_cancel();
	if (ret) {
		fprintf(stderr, "test_accept_cancel failed\n");
		return ret;
	}

	return 0;
}
