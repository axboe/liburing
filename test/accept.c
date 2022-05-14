/* SPDX-License-Identifier: MIT */
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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "helpers.h"
#include "liburing.h"

static int no_accept;

struct data {
	char buf[128];
	struct iovec iov;
};

static void queue_send(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe;
	struct data *d;

	d = t_malloc(sizeof(*d));
	d->iov.iov_base = d->buf;
	d->iov.iov_len = sizeof(d->buf);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_writev(sqe, fd, &d->iov, 1, 0);
	sqe->user_data = 1;
}

static void queue_recv(struct io_uring *ring, int fd, bool fixed)
{
	struct io_uring_sqe *sqe;
	struct data *d;

	d = t_malloc(sizeof(*d));
	d->iov.iov_base = d->buf;
	d->iov.iov_len = sizeof(d->buf);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_readv(sqe, fd, &d->iov, 1, 0);
	sqe->user_data = 2;
	if (fixed)
		sqe->flags |= IOSQE_FIXED_FILE;
}

static void queue_accept_conn(struct io_uring *ring,
			      int fd, int fixed_idx,
			      int count)
{
	struct io_uring_sqe *sqe;
	int ret;

	while (count--) {
		sqe = io_uring_get_sqe(ring);
		if (fixed_idx < 0)
			io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
		else
			io_uring_prep_accept_direct(sqe, fd, NULL, NULL, 0,
						    fixed_idx);

		ret = io_uring_submit(ring);
		assert(ret != -1);
	}
}

static int accept_conn(struct io_uring *ring, int fixed_idx)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_wait_cqe(ring, &cqe);
	assert(!ret);
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);

	if (fixed_idx >= 0) {
		if (ret > 0) {
			close(ret);
			return -EINVAL;
		} else if (!ret) {
			ret = fixed_idx;
		}
	}
	return ret;
}

static int start_accept_listen(struct sockaddr_in *addr, int port_off,
			       int extra_flags)
{
	int fd, ret;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | extra_flags,
		    IPPROTO_TCP);

	int32_t val = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
	assert(ret != -1);
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	assert(ret != -1);

	struct sockaddr_in laddr;

	if (!addr)
		addr = &laddr;

	addr->sin_family = AF_INET;
	addr->sin_port = htons(0x1235 + port_off);
	addr->sin_addr.s_addr = inet_addr("127.0.0.1");

	ret = bind(fd, (struct sockaddr*)addr, sizeof(*addr));
	assert(ret != -1);
	ret = listen(fd, 128);
	assert(ret != -1);

	return fd;
}

struct accept_test_args {
	int accept_should_error;
	bool fixed;
	bool nonblock;
	bool queue_accept_before_connect;
	int extra_loops;
};


static int test_loop(struct io_uring *ring,
		     struct accept_test_args args,
		     int recv_s0,
		     struct sockaddr_in *addr)
{
	struct io_uring_cqe *cqe;
	uint32_t head, count = 0;
	int ret, p_fd[2], done = 0;
	int32_t val;

	p_fd[1] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);

	val = 1;
	ret = setsockopt(p_fd[1], IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	assert(ret != -1);

	int32_t flags = fcntl(p_fd[1], F_GETFL, 0);
	assert(flags != -1);

	flags |= O_NONBLOCK;
	ret = fcntl(p_fd[1], F_SETFL, flags);
	assert(ret != -1);

	ret = connect(p_fd[1], (struct sockaddr *)addr, sizeof(*addr));
	assert(ret == -1);

	flags = fcntl(p_fd[1], F_GETFL, 0);
	assert(flags != -1);

	flags &= ~O_NONBLOCK;
	ret = fcntl(p_fd[1], F_SETFL, flags);
	assert(ret != -1);

	if (!args.queue_accept_before_connect)
		queue_accept_conn(ring, recv_s0, args.fixed ? 0 : -1, 1);

	p_fd[0] = accept_conn(ring, args.fixed ? 0 : -1);
	if (p_fd[0] == -EINVAL) {
		if (args.accept_should_error)
			goto out;
		if (args.fixed)
			fprintf(stdout, "Fixed accept not supported, skipping\n");
		else
			fprintf(stdout, "Accept not supported, skipping\n");
		no_accept = 1;
		goto out;
	} else if (p_fd[0] < 0) {
		if (args.accept_should_error &&
		    (p_fd[0] == -EBADF || p_fd[0] == -EINVAL))
			goto out;
		fprintf(stderr, "Accept got %d\n", p_fd[0]);
		goto err;
	}

	queue_send(ring, p_fd[1]);
	queue_recv(ring, p_fd[0], args.fixed);

	ret = io_uring_submit_and_wait(ring, 2);
	assert(ret != -1);

	while (count < 2) {
		io_uring_for_each_cqe(ring, head, cqe) {
			if (cqe->res < 0) {
				fprintf(stderr, "Got cqe res %d, user_data %i\n",
						cqe->res, (int)cqe->user_data);
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
	if (!args.fixed)
		close(p_fd[0]);
	close(p_fd[1]);
	return 0;
err:
	if (!args.fixed)
		close(p_fd[0]);
	close(p_fd[1]);
	return 1;
}

static int test(struct io_uring *ring, struct accept_test_args args)
{
	struct sockaddr_in addr;
	int ret = 0;
	int loop;
	int32_t recv_s0 = start_accept_listen(&addr, 0,
					      args.nonblock ? O_NONBLOCK : 0);
	if (args.queue_accept_before_connect)
		queue_accept_conn(ring, recv_s0, args.fixed ? 0 : -1,
				  1 + args.extra_loops);
	for (loop = 0; loop < 1 + args.extra_loops; loop++) {
		ret = test_loop(ring, args, recv_s0, &addr);
		if (ret)
			break;
	}

	close(recv_s0);
	return ret;
}

static void sig_alrm(int sig)
{
	exit(0);
}

static int test_accept_pending_on_exit(void)
{
	struct io_uring m_io_uring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int fd, ret;

	ret = io_uring_queue_init(32, &m_io_uring, 0);
	assert(ret >= 0);

	fd = start_accept_listen(NULL, 0, 0);

	sqe = io_uring_get_sqe(&m_io_uring);
	io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
	ret = io_uring_submit(&m_io_uring);
	assert(ret != -1);

	signal(SIGALRM, sig_alrm);
	alarm(1);
	ret = io_uring_wait_cqe(&m_io_uring, &cqe);
	assert(!ret);
	io_uring_cqe_seen(&m_io_uring, cqe);

	io_uring_queue_exit(&m_io_uring);
	return 0;
}

struct test_accept_many_args {
	unsigned int usecs;
	bool nonblock;
	bool single_sock;
	bool close_fds;
};

/*
 * Test issue many accepts and see if we handle cancellation on exit
 */
static int test_accept_many(struct test_accept_many_args args)
{
	struct io_uring m_io_uring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	unsigned long cur_lim;
	struct rlimit rlim;
	int *fds, i, ret;
	unsigned int nr = 128;
	int nr_socks = args.single_sock ? 1 : nr;

	if (getrlimit(RLIMIT_NPROC, &rlim) < 0) {
		perror("getrlimit");
		return 1;
	}

	cur_lim = rlim.rlim_cur;
	rlim.rlim_cur = nr / 4;

	if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
		perror("setrlimit");
		return 1;
	}

	ret = io_uring_queue_init(2 * nr, &m_io_uring, 0);
	assert(ret >= 0);

	fds = t_calloc(nr_socks, sizeof(int));

	for (i = 0; i < nr_socks; i++)
		fds[i] = start_accept_listen(NULL, i,
					     args.nonblock ? O_NONBLOCK : 0);

	for (i = 0; i < nr; i++) {
		int sock_idx = args.single_sock ? 0 : i;
		sqe = io_uring_get_sqe(&m_io_uring);
		io_uring_prep_accept(sqe, fds[sock_idx], NULL, NULL, 0);
		sqe->user_data = 1 + i;
		ret = io_uring_submit(&m_io_uring);
		assert(ret == 1);
	}

	if (args.usecs)
		usleep(args.usecs);

	if (args.close_fds)
		for (i = 0; i < nr_socks; i++)
			close(fds[i]);

	for (i = 0; i < nr; i++) {
		if (io_uring_peek_cqe(&m_io_uring, &cqe))
			break;
		if (cqe->res != -ECANCELED) {
			fprintf(stderr, "Expected cqe to be cancelled %d\n", cqe->res);
			ret = 1;
			goto out;
		}
		io_uring_cqe_seen(&m_io_uring, cqe);
	}
	ret = 0;
out:
	rlim.rlim_cur = cur_lim;
	if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
		perror("setrlimit");
		return 1;
	}

	free(fds);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

static int test_accept_cancel(unsigned usecs, unsigned int nr)
{
	struct io_uring m_io_uring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int fd, i, ret;

	ret = io_uring_queue_init(32, &m_io_uring, 0);
	assert(ret >= 0);

	fd = start_accept_listen(NULL, 0, 0);

	for (i = 1; i <= nr; i++) {
		sqe = io_uring_get_sqe(&m_io_uring);
		io_uring_prep_accept(sqe, fd, NULL, NULL, 0);
		sqe->user_data = i;
		ret = io_uring_submit(&m_io_uring);
		assert(ret == 1);
	}

	if (usecs)
		usleep(usecs);

	for (i = 1; i <= nr; i++) {
		sqe = io_uring_get_sqe(&m_io_uring);
		io_uring_prep_cancel(sqe, i, 0);
		sqe->user_data = nr + i;
		ret = io_uring_submit(&m_io_uring);
		assert(ret == 1);
	}
	for (i = 0; i < nr * 2; i++) {
		ret = io_uring_wait_cqe(&m_io_uring, &cqe);
		assert(!ret);
		/*
		 * Two cases here:
		 *
		 * 1) We cancel the accept4() before it got started, we should
		 *    get '0' for the cancel request and '-ECANCELED' for the
		 *    accept request.
		 * 2) We cancel the accept4() after it's already running, we
		 *    should get '-EALREADY' for the cancel request and
		 *    '-EINTR' for the accept request.
		 */
		if (cqe->user_data == 0) {
			fprintf(stderr, "unexpected 0 user data\n");
			goto err;
		} else if (cqe->user_data <= nr) {
			if (cqe->res != -EINTR && cqe->res != -ECANCELED) {
				fprintf(stderr, "Cancelled accept got %d\n", cqe->res);
				goto err;
			}
		} else if (cqe->user_data <= nr * 2) {
			if (cqe->res != -EALREADY && cqe->res != 0) {
				fprintf(stderr, "Cancel got %d\n", cqe->res);
				goto err;
			}
		}
		io_uring_cqe_seen(&m_io_uring, cqe);
	}

	io_uring_queue_exit(&m_io_uring);
	close(fd);
	return 0;
err:
	io_uring_queue_exit(&m_io_uring);
	close(fd);
	return 1;
}

static int test_accept(int count, bool before)
{
	struct io_uring m_io_uring;
	int ret;
	struct accept_test_args args = {
		.queue_accept_before_connect = before,
		.extra_loops = count - 1
	};

	ret = io_uring_queue_init(32, &m_io_uring, 0);
	assert(ret >= 0);
	ret = test(&m_io_uring, args);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

static int test_accept_nonblock(bool queue_before_connect, int count)
{
	struct io_uring m_io_uring;
	int ret;
	struct accept_test_args args = {
		.nonblock = true,
		.queue_accept_before_connect = queue_before_connect,
		.extra_loops = count - 1
	};

	ret = io_uring_queue_init(32, &m_io_uring, 0);
	assert(ret >= 0);
	ret = test(&m_io_uring, args);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

static int test_accept_fixed(void)
{
	struct io_uring m_io_uring;
	int ret, fd = -1;
	struct accept_test_args args = {
		.fixed = true
	};

	ret = io_uring_queue_init(32, &m_io_uring, 0);
	assert(ret >= 0);
	ret = io_uring_register_files(&m_io_uring, &fd, 1);
	assert(ret == 0);
	ret = test(&m_io_uring, args);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

static int test_accept_sqpoll(void)
{
	struct io_uring m_io_uring;
	struct io_uring_params p = { };
	int ret;
	struct accept_test_args args = { };

	p.flags = IORING_SETUP_SQPOLL;
	ret = t_create_ring_params(32, &m_io_uring, &p);
	if (ret == T_SETUP_SKIP)
		return 0;
	else if (ret < 0)
		return ret;

	args.accept_should_error = 1;
	if (p.features & IORING_FEAT_SQPOLL_NONFIXED)
		args.accept_should_error = 0;

	ret = test(&m_io_uring, args);
	io_uring_queue_exit(&m_io_uring);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_accept(1, false);
	if (ret) {
		fprintf(stderr, "test_accept failed\n");
		return ret;
	}
	if (no_accept)
		return 0;

	ret = test_accept(2, false);
	if (ret) {
		fprintf(stderr, "test_accept(2) failed\n");
		return ret;
	}

	ret = test_accept(2, true);
	if (ret) {
		fprintf(stderr, "test_accept(2, true) failed\n");
		return ret;
	}

	ret = test_accept_nonblock(false, 1);
	if (ret) {
		fprintf(stderr, "test_accept_nonblock failed\n");
		return ret;
	}

	ret = test_accept_nonblock(true, 1);
	if (ret) {
		fprintf(stderr, "test_accept_nonblock(before, 1) failed\n");
		return ret;
	}

	ret = test_accept_nonblock(true, 3);
	if (ret) {
		fprintf(stderr, "test_accept_nonblock(before,3) failed\n");
		return ret;
	}

	ret = test_accept_fixed();
	if (ret) {
		fprintf(stderr, "test_accept_fixed failed\n");
		return ret;
	}

	ret = test_accept_sqpoll();
	if (ret) {
		fprintf(stderr, "test_accept_sqpoll failed\n");
		return ret;
	}

	ret = test_accept_cancel(0, 1);
	if (ret) {
		fprintf(stderr, "test_accept_cancel nodelay failed\n");
		return ret;
	}

	ret = test_accept_cancel(10000, 1);
	if (ret) {
		fprintf(stderr, "test_accept_cancel delay failed\n");
		return ret;
	}

	ret = test_accept_cancel(0, 4);
	if (ret) {
		fprintf(stderr, "test_accept_cancel nodelay failed\n");
		return ret;
	}

	ret = test_accept_cancel(10000, 4);
	if (ret) {
		fprintf(stderr, "test_accept_cancel delay failed\n");
		return ret;
	}

	ret = test_accept_many((struct test_accept_many_args) {});
	if (ret) {
		fprintf(stderr, "test_accept_many failed\n");
		return ret;
	}

	ret = test_accept_many((struct test_accept_many_args) {
				.usecs = 100000 });
	if (ret) {
		fprintf(stderr, "test_accept_many(sleep) failed\n");
		return ret;
	}

	ret = test_accept_many((struct test_accept_many_args) {
				.nonblock = true });
	if (ret) {
		fprintf(stderr, "test_accept_many(nonblock) failed\n");
		return ret;
	}

	ret = test_accept_many((struct test_accept_many_args) {
				.nonblock = true,
				.single_sock = true,
				.close_fds = true });
	if (ret) {
		fprintf(stderr, "test_accept_many(nonblock,close) failed\n");
		return ret;
	}

	ret = test_accept_pending_on_exit();
	if (ret) {
		fprintf(stderr, "test_accept_pending_on_exit failed\n");
		return ret;
	}

	return 0;
}
