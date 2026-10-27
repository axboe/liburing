/* SPDX-License-Identifier: MIT */
/*
 * Check IORING_OP_CONNECT against listeners that can't take a new
 * connection yet:
 *
 * - An AF_UNIX listener with a full backlog fails a non-blocking connect(2)
 *   with -EAGAIN. IORING_OP_CONNECT on a non-blocking socket should complete
 *   with -EAGAIN as well, without starting an io-wq worker.
 * - A blocking connect to the same listener should wait until accept()
 *   makes room, then succeed.
 * - A non-blocking TCP connect whose SYN is dropped gets -EINPROGRESS.
 *   IORING_OP_CONNECT should wait for the handshake, then succeed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "liburing.h"
#include "helpers.h"

static int count_iowq_workers(void)
{
	struct dirent *de;
	char path[PATH_MAX], comm[32];
	int nr = 0;
	DIR *dir;

	dir = opendir("/proc/self/task");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		ssize_t n;
		int fd;

		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/proc/self/task/%s/comm",
			 de->d_name);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, comm, sizeof(comm) - 1);
		close(fd);
		if (n <= 0)
			continue;
		comm[n] = '\0';
		if (!strncmp(comm, "iou-wrk-", 8))
			nr++;
	}

	closedir(dir);
	return nr;
}

static int wait_cqe_ms(struct io_uring *ring, unsigned int ms,
		       struct io_uring_cqe **cqe)
{
	struct __kernel_timespec ts = {
		.tv_sec = ms / 1000,
		.tv_nsec = (ms % 1000) * 1000000ULL,
	};

	return io_uring_wait_cqe_timeout(ring, cqe, &ts);
}

static int submit_connect(struct io_uring *ring, int fd,
			  const struct sockaddr *addr, socklen_t addrlen)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_connect(sqe, fd, addr, addrlen);
	sqe->user_data = 1;

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return T_EXIT_FAIL;
	}
	return T_EXIT_PASS;
}

/*
 * Create an AF_UNIX listener with a backlog of 0 and fill its backlog with
 * a non-blocking connect that nobody accepts.
 */
static int unix_full_listener(struct sockaddr_un *addr, socklen_t *addrlen,
			      int *client)
{
	int lfd, fd;

	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket");
		return -1;
	}

	/* Bind with only the family to get a unique abstract address. */
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	if (bind(lfd, (struct sockaddr *)addr, sizeof(sa_family_t)) < 0) {
		perror("bind");
		goto err;
	}
	*addrlen = sizeof(*addr);
	if (getsockname(lfd, (struct sockaddr *)addr, addrlen) < 0) {
		perror("getsockname");
		goto err;
	}
	if (listen(lfd, 0) < 0) {
		perror("listen");
		goto err;
	}

	*client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (*client < 0) {
		perror("socket");
		goto err;
	}
	if (connect(*client, (struct sockaddr *)addr, *addrlen) < 0) {
		perror("connect");
		close(*client);
		goto err;
	}

	/* The backlog is full now, so another non-blocking connect fails. */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("socket");
		close(*client);
		goto err;
	}
	if (connect(fd, (struct sockaddr *)addr, *addrlen) == 0 ||
	    errno != EAGAIN) {
		fprintf(stderr, "backlog not full: %d\n", errno);
		close(fd);
		close(*client);
		goto err;
	}
	close(fd);

	return lfd;
err:
	close(lfd);
	return -1;
}

static int test_unix_nonblock(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct sockaddr_un addr;
	socklen_t addrlen;
	int lfd, client, fd, ret, workers;

	lfd = unix_full_listener(&addr, &addrlen, &client);
	if (lfd < 0)
		return T_EXIT_FAIL;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("socket");
		return T_EXIT_FAIL;
	}

	ret = submit_connect(ring, fd, (struct sockaddr *)&addr, addrlen);
	if (ret)
		return ret;

	ret = wait_cqe_ms(ring, 5000, &cqe);
	if (ret) {
		fprintf(stderr, "non-blocking connect: no cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	if (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP)
		return T_EXIT_SKIP;
	if (cqe->res != -EAGAIN) {
		fprintf(stderr, "non-blocking connect: got %d, wanted %d\n",
			cqe->res, -EAGAIN);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(ring, cqe);

	/*
	 * Polling the client socket can't tell when the listener's backlog
	 * drains, and a non-blocking connect from io-wq fails with -EAGAIN
	 * too. An io-wq worker means that the request was punted for nothing.
	 */
	workers = count_iowq_workers();
	if (workers) {
		fprintf(stderr, "non-blocking connect: %d io-wq workers\n",
			workers);
		return T_EXIT_FAIL;
	}

	close(fd);
	close(client);
	close(lfd);
	return T_EXIT_PASS;
}

static int test_unix_block(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct sockaddr_un addr;
	socklen_t addrlen;
	int lfd, client, fd, afd, ret;

	lfd = unix_full_listener(&addr, &addrlen, &client);
	if (lfd < 0)
		return T_EXIT_FAIL;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return T_EXIT_FAIL;
	}

	ret = submit_connect(ring, fd, (struct sockaddr *)&addr, addrlen);
	if (ret)
		return ret;

	ret = wait_cqe_ms(ring, 200, &cqe);
	if (!ret) {
		if (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP)
			return T_EXIT_SKIP;
		fprintf(stderr, "blocking connect: completed early: %d\n",
			cqe->res);
		return T_EXIT_FAIL;
	}
	if (ret != -ETIME) {
		fprintf(stderr, "blocking connect: wait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	/* accept() makes room in the backlog, so the connect can go through. */
	afd = accept(lfd, NULL, NULL);
	if (afd < 0) {
		perror("accept");
		return T_EXIT_FAIL;
	}

	ret = wait_cqe_ms(ring, 5000, &cqe);
	if (ret) {
		fprintf(stderr, "blocking connect: no cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	if (cqe->res) {
		fprintf(stderr, "blocking connect: got %d\n", cqe->res);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(ring, cqe);

	close(afd);
	close(fd);
	close(client);
	close(lfd);
	return T_EXIT_PASS;
}

/*
 * A TCP listener drops SYNs while its accept queue is full, so a
 * non-blocking connect gets -EINPROGRESS and only completes after accept()
 * made room and the client retransmitted its SYN.
 */
static int test_tcp_inprogress(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t addrlen = sizeof(addr);
	struct pollfd pfd;
	int lfd, client, fd, afd, ret;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		perror("socket");
		return T_EXIT_FAIL;
	}
	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    getsockname(lfd, (struct sockaddr *)&addr, &addrlen) < 0 ||
	    listen(lfd, 0) < 0) {
		perror("bind/listen");
		return T_EXIT_FAIL;
	}

	client = socket(AF_INET, SOCK_STREAM, 0);
	if (client < 0) {
		perror("socket");
		return T_EXIT_FAIL;
	}
	if (connect(client, (struct sockaddr *)&addr, addrlen) < 0) {
		perror("connect");
		return T_EXIT_FAIL;
	}

	/* Wait until the first connection sits in the accept queue. */
	pfd.fd = lfd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 5000) != 1) {
		fprintf(stderr, "listener not readable\n");
		return T_EXIT_FAIL;
	}

	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("socket");
		return T_EXIT_FAIL;
	}

	ret = submit_connect(ring, fd, (struct sockaddr *)&addr, addrlen);
	if (ret)
		return ret;

	ret = wait_cqe_ms(ring, 200, &cqe);
	if (!ret) {
		if (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP)
			return T_EXIT_SKIP;
		fprintf(stderr, "tcp connect: completed early: %d\n", cqe->res);
		return T_EXIT_FAIL;
	}
	if (ret != -ETIME) {
		fprintf(stderr, "tcp connect: wait: %d\n", ret);
		return T_EXIT_FAIL;
	}

	afd = accept(lfd, NULL, NULL);
	if (afd < 0) {
		perror("accept");
		return T_EXIT_FAIL;
	}

	/* The client retransmits its SYN after one second. */
	ret = wait_cqe_ms(ring, 10000, &cqe);
	if (ret) {
		fprintf(stderr, "tcp connect: no cqe: %d\n", ret);
		return T_EXIT_FAIL;
	}
	if (cqe->res) {
		fprintf(stderr, "tcp connect: got %d\n", cqe->res);
		return T_EXIT_FAIL;
	}
	io_uring_cqe_seen(ring, cqe);

	close(afd);
	close(fd);
	close(client);
	close(lfd);
	return T_EXIT_PASS;
}

/*
 * Run each test in its own process, so it starts without io-wq workers
 * that an earlier test created.
 */
static int run(int (*fn)(struct io_uring *), unsigned int flags,
	       const char *name)
{
	struct io_uring ring;
	int ret, status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return T_EXIT_FAIL;
	}
	if (!pid) {
		ret = io_uring_queue_init(8, &ring, flags);
		if (ret == -EINVAL || ret == -EPERM)
			exit(T_EXIT_SKIP);
		if (ret) {
			fprintf(stderr, "ring setup failed: %d\n", ret);
			exit(T_EXIT_FAIL);
		}
		ret = fn(&ring);
		io_uring_queue_exit(&ring);
		exit(ret);
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return T_EXIT_FAIL;
	}
	if (!WIFEXITED(status)) {
		fprintf(stderr, "%s (flags %x): child died\n", name, flags);
		return T_EXIT_FAIL;
	}
	ret = WEXITSTATUS(status);
	if (ret == T_EXIT_FAIL)
		fprintf(stderr, "%s (flags %x) failed\n", name, flags);
	return ret;
}

int main(int argc, char *argv[])
{
	static const unsigned int ring_flags[] = {
		0,
		IORING_SETUP_SQPOLL,
		IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
	};
	static const struct {
		int (*fn)(struct io_uring *);
		const char *name;
	} tests[] = {
		{ test_unix_nonblock, "unix non-blocking" },
		{ test_unix_block, "unix blocking" },
		{ test_tcp_inprogress, "tcp in progress" },
	};
	bool any_passed = false, failed = false;
	unsigned int i, j;
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	for (i = 0; i < ARRAY_SIZE(ring_flags); i++) {
		for (j = 0; j < ARRAY_SIZE(tests); j++) {
			ret = run(tests[j].fn, ring_flags[i], tests[j].name);
			if (ret == T_EXIT_FAIL)
				failed = true;
			else if (ret == T_EXIT_PASS)
				any_passed = true;
		}
	}

	if (failed)
		return T_EXIT_FAIL;
	return any_passed ? T_EXIT_PASS : T_EXIT_SKIP;
}
