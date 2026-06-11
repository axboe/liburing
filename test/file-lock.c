/* SPDX-License-Identifier: MIT */
/*
 * Description: test IORING_OP_FLOCK and IORING_OP_OFD_LOCK, both basic
 * functionality (conflicts, pending grants, cancelation, interop with the
 * flock(2)/fcntl(2) syscalls) and deliberate error cases.
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "liburing.h"
#include "helpers.h"

#ifndef F_OFD_SETLK
#define F_OFD_SETLK	37
#endif

static int no_filelock;

static int submit_wait_res(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return INT_MIN;
	}
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe: %d\n", ret);
		return INT_MIN;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int do_flock(struct io_uring *ring, int fd, int op)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd, op);
	return submit_wait_res(ring);
}

static int do_ofd(struct io_uring *ring, int fd, int type, __u64 start,
		  __u64 len, unsigned int flags)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_ofd_lock(sqe, fd, type, start, len, flags);
	return submit_wait_res(ring);
}

/*
 * Submit a lock request that is expected to remain pending, and verify
 * that no completion arrives for it.
 */
static int submit_pending(struct io_uring *ring, struct io_uring_sqe *sqe,
			  __u64 user_data)
{
	struct __kernel_timespec ts = { .tv_nsec = 100000000 };
	struct io_uring_cqe *cqe;
	int ret;

	sqe->user_data = user_data;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
	if (ret != -ETIME) {
		fprintf(stderr, "lock not pending: %d/%d\n", ret,
			!ret ? cqe->res : 0);
		return 1;
	}
	return 0;
}

/*
 * Reap @nr completions, returning the res of the one matching @user_data
 * and verifying that all others returned success.
 */
static int reap_match(struct io_uring *ring, int nr, __u64 user_data)
{
	struct io_uring_cqe *cqe;
	int i, ret, res = INT_MIN;

	for (i = 0; i < nr; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait_cqe: %d\n", ret);
			return INT_MIN;
		}
		if (cqe->user_data == user_data)
			res = cqe->res;
		else if (cqe->res < 0) {
			fprintf(stderr, "cqe %d: unexpected res %d\n",
				(int) cqe->user_data, cqe->res);
			res = INT_MIN;
		}
		io_uring_cqe_seen(ring, cqe);
	}
	return res;
}

static int test_flock_basic(struct io_uring *ring, int fd1, int fd2)
{
	int ret;

	ret = do_flock(ring, fd1, LOCK_EX);
	if (ret == -EINVAL || ret == -EOPNOTSUPP) {
		no_filelock = 1;
		return 0;
	}
	if (ret) {
		fprintf(stderr, "flock EX: %d\n", ret);
		return 1;
	}
	ret = do_flock(ring, fd2, LOCK_EX | LOCK_NB);
	if (ret != -EAGAIN) {
		fprintf(stderr, "flock EX|NB vs EX: %d\n", ret);
		return 1;
	}
	ret = do_flock(ring, fd2, LOCK_SH | LOCK_NB);
	if (ret != -EAGAIN) {
		fprintf(stderr, "flock SH|NB vs EX: %d\n", ret);
		return 1;
	}
	/* same lock space as the syscall */
	if (!flock(fd2, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK) {
		fprintf(stderr, "flock(2) interop broken\n");
		return 1;
	}
	ret = do_flock(ring, fd1, LOCK_UN);
	if (ret) {
		fprintf(stderr, "flock UN: %d\n", ret);
		return 1;
	}
	/* shared locks don't conflict */
	ret = do_flock(ring, fd1, LOCK_SH);
	if (ret) {
		fprintf(stderr, "flock SH: %d\n", ret);
		return 1;
	}
	ret = do_flock(ring, fd2, LOCK_SH | LOCK_NB);
	if (ret) {
		fprintf(stderr, "flock SH|NB vs SH: %d\n", ret);
		return 1;
	}
	if (do_flock(ring, fd1, LOCK_UN) || do_flock(ring, fd2, LOCK_UN)) {
		fprintf(stderr, "flock UN\n");
		return 1;
	}
	return 0;
}

static int test_flock_blocking(struct io_uring *ring, int fd1, int fd2)
{
	struct io_uring_sqe *sqe;
	int ret;

	ret = do_flock(ring, fd1, LOCK_EX);
	if (ret) {
		fprintf(stderr, "flock EX: %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd2, LOCK_EX);
	if (submit_pending(ring, sqe, 2))
		return 1;

	/* unlock fd1, the pending request should now complete */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd1, LOCK_UN);
	sqe->user_data = 3;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = reap_match(ring, 2, 2);
	if (ret) {
		fprintf(stderr, "blocked flock granted: %d\n", ret);
		return 1;
	}
	ret = do_flock(ring, fd2, LOCK_UN);
	if (ret) {
		fprintf(stderr, "flock UN: %d\n", ret);
		return 1;
	}
	return 0;
}

static int test_flock_cancel(struct io_uring *ring, int fd1, int fd2)
{
	struct io_uring_sqe *sqe;
	int ret;

	ret = do_flock(ring, fd1, LOCK_EX);
	if (ret) {
		fprintf(stderr, "flock EX: %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd2, LOCK_EX);
	if (submit_pending(ring, sqe, 2))
		return 1;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel64(sqe, 2, 0);
	sqe->user_data = 3;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = reap_match(ring, 2, 2);
	if (ret != -ECANCELED) {
		fprintf(stderr, "cancelled flock: %d\n", ret);
		return 1;
	}
	/* fd2 must not hold the lock, fd1 still does */
	if (!flock(fd2, LOCK_EX | LOCK_NB) || errno != EWOULDBLOCK) {
		fprintf(stderr, "lock held post cancel\n");
		return 1;
	}
	/*
	 * Re-issue the blocked request. It will likely recycle the just
	 * cancelled request, verifying that no cancelation state leaks into
	 * a new request once it gets deferred and retried.
	 */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd2, LOCK_EX);
	if (submit_pending(ring, sqe, 4))
		return 1;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd1, LOCK_UN);
	sqe->user_data = 5;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = reap_match(ring, 2, 4);
	if (ret) {
		fprintf(stderr, "recycled flock granted: %d\n", ret);
		return 1;
	}
	ret = do_flock(ring, fd2, LOCK_UN);
	if (ret) {
		fprintf(stderr, "flock UN: %d\n", ret);
		return 1;
	}
	return 0;
}

static int test_ofd_basic(struct io_uring *ring, int fd1, int fd2)
{
	struct flock fl = {
		.l_type		= F_WRLCK,
		.l_whence	= SEEK_SET,
		.l_start	= 0,
		.l_len		= 10,
	};
	int ret;

	ret = do_ofd(ring, fd1, F_WRLCK, 0, 10, 0);
	if (ret) {
		fprintf(stderr, "ofd wr [0,10): %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd2, F_WRLCK, 0, 10, IORING_OFD_LOCK_NOWAIT);
	if (ret != -EAGAIN) {
		fprintf(stderr, "ofd wr overlap: %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd2, F_RDLCK, 5, 10, IORING_OFD_LOCK_NOWAIT);
	if (ret != -EAGAIN) {
		fprintf(stderr, "ofd rd overlap wr: %d\n", ret);
		return 1;
	}
	/* non-overlapping range works */
	ret = do_ofd(ring, fd2, F_WRLCK, 10, 10, IORING_OFD_LOCK_NOWAIT);
	if (ret) {
		fprintf(stderr, "ofd wr [10,20): %d\n", ret);
		return 1;
	}
	/* same lock space as fcntl(2) F_OFD_SETLK */
	if (!fcntl(fd2, F_OFD_SETLK, &fl) ||
	    (errno != EAGAIN && errno != EACCES)) {
		fprintf(stderr, "F_OFD_SETLK interop broken\n");
		return 1;
	}
	ret = do_ofd(ring, fd1, F_UNLCK, 0, 10, 0);
	if (ret) {
		fprintf(stderr, "ofd unlock: %d\n", ret);
		return 1;
	}
	/* read locks are shared */
	ret = do_ofd(ring, fd1, F_RDLCK, 0, 10, 0);
	if (ret) {
		fprintf(stderr, "ofd rd: %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd2, F_RDLCK, 5, 10, IORING_OFD_LOCK_NOWAIT);
	if (ret) {
		fprintf(stderr, "ofd rd shared: %d\n", ret);
		return 1;
	}
	if (do_ofd(ring, fd1, F_UNLCK, 0, 0, 0) ||
	    do_ofd(ring, fd2, F_UNLCK, 0, 0, 0)) {
		fprintf(stderr, "ofd unlock\n");
		return 1;
	}
	return 0;
}

static int test_ofd_same_owner(struct io_uring *ring, int fd1, int fd2)
{
	int fd3, ret;

	/*
	 * A dup'ed fd shares the open file description, and with it lock
	 * ownership - overlapping requests don't conflict, they merge.
	 */
	fd3 = dup(fd1);
	if (fd3 < 0) {
		perror("dup");
		return 1;
	}
	ret = do_ofd(ring, fd1, F_WRLCK, 0, 10, 0);
	if (ret) {
		fprintf(stderr, "ofd wr: %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd3, F_WRLCK, 5, 10, IORING_OFD_LOCK_NOWAIT);
	if (ret) {
		fprintf(stderr, "ofd wr same owner: %d\n", ret);
		return 1;
	}
	/* still held against the other file */
	ret = do_ofd(ring, fd2, F_WRLCK, 12, 1, IORING_OFD_LOCK_NOWAIT);
	if (ret != -EAGAIN) {
		fprintf(stderr, "ofd wr merged range: %d\n", ret);
		return 1;
	}
	close(fd3);
	ret = do_ofd(ring, fd1, F_UNLCK, 0, 0, 0);
	if (ret) {
		fprintf(stderr, "ofd unlock: %d\n", ret);
		return 1;
	}
	return 0;
}

static int test_ofd_cancel(struct io_uring *ring, int fd1, int fd2)
{
	struct io_uring_sqe *sqe;
	int ret;

	ret = do_ofd(ring, fd1, F_WRLCK, 0, 10, 0);
	if (ret) {
		fprintf(stderr, "ofd wr: %d\n", ret);
		return 1;
	}

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_ofd_lock(sqe, fd2, F_WRLCK, 0, 10, 0);
	if (submit_pending(ring, sqe, 2))
		return 1;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel64(sqe, 2, 0);
	sqe->user_data = 3;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = reap_match(ring, 2, 2);
	if (ret != -ECANCELED) {
		fprintf(stderr, "cancelled ofd lock: %d\n", ret);
		return 1;
	}
	/* re-issue the blocked request, see test_flock_cancel() */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_ofd_lock(sqe, fd2, F_WRLCK, 0, 10, 0);
	if (submit_pending(ring, sqe, 4))
		return 1;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_ofd_lock(sqe, fd1, F_UNLCK, 0, 0, 0);
	sqe->user_data = 5;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = reap_match(ring, 2, 4);
	if (ret) {
		fprintf(stderr, "recycled ofd lock granted: %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd2, F_UNLCK, 0, 0, 0);
	if (ret) {
		fprintf(stderr, "ofd unlock: %d\n", ret);
		return 1;
	}
	return 0;
}

/*
 * Exiting a ring with a lock request still parked on a blocker must
 * cancel it - it must neither hang the exit, nor acquire the lock.
 */
static int test_ring_exit(unsigned int ring_flags, int fd1, int fd2)
{
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, ring_flags);
	if (ret) {
		fprintf(stderr, "queue_init: %d\n", ret);
		return 1;
	}
	if (flock(fd1, LOCK_EX)) {
		perror("flock");
		return 1;
	}
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_flock(sqe, fd2, LOCK_EX);
	if (submit_pending(&ring, sqe, 2))
		return 1;

	io_uring_queue_exit(&ring);

	if (flock(fd1, LOCK_UN)) {
		perror("flock");
		return 1;
	}
	if (flock(fd2, LOCK_EX | LOCK_NB)) {
		fprintf(stderr, "lock held after ring exit\n");
		return 1;
	}
	if (flock(fd2, LOCK_UN)) {
		perror("flock");
		return 1;
	}
	return 0;
}

static int test_errors(struct io_uring *ring, int fd1, int fd_rd, int fd_wr)
{
	struct io_uring_sqe *sqe;
	int ret;

	/* invalid flock operations */
	ret = do_flock(ring, fd1, 0);
	if (ret != -EINVAL) {
		fprintf(stderr, "flock op 0: %d\n", ret);
		return 1;
	}
	ret = do_flock(ring, fd1, LOCK_SH | LOCK_EX);
	if (ret != -EINVAL) {
		fprintf(stderr, "flock op SH|EX: %d\n", ret);
		return 1;
	}
	/* stray sqe field */
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_flock(sqe, fd1, LOCK_EX);
	sqe->off = 1;
	ret = submit_wait_res(ring);
	if (ret != -EINVAL) {
		fprintf(stderr, "flock stray off: %d\n", ret);
		return 1;
	}
	/* bad fd */
	ret = do_flock(ring, -1, LOCK_EX);
	if (ret != -EBADF) {
		fprintf(stderr, "flock bad fd: %d\n", ret);
		return 1;
	}
	/* invalid lock type */
	ret = do_ofd(ring, fd1, 42, 0, 0, 0);
	if (ret != -EINVAL) {
		fprintf(stderr, "ofd bad type: %d\n", ret);
		return 1;
	}
	/* invalid lock_flags */
	ret = do_ofd(ring, fd1, F_RDLCK, 0, 0, ~IORING_OFD_LOCK_NOWAIT);
	if (ret != -EINVAL) {
		fprintf(stderr, "ofd bad flags: %d\n", ret);
		return 1;
	}
	/* bad ranges */
	ret = do_ofd(ring, fd1, F_WRLCK, 1ULL << 63, 1, 0);
	if (ret != -EINVAL) {
		fprintf(stderr, "ofd bad start: %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd1, F_WRLCK, LLONG_MAX, 2, 0);
	if (ret != -EOVERFLOW) {
		fprintf(stderr, "ofd range overflow: %d\n", ret);
		return 1;
	}
	/* lock type vs open mode */
	ret = do_ofd(ring, fd_rd, F_WRLCK, 0, 10, 0);
	if (ret != -EBADF) {
		fprintf(stderr, "ofd wr on read only: %d\n", ret);
		return 1;
	}
	ret = do_ofd(ring, fd_wr, F_RDLCK, 0, 10, 0);
	if (ret != -EBADF) {
		fprintf(stderr, "ofd rd on write only: %d\n", ret);
		return 1;
	}
	return 0;
}

static int test(unsigned int ring_flags, const char *path)
{
	int fd1, fd2, fd_rd, fd_wr, ret;
	struct io_uring ring;

	ret = io_uring_queue_init(8, &ring, ring_flags);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;
	else if (ret) {
		fprintf(stderr, "queue_init: %d\n", ret);
		return T_EXIT_FAIL;
	}

	fd1 = open(path, O_RDWR);
	fd2 = open(path, O_RDWR);
	fd_rd = open(path, O_RDONLY);
	fd_wr = open(path, O_WRONLY);
	if (fd1 < 0 || fd2 < 0 || fd_rd < 0 || fd_wr < 0) {
		perror("open");
		return T_EXIT_FAIL;
	}

	ret = test_flock_basic(&ring, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_flock_basic failed\n");
		return T_EXIT_FAIL;
	}
	if (no_filelock)
		return T_EXIT_SKIP;

	ret = test_flock_blocking(&ring, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_flock_blocking failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_flock_cancel(&ring, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_flock_cancel failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_ofd_basic(&ring, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_ofd_basic failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_ofd_same_owner(&ring, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_ofd_same_owner failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_ofd_cancel(&ring, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_ofd_cancel failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_errors(&ring, fd1, fd_rd, fd_wr);
	if (ret) {
		fprintf(stderr, "test_errors failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_ring_exit(ring_flags, fd1, fd2);
	if (ret) {
		fprintf(stderr, "test_ring_exit failed\n");
		return T_EXIT_FAIL;
	}

	close(fd1);
	close(fd2);
	close(fd_rd);
	close(fd_wr);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	const char *path = ".file-lock";
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	t_create_file(path, 4096);

	ret = test(0, path);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test 0 failed\n");
		goto err;
	}
	if (ret == T_EXIT_SKIP)
		goto skip;

	ret = test(IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
		   path);
	if (ret == T_EXIT_FAIL) {
		fprintf(stderr, "test DEFER_TASKRUN failed\n");
		goto err;
	}

	unlink(path);
	return T_EXIT_PASS;
skip:
	unlink(path);
	return T_EXIT_SKIP;
err:
	unlink(path);
	return T_EXIT_FAIL;
}
