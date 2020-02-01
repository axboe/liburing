/*
 * Description: basic read/write tests with buffered, O_DIRECT, and SQPOLL
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/eventfd.h>
#include "liburing.h"

#define FILE_SIZE	(128 * 1024)
#define BS		4096
#define BUFFERS		(FILE_SIZE / BS)

static struct iovec *vecs;
static int no_read;

static int create_buffers(void)
{
	int i;

	vecs = malloc(BUFFERS * sizeof(struct iovec));
	for (i = 0; i < BUFFERS; i++) {
		if (posix_memalign(&vecs[i].iov_base, BS, BS))
			return 1;
		vecs[i].iov_len = BS;
	}

	return 0;
}

static int create_file(const char *file)
{
	ssize_t ret;
	char *buf;
	int fd;

	buf = malloc(FILE_SIZE);
	memset(buf, 0xaa, FILE_SIZE);

	fd = open(file, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open file");
		return 1;
	}
	ret = write(fd, buf, FILE_SIZE);
	close(fd);
	return ret != FILE_SIZE;
}

static int test_io(const char *file, int write, int buffered, int sqthread,
		   int fixed, int mixed_fixed, int nonvec)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int open_flags, ring_flags;
	int i, fd, ret;
	static int warned;

#ifdef VERBOSE
	fprintf(stdout, "%s: start %d/%d/%d/%d/%d/%d: ", __FUNCTION__, write,
							buffered, sqthread,
							fixed, mixed_fixed,
							nonvec);
#endif
	if (sqthread && geteuid()) {
#ifdef VERBOSE
		fprintf(stdout, "SKIPPED (not root)\n");
#endif
		return 0;
	}

	if (write)
		open_flags = O_WRONLY;
	else
		open_flags = O_RDONLY;
	if (!buffered)
		open_flags |= O_DIRECT;

	fd = open(file, open_flags);
	if (fd < 0) {
		perror("file open");
		goto err;
	}

	if (sqthread)
		ring_flags = IORING_SETUP_SQPOLL;
	else
		ring_flags = 0;
	ret = io_uring_queue_init(64, &ring, ring_flags);
	if (ret) {
		fprintf(stderr, "ring create failed: %d\n", ret);
		goto err;
	}

	if (fixed) {
		ret = io_uring_register_buffers(&ring, vecs, BUFFERS);
		if (ret) {
			fprintf(stderr, "buffer reg failed: %d\n", ret);
			goto err;
		}
	}
	if (sqthread) {
		ret = io_uring_register_files(&ring, &fd, 1);
		if (ret) {
			fprintf(stderr, "file reg failed: %d\n", ret);
			goto err;
		}
	}

	for (i = 0; i < BUFFERS; i++) {
		off_t offset;

		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "sqe get failed\n");
			goto err;
		}
		offset = BS * (rand() % BUFFERS);
		if (write) {
			int do_fixed = fixed;
			int use_fd = fd;

			if (sqthread)
				use_fd = 0;
			if (fixed && (i & 1))
				do_fixed = 0;
			if (do_fixed) {
				io_uring_prep_write_fixed(sqe, use_fd, vecs[i].iov_base,
								vecs[i].iov_len,
								offset, i);
			} else if (nonvec) {
				io_uring_prep_write(sqe, use_fd, vecs[i].iov_base,
							vecs[i].iov_len, offset);
			} else {
				io_uring_prep_writev(sqe, use_fd, &vecs[i], 1,
								offset);
			}
		} else {
			int do_fixed = fixed;
			int use_fd = fd;

			if (sqthread)
				use_fd = 0;
			if (fixed && (i & 1))
				do_fixed = 0;
			if (do_fixed) {
				io_uring_prep_read_fixed(sqe, use_fd, vecs[i].iov_base,
								vecs[i].iov_len,
								offset, i);
			} else if (nonvec) {
				io_uring_prep_read(sqe, use_fd, vecs[i].iov_base,
							vecs[i].iov_len, offset);
			} else {
				io_uring_prep_readv(sqe, use_fd, &vecs[i], 1,
								offset);
			}

		}
		if (sqthread)
			sqe->flags |= IOSQE_FIXED_FILE;
	}

	ret = io_uring_submit(&ring);
	if (ret != BUFFERS) {
		fprintf(stderr, "submit got %d, wanted %d\n", ret, BUFFERS);
		goto err;
	}

	for (i = 0; i < BUFFERS; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait_cqe=%d\n", ret);
			goto err;
		}
		if (cqe->res == -EINVAL && nonvec) {
			if (!warned) {
				fprintf(stdout, "Non-vectored IO not "
					"supported, skipping\n");
				warned = 1;
				no_read = 1;
			}
		} else if (cqe->res != BS) {
			fprintf(stderr, "cqe res %d, wanted %d\n", cqe->res, BS);
			goto err;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	if (fixed) {
		ret = io_uring_unregister_buffers(&ring);
		if (ret) {
			fprintf(stderr, "buffer unreg failed: %d\n", ret);
			goto err;
		}
	}
	if (sqthread) {
		ret = io_uring_unregister_files(&ring);
		if (ret) {
			fprintf(stderr, "file unreg failed: %d\n", ret);
			goto err;
		}
	}

	io_uring_queue_exit(&ring);
	close(fd);
#ifdef VERBOSE
	fprintf(stdout, "PASS\n");
#endif
	return 0;
err:
#ifdef VERBOSE
	fprintf(stderr, "FAILED\n");
#endif
	if (fd != -1)
		close(fd);
	return 1;
}

static int read_poll_link(const char *file)
{
	struct __kernel_timespec ts;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int i, fd, ret, fds[2];

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret)
		return ret;

	fd = open(file, O_WRONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (pipe(fds)) {
		perror("pipe");
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_writev(sqe, fd, &vecs[0], 1, 0);
	sqe->flags |= IOSQE_IO_LINK;
	sqe->user_data = 1;

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_poll_add(sqe, fds[0], POLLIN);
	sqe->flags |= IOSQE_IO_LINK;
	sqe->user_data = 2;

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_link_timeout(sqe, &ts, 0);
	sqe->user_data = 3;

	ret = io_uring_submit(&ring);
	if (ret != 3) {
		fprintf(stderr, "submitted %d\n", ret);
		return 1;
	}

	for (i = 0; i < 3; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait_cqe=%d\n", ret);
			return 1;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	return 0;
}

static int has_nonvec_read(void)
{
	struct io_uring_probe *p;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(1, &ring, 0);
	if (ret) {
		fprintf(stderr, "queue init: %d\n", ret);
		exit(ret);
	}

	p = calloc(1, sizeof(*p) + 256 * sizeof(struct io_uring_probe_op));
	ret = io_uring_register_probe(&ring, p, 256);
	/* if we don't have PROBE_REGISTER, we don't have OP_READ/WRITE */
	if (ret == -EINVAL) {
out:
		io_uring_queue_exit(&ring);
		return 0;
	} else if (ret) {
		fprintf(stderr, "register_probe: %d\n", ret);
		goto out;
	}

	if (p->ops_len <= IORING_OP_READ)
		goto out;
	if (!(p->ops[IORING_OP_READ].flags & IO_URING_OP_SUPPORTED))
		goto out;
	io_uring_queue_exit(&ring);
	return 1;
}

static int test_eventfd_read(void)
{
	struct io_uring ring;
	int fd, ret;
	eventfd_t event;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;

	if (no_read)
		return 0;
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret)
		return ret;

	fd = eventfd(1, 0);
	if (fd < 0) {
		perror("eventfd");
		return 1;
	}
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, fd, &event, sizeof(eventfd_t), 0);
	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submitted %d\n", ret);
		return 1;
	}
	eventfd_write(fd, 1);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait_cqe=%d\n", ret);
		return 1;
	}
	if (cqe->res != sizeof(eventfd_t)) {
		fprintf(stderr, "cqe res %d, wanted %ld\n", cqe->res, sizeof(eventfd_t));
		return 1;
	}
	io_uring_cqe_seen(&ring, cqe);
	return 0;
}

int main(int argc, char *argv[])
{
	int i, ret, nr;

	if (create_file(".basic-rw")) {
		fprintf(stderr, "file creation failed\n");
		goto err;
	}
	if (create_buffers()) {
		fprintf(stderr, "file creation failed\n");
		goto err;
	}

	/* if we don't have nonvec read, skip testing that */
	if (has_nonvec_read())
		nr = 64;
	else
		nr = 32;

	for (i = 0; i < nr; i++) {
		int v1, v2, v3, v4, v5, v6;

		v1 = (i & 1) != 0;
		v2 = (i & 2) != 0;
		v3 = (i & 4) != 0;
		v4 = (i & 8) != 0;
		v5 = (i & 16) != 0;
		v6 = (i & 32) != 0;
		ret = test_io(".basic-rw", v1, v2, v3, v4, v5, v6);
		if (ret) {
			fprintf(stderr, "test_io failed %d/%d/%d/%d/%d/%d\n",
					v1, v2, v3, v4, v5, v6);
			goto err;
		}
	}

	ret = test_eventfd_read();
	if (ret) {
		fprintf(stderr, "test_eventfd_read failed\n");
		goto err;
	}

	ret = read_poll_link(".basic-rw");
	if (ret) {
		fprintf(stderr, "read_poll_link failed\n");
		goto err;
	}

	unlink(".basic-rw");
	return 0;
err:
	unlink(".basic-rw");
	return 1;
}
