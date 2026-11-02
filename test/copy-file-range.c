/* SPDX-License-Identifier: MIT */
/*
 * Description: test IORING_OP_COPY_FILE_RANGE
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#include "liburing.h"
#include "helpers.h"

#define BS		4096
#define GIG		(1024ULL * 1024 * 1024)

static const char src_path[] = ".cfr-src.XXXXXX";
static const char dst_path[] = ".cfr-dst.XXXXXX";

static int make_file(const char *tmpl, int flags)
{
	char path[64];
	int fd;

	strcpy(path, tmpl);
	fd = mkostemp(path, flags);
	if (fd < 0) {
		perror("mkostemp");
		exit(T_EXIT_FAIL);
	}
	unlink(path);
	return fd;
}

static void fill(int fd, off_t off, size_t len, unsigned char seed)
{
	size_t chunk = len < (1U << 20) ? len : (1U << 20);
	unsigned char *buf = t_malloc(chunk);
	size_t i, done;

	for (done = 0; done < len; done += chunk) {
		size_t n = len - done < chunk ? len - done : chunk;

		for (i = 0; i < n; i++)
			buf[i] = (unsigned char) (seed + (done + i) * 7);
		if (pwrite(fd, buf, n, off + done) != (ssize_t) n) {
			if (errno == ENOSPC || errno == EFBIG) {
				fprintf(stdout, "no space for test data, skipping\n");
				exit(T_EXIT_SKIP);
			}
			perror("pwrite");
			exit(T_EXIT_FAIL);
		}
	}
	free(buf);
}

static int same(int fa, off_t oa, int fb, off_t ob, size_t len)
{
	unsigned char *a = t_malloc(len), *b = t_malloc(len);
	int ret;

	if (pread(fa, a, len, oa) != (ssize_t) len ||
	    pread(fb, b, len, ob) != (ssize_t) len) {
		perror("pread");
		exit(T_EXIT_FAIL);
	}
	ret = !memcmp(a, b, len);
	free(a);
	free(b);
	return ret;
}

static int submit_one(struct io_uring *ring, int fd_in, int64_t off_in,
		      int fd_out, int64_t off_out, unsigned int len,
		      unsigned int flags, unsigned sqe_flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, fd_in, off_in, fd_out, off_out, len,
				      flags);
	sqe->flags |= sqe_flags;
	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		exit(T_EXIT_FAIL);
	}
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait: %d\n", ret);
		exit(T_EXIT_FAIL);
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

#define CHECK(cond, ...) do {						\
	if (!(cond)) {							\
		fprintf(stderr, "%s:%d: ", __func__, __LINE__);		\
		fprintf(stderr, __VA_ARGS__);				\
		fputc('\n', stderr);					\
		return T_EXIT_FAIL;					\
	}								\
} while (0)

static int test_basic(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int ret;

	fill(in, 0, 1024 * 1024, 1);
	ret = submit_one(ring, in, BS, out, 0, 64 * 1024, 0, 0);
	CHECK(ret == 64 * 1024, "res %d", ret);
	CHECK(same(in, BS, out, 0, 64 * 1024), "content mismatch");
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_fpos(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int ret;

	fill(in, 0, 8192, 2);
	lseek(in, 100, SEEK_SET);
	lseek(out, 10, SEEK_SET);
	ret = submit_one(ring, in, -1, out, -1, 1000, 0, 0);
	CHECK(ret == 1000, "res %d", ret);
	CHECK(lseek(in, 0, SEEK_CUR) == 1100, "in pos %ld",
	      (long) lseek(in, 0, SEEK_CUR));
	CHECK(lseek(out, 0, SEEK_CUR) == 1010, "out pos %ld",
	      (long) lseek(out, 0, SEEK_CUR));
	CHECK(same(in, 100, out, 10, 1000), "content mismatch");

	ret = submit_one(ring, in, 0, out, 5000, 100, 0, 0);
	CHECK(ret == 100, "res %d", ret);
	CHECK(lseek(in, 0, SEEK_CUR) == 1100, "explicit off moved in pos");
	CHECK(lseek(out, 0, SEEK_CUR) == 1010, "explicit off moved out pos");
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_eof(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int ret;

	fill(in, 0, BS, 3);
	ret = submit_one(ring, in, BS, out, 0, 100, 0, 0);
	CHECK(ret == 0, "at EOF res %d", ret);
	ret = submit_one(ring, in, BS + 10, out, 0, 100, 0, 0);
	CHECK(ret == 0, "past EOF res %d", ret);
	ret = submit_one(ring, in, 4000, out, 0, 1000, 0, 0);
	CHECK(ret == 96, "crossing EOF res %d", ret);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_zero_len(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int i, ret;

	fill(in, 0, BS, 4);
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 0, out, 0, 0, 0);
	sqe->flags |= IOSQE_IO_LINK;
	sqe->user_data = 1;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_fsync(sqe, out, 0);
	sqe->user_data = 2;
	CHECK(io_uring_submit(ring) == 2, "submit");
	for (i = 0; i < 2; i++) {
		CHECK(!io_uring_wait_cqe(ring, &cqe), "wait");
		ret = cqe->res;
		CHECK(ret == 0, "ud %llu res %d",
		      (unsigned long long) cqe->user_data, ret);
		io_uring_cqe_seen(ring, cqe);
	}
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_errors(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	char apath[] = ".cfr-app.XXXXXX", wpath[] = ".cfr-wo.XXXXXX";
	char procp[64];
	int app, wo, ret;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;

	fill(in, 0, 64 * 1024, 5);

	ret = submit_one(ring, in, 0, in, 100, 1000, 0, 0);
	CHECK(ret == -EINVAL, "overlap res %d", ret);

	app = make_file(apath, O_WRONLY | O_APPEND);
	ret = submit_one(ring, in, 0, app, 0, 1000, 0, 0);
	CHECK(ret == -EBADF, "O_APPEND out res %d", ret);
	close(app);

	app = make_file(wpath, O_RDWR);
	fill(app, 0, BS, 5);
	snprintf(procp, sizeof(procp), "/proc/self/fd/%d", app);
	wo = open(procp, O_WRONLY);
	close(app);
	CHECK(wo >= 0, "reopen O_WRONLY");
	ret = submit_one(ring, wo, 0, out, 0, 1000, 0, 0);
	CHECK(ret == -EBADF, "O_WRONLY in res %d", ret);
	close(wo);

	ret = submit_one(ring, in, 0, out, 0, 1000, SPLICE_F_MOVE, 0);
	CHECK(ret == -EINVAL, "splice flag res %d", ret);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 0, out, 0, 1000, 0);
	sqe->addr3 = 1;
	CHECK(io_uring_submit(ring) == 1, "submit");
	CHECK(!io_uring_wait_cqe(ring, &cqe), "wait");
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	CHECK(ret == -EINVAL, "addr3 res %d", ret);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 0, out, 0, 1000, 0);
	sqe->buf_index = 1;
	CHECK(io_uring_submit(ring) == 1, "submit");
	CHECK(!io_uring_wait_cqe(ring, &cqe), "wait");
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	CHECK(ret == -EINVAL, "buf_index res %d", ret);

	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int sys_copy(int in, loff_t off_in, int out, loff_t off_out, size_t len)
{
	ssize_t ret = copy_file_range(in, &off_in, out, &off_out, len, 0);

	return ret < 0 ? -errno : (int) ret;
}

static int test_bad_offset(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int ret;

	fill(in, 0, BS, 6);
	ret = submit_one(ring, in, -2, out, 0, 100, 0, 0);
	CHECK(ret < 0 && ret == sys_copy(in, -2, out, 0, 100),
	      "off_in -2 res %d", ret);
	ret = submit_one(ring, in, 0, out, -2, 100, 0, 0);
	CHECK(ret < 0 && ret == sys_copy(in, 0, out, -2, 100),
	      "off_out -2 res %d", ret);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_zero_len_errors(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	char apath[] = ".cfr-zapp.XXXXXX";
	int p[2], app, ret;

	fill(in, 0, BS, 16);
	if (pipe(p)) {
		perror("pipe");
		return T_EXIT_FAIL;
	}
	ret = submit_one(ring, p[0], -1, out, 0, 0, 0, 0);
	CHECK(ret < 0 && ret == sys_copy(p[0], -1, out, 0, 0),
	      "zero len pipe in res %d", ret);
	close(p[0]);
	close(p[1]);

	app = make_file(apath, O_WRONLY | O_APPEND);
	ret = submit_one(ring, in, 0, app, 0, 0, 0, 0);
	CHECK(ret < 0 && ret == sys_copy(in, 0, app, 0, 0),
	      "zero len O_APPEND out res %d", ret);
	close(app);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_nonreg_in(struct io_uring *ring)
{
	int out = make_file(dst_path, O_RDWR);
	int p[2], dir, ret;

	if (pipe(p)) {
		perror("pipe");
		return T_EXIT_FAIL;
	}
	CHECK(write(p[1], "x", 1) == 1, "pipe write");
	ret = submit_one(ring, p[0], -1, out, 0, 1, 0, 0);
	CHECK(ret == -EINVAL, "pipe in res %d", ret);
	close(p[0]);
	close(p[1]);

	dir = open(".", O_RDONLY | O_DIRECTORY);
	CHECK(dir >= 0, "open dir");
	ret = submit_one(ring, dir, 0, out, 0, 1, 0, 0);
	CHECK(ret == -EISDIR, "dir in res %d", ret);
	close(dir);
	close(out);
	return T_EXIT_PASS;
}

static int test_same_file_disjoint(struct io_uring *ring)
{
	int fd = make_file(src_path, O_RDWR);
	int ret;

	fill(fd, 0, 2 * BS, 7);
	ret = submit_one(ring, fd, 0, fd, 2 * BS, BS, 0, 0);
	CHECK(ret == BS, "res %d", ret);
	CHECK(same(fd, 0, fd, 2 * BS, BS), "content mismatch");
	close(fd);
	return T_EXIT_PASS;
}

static int test_exdev(struct io_uring *ring)
{
	char opath[] = "/dev/shm/.cfr-xdev.XXXXXX";
	struct stat a, b;
	int in, out, ret;

	if (stat(".", &a) || stat("/dev/shm", &b) || a.st_dev == b.st_dev)
		return T_EXIT_SKIP;
	in = make_file(src_path, O_RDWR);
	out = mkostemp(opath, O_RDWR);
	if (out < 0)
		return T_EXIT_SKIP;
	unlink(opath);
	fill(in, 0, BS, 8);
	ret = submit_one(ring, in, 0, out, 0, BS, 0, 0);
	/* NFS/CIFS may legitimately succeed via their own ->copy_file_range */
	CHECK(ret == -EXDEV || ret == BS, "cross-fs res %d", ret);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_fixed(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int fds[2] = { in, out };
	int ret;

	fill(in, 0, 64 * 1024, 9);
	ret = io_uring_register_files(ring, fds, 2);
	CHECK(!ret, "register files %d", ret);

	ret = submit_one(ring, 0, 0, 1, 0, 8192, SPLICE_F_FD_IN_FIXED,
			 IOSQE_FIXED_FILE);
	CHECK(ret == 8192, "both fixed res %d", ret);
	CHECK(same(in, 0, out, 0, 8192), "content mismatch");

	ret = submit_one(ring, 0, 8192, out, 8192, 4096, SPLICE_F_FD_IN_FIXED, 0);
	CHECK(ret == 4096, "fixed in res %d", ret);

	ret = submit_one(ring, in, 12288, 1, 12288, 4096, 0, IOSQE_FIXED_FILE);
	CHECK(ret == 4096, "fixed out res %d", ret);

	io_uring_unregister_files(ring);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_fixed_bad_index(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int fds[1] = { in };
	int ret;

	ret = submit_one(ring, 0, 0, out, 0, 100, SPLICE_F_FD_IN_FIXED, 0);
	CHECK(ret == -EBADF, "no table res %d", ret);

	CHECK(!io_uring_register_files(ring, fds, 1), "register");
	ret = submit_one(ring, 5, 0, out, 0, 100, SPLICE_F_FD_IN_FIXED, 0);
	CHECK(ret == -EBADF, "out of range res %d", ret);
	io_uring_unregister_files(ring);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_large(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	int ret;

	if (ftruncate(in, 8 * GIG)) {
		perror("ftruncate");
		return T_EXIT_SKIP;
	}
	fill(in, 5 * GIG, 64 * 1024, 10);
	ret = submit_one(ring, in, 5 * GIG, out, 6 * GIG, 64 * 1024, 0, 0);
	CHECK(ret == 64 * 1024, "res %d", ret);
	CHECK(same(in, 5 * GIG, out, 6 * GIG, 64 * 1024), "content mismatch");
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int reflink_supported(void)
{
	char a[] = ".cfr-rla.XXXXXX", b[] = ".cfr-rlb.XXXXXX";
	int fa = make_file(a, O_RDWR), fb = make_file(b, O_RDWR);
	int ok;

	fill(fa, 0, BS, 11);
	fsync(fa);
	ok = !ioctl(fb, FICLONE, fa);
	close(fa);
	close(fb);
	return ok;
}

static int has_shared_extent(int fd)
{
	struct fiemap *fm;
	unsigned int i;
	int shared = 0;

	fm = t_calloc(1, sizeof(*fm) + 32 * sizeof(struct fiemap_extent));
	fm->fm_length = ~0ULL;
	fm->fm_flags = FIEMAP_FLAG_SYNC;
	fm->fm_extent_count = 32;
	if (ioctl(fd, FS_IOC_FIEMAP, fm) == 0) {
		for (i = 0; i < fm->fm_mapped_extents; i++)
			if (fm->fm_extents[i].fe_flags & FIEMAP_EXTENT_SHARED)
				shared = 1;
	} else {
		shared = -1;
	}
	free(fm);
	return shared;
}

static int test_reflink(struct io_uring *ring)
{
	int in, out, ret;
	long page = sysconf(_SC_PAGESIZE);
	unsigned int max_rw = INT_MAX & ~(page - 1);

	if (!reflink_supported())
		return T_EXIT_SKIP;

	in = make_file(src_path, O_RDWR);
	out = make_file(dst_path, O_RDWR);
	fill(in, 0, 1024 * 1024, 12);
	fsync(in);
	ret = submit_one(ring, in, 0, out, 0, 1024 * 1024, 0, 0);
	CHECK(ret == 1024 * 1024, "res %d", ret);
	ret = has_shared_extent(out);
	close(in);
	close(out);
	if (ret < 0)
		return T_EXIT_SKIP;
	CHECK(ret == 1, "destination has no shared extent");

	in = make_file(src_path, O_RDWR);
	out = make_file(dst_path, O_RDWR);
	CHECK(!ftruncate(in, 4 * GIG), "ftruncate");
	ret = submit_one(ring, in, 0, out, 0, 0xffffffffU, 0, 0);
	CHECK(ret == (int) max_rw, "clamp res %d want %u", ret, max_rw);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_link(struct io_uring *ring, unsigned int copy_len,
		     unsigned link_flag, int want_copy, int want_fsync)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int i;

	fill(in, 0, BS, 13);
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 0, out, 0, copy_len, 0);
	sqe->flags |= link_flag;
	sqe->user_data = 1;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_fsync(sqe, out, 0);
	sqe->user_data = 2;
	CHECK(io_uring_submit(ring) == 2, "submit");
	for (i = 0; i < 2; i++) {
		CHECK(!io_uring_wait_cqe(ring, &cqe), "wait");
		if (cqe->user_data == 1)
			CHECK(cqe->res == want_copy, "copy res %d want %d",
			      cqe->res, want_copy);
		else
			CHECK(cqe->res == want_fsync, "fsync res %d want %d",
			      cqe->res, want_fsync);
		io_uring_cqe_seen(ring, cqe);
	}
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_cancel_queued(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int i, copy2 = 1, cancel = 1;

	fill(in, 0, 512 * 1024 * 1024, 14);
	fsync(in);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 1, out, 0, 511 * 1024 * 1024, 0);
	sqe->user_data = 1;
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 0, out, 0, BS, 0);
	sqe->user_data = 2;
	CHECK(io_uring_submit(ring) == 2, "submit");

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel64(sqe, 2, 0);
	sqe->user_data = 3;
	CHECK(io_uring_submit(ring) == 1, "submit cancel");

	for (i = 0; i < 3; i++) {
		CHECK(!io_uring_wait_cqe(ring, &cqe), "wait");
		if (cqe->user_data == 2)
			copy2 = cqe->res;
		else if (cqe->user_data == 3)
			cancel = cqe->res;
		io_uring_cqe_seen(ring, cqe);
	}
	CHECK(copy2 == -ECANCELED, "queued copy res %d (cancel res %d)",
	      copy2, cancel);
	CHECK(cancel == 0, "cancel res %d", cancel);
	close(in);
	close(out);
	return T_EXIT_PASS;
}

static int test_cancel_inflight(struct io_uring *ring)
{
	int in = make_file(src_path, O_RDWR), out = make_file(dst_path, O_RDWR);
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int i, copy = 1, cancel = 1;
	unsigned int len = 1024U * 1024 * 1024;

	fill(in, 0, len, 15);
	fsync(in);
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_copy_file_range(sqe, in, 1, out, 0, len - 1, 0);
	sqe->user_data = 1;
	CHECK(io_uring_submit(ring) == 1, "submit");
	for (i = 0; i < 200; i++) {
		struct stat st;

		if (!fstat(out, &st) && st.st_size > 0)
			break;
		usleep(1000);
	}
	sqe = io_uring_get_sqe(ring);
	io_uring_prep_cancel64(sqe, 1, 0);
	sqe->user_data = 2;
	CHECK(io_uring_submit(ring) == 1, "submit cancel");
	for (i = 0; i < 2; i++) {
		CHECK(!io_uring_wait_cqe(ring, &cqe), "wait");
		if (cqe->user_data == 1)
			copy = cqe->res;
		else
			cancel = cqe->res;
		io_uring_cqe_seen(ring, cqe);
	}
	close(in);
	close(out);
	/* not started yet: cancelled from the queue */
	if (copy == -ECANCELED && cancel == 0)
		return T_EXIT_PASS;
	/* finished before the cancel arrived: nothing to interrupt here */
	if (copy == (int) (len - 1) && cancel == -ENOENT)
		return T_EXIT_SKIP;
	/*
	 * The running copy is signalled and stops early with a short count,
	 * or -EINTR if the filesystem can't report partial progress.
	 * Depending on how fast it unwinds, ASYNC_CANCEL reports either
	 * -EALREADY or, if it already completed, -ENOENT.
	 */
	CHECK(cancel == -EALREADY || cancel == -ENOENT, "cancel res %d", cancel);
	CHECK((copy >= 0 && copy < (int) (len - 1)) || copy == -EINTR,
	      "inflight copy res %d", copy);
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring_probe *probe;
	struct io_uring ring;
	int ret, i;
	struct {
		const char *name;
		int (*fn)(struct io_uring *);
	} tests[] = {
		{ "basic", test_basic },
		{ "fpos", test_fpos },
		{ "eof", test_eof },
		{ "zero_len", test_zero_len },
		{ "zero_len_errors", test_zero_len_errors },
		{ "errors", test_errors },
		{ "bad_offset", test_bad_offset },
		{ "nonreg_in", test_nonreg_in },
		{ "same_file_disjoint", test_same_file_disjoint },
		{ "exdev", test_exdev },
		{ "fixed", test_fixed },
		{ "fixed_bad_index", test_fixed_bad_index },
		{ "large", test_large },
		{ "reflink", test_reflink },
		{ "cancel_queued", test_cancel_queued },
		{ "cancel_inflight", test_cancel_inflight },
	};

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return T_EXIT_FAIL;
	}
	probe = io_uring_get_probe_ring(&ring);
	if (!probe || !io_uring_opcode_supported(probe,
						 IORING_OP_COPY_FILE_RANGE)) {
		fprintf(stdout, "copy_file_range not supported, skipping\n");
		return T_EXIT_SKIP;
	}
	io_uring_free_probe(probe);

	for (i = 0; i < (int) (sizeof(tests) / sizeof(tests[0])); i++) {
		ret = tests[i].fn(&ring);
		if (ret == T_EXIT_FAIL) {
			fprintf(stderr, "test_%s failed\n", tests[i].name);
			return T_EXIT_FAIL;
		}
		if (ret == T_EXIT_SKIP)
			fprintf(stdout, "test_%s: not supported here, skipped\n",
				tests[i].name);
	}

	ret = test_link(&ring, BS, IOSQE_IO_LINK, BS, 0);
	if (ret == T_EXIT_FAIL)
		return ret;
	ret = test_link(&ring, 2 * BS, IOSQE_IO_LINK, BS, -ECANCELED);
	if (ret == T_EXIT_FAIL)
		return ret;
	ret = test_link(&ring, 2 * BS, IOSQE_IO_HARDLINK, BS, 0);
	if (ret == T_EXIT_FAIL)
		return ret;

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
}
