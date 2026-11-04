/* SPDX-License-Identifier: MIT */
/*
 * Description: test that a pending multishot read on /dev/fuse completes
 *		with -ENODEV and without IORING_CQE_F_MORE after unmount.
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <linux/fuse.h>

#include "liburing.h"
#include "helpers.h"

#define BUF_SIZE	(64 * 1024)
#define NR_BUFS		8
#define BUF_BGID	1
#define UD_READ		1
#define WAIT_SEC	2

static char mnt[] = "/tmp/read-mshot-fuse.XXXXXX";

static int write_file(const char *path, const char *s)
{
	int fd, ret;
	ssize_t len = strlen(s);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ret = write(fd, s, len) == len ? 0 : -1;
	close(fd);
	return ret;
}

/* become root of a private mount namespace, like `unshare -Urm` */
static int enter_namespaces(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char map[64];

	if (getuid() == 0) {
		if (unshare(CLONE_NEWNS))
			return -1;
	} else {
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
			return -1;
		if (write_file("/proc/self/setgroups", "deny"))
			return -1;

		snprintf(map, sizeof(map), "0 %u 1", uid);
		if (write_file("/proc/self/uid_map", map))
			return -1;

		snprintf(map, sizeof(map), "0 %u 1", gid);
		if (write_file("/proc/self/gid_map", map))
			return -1;
	}

	return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
}

static int reply_init(int fd, const void *req, ssize_t len)
{
	struct fuse_in_header in;
	struct {
		struct fuse_out_header h;
		struct fuse_init_out init;
	} out = {};

	if (len < (ssize_t)sizeof(in)) {
		fprintf(stderr, "short FUSE_INIT request: %zd bytes\n", len);
		return -1;
	}

	memcpy(&in, req, sizeof(in));
	if (in.opcode != FUSE_INIT) {
		fprintf(stderr, "expected FUSE_INIT, got opcode %u\n",
			in.opcode);
		return -1;
	}

	out.h.len = sizeof(out);
	out.h.unique = in.unique;
	out.init.major = FUSE_KERNEL_VERSION;
	out.init.minor = FUSE_KERNEL_MINOR_VERSION;
	out.init.max_write = 4096;

	if (write(fd, &out, sizeof(out)) != (ssize_t)sizeof(out)) {
		fprintf(stderr, "write FUSE_INIT reply failed\n");
		return -1;
	}

	return 0;
}

static int init_sync(int fd)
{
	char buf[BUF_SIZE];
	ssize_t n;

	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		perror("read FUSE_INIT");
		return -1;
	}

	return reply_init(fd, buf, n);
}

/*
 * final == 0: before umount, expect no CQE within 100 ms.
 * final == 1: after umount, expect -ENODEV without F_MORE.
 */
static int wait_read(struct io_uring *ring, int *pending, int final)
{
	struct __kernel_timespec ts = {
		.tv_sec = final ? WAIT_SEC : 0,
		.tv_nsec = final ? 0 : 100 * 1000 * 1000,
	};
	struct io_uring_cqe *cqe;
	int ret, ok;

	ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
	if (!final && ret == -ETIME)
		return 0;

	if (ret) {
		fprintf(stderr, "wait %s umount: %d\n",
			final ? "after" : "before", ret);
		return -1;
	}

	printf("CQE %s umount: user_data=%llu res=%d flags=0x%x\n",
	       final ? "after" : "before", (unsigned long long)cqe->user_data,
	       cqe->res, cqe->flags);

	if (cqe->user_data == UD_READ && !(cqe->flags & IORING_CQE_F_MORE))
		*pending = 0;

	ok = final && cqe->user_data == UD_READ && cqe->res == -ENODEV &&
	     !(cqe->flags & IORING_CQE_F_MORE);

	io_uring_cqe_seen(ring, cqe);
	return ok ? 0 : -1;
}

static int cancel_read(struct io_uring *ring)
{
	struct io_uring_sync_cancel_reg reg = {
		.addr = UD_READ,
		.timeout = { .tv_sec = WAIT_SEC },
	};
	struct __kernel_timespec ts = { .tv_sec = WAIT_SEC };
	struct io_uring_cqe *cqe;
	int ret, ok;

	ret = io_uring_register_sync_cancel(ring, &reg);
	if (ret < 0 && ret != -ENOENT)
		return ret;

	/* -ENOENT can race with completion; require the terminal read CQE. */
	ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
	if (ret)
		return ret;

	ok = cqe->user_data == UD_READ && !(cqe->flags & IORING_CQE_F_MORE);
	io_uring_cqe_seen(ring, cqe);

	return ok ? 0 : -EINVAL;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_probe *probe;
	struct io_uring_buf_ring *br = NULL;
	struct io_uring_sqe *sqe;
	char *bufs = NULL;
	char opts[128];
	int fd = -1, mounted = 0, pending = 0;
	int ret = T_EXIT_FAIL, rc, i;

	(void)argv;
	if (argc > 1)
		return T_EXIT_SKIP;

	if (access("/dev/fuse", W_OK | R_OK))
		return T_EXIT_SKIP;

	if (enter_namespaces() < 0) {
		perror("enter namespaces");
		return T_EXIT_SKIP;
	}

	rc = io_uring_queue_init(8, &ring, 0);
	if (rc) {
		fprintf(stderr, "ring setup failed: %d\n", rc);
		return T_EXIT_FAIL;
	}

	probe = io_uring_get_probe_ring(&ring);
	if (!probe) {
		fprintf(stderr, "opcode probe failed\n");
		goto out_ring;
	}

	rc = io_uring_opcode_supported(probe, IORING_OP_READ_MULTISHOT);
	io_uring_free_probe(probe);
	if (!rc) {
		ret = T_EXIT_SKIP;
		goto out_ring;
	}

	if (!mkdtemp(mnt)) {
		perror("mkdtemp");
		goto out_ring;
	}

	fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/fuse");
		goto out;
	}

	snprintf(opts, sizeof(opts),
		 "fd=%d,rootmode=40000,user_id=0,group_id=0", fd);
	if (mount("read-mshot-fuse", mnt, "fuse", MS_NOSUID | MS_NODEV, opts) <
	    0) {
		if (errno == EPERM || errno == EACCES || errno == ENODEV)
			ret = T_EXIT_SKIP;
		perror("mount fuse");
		goto out;
	}
	mounted = 1;

	if (init_sync(fd))
		goto out;

	br = io_uring_setup_buf_ring(&ring, NR_BUFS, BUF_BGID, 0, &rc);
	if (!br) {
		fprintf(stderr, "buffer ring setup failed: %d\n", rc);
		goto out;
	}

	bufs = malloc(NR_BUFS * BUF_SIZE);
	if (!bufs) {
		perror("malloc");
		goto out;
	}
	for (i = 0; i < NR_BUFS; i++)
		io_uring_buf_ring_add(br, bufs + i * BUF_SIZE, BUF_SIZE, i,
				      NR_BUFS - 1, i);
	io_uring_buf_ring_advance(br, NR_BUFS);

	/* 1. Submit the read while the filesystem is still mounted. */
	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		goto out;

	io_uring_prep_read_multishot(sqe, fd, 0, 0, BUF_BGID);
	sqe->user_data = UD_READ;

	rc = io_uring_submit(&ring);
	if (rc != 1) {
		fprintf(stderr, "submit read failed: %d\n", rc);
		goto out;
	}
	pending = 1;

	/* 2. Reject any completion that arrives before unmount. */
	if (wait_read(&ring, &pending, 0))
		goto out;

	/* 3. Disconnect the filesystem, keeping fd and ring alive. */
	if (umount2(mnt, MNT_DETACH) < 0) {
		perror("umount fuse");
		goto out;
	}
	mounted = 0;

	/* 4. Require a terminal -ENODEV CQE within WAIT_SEC. */
	if (wait_read(&ring, &pending, 1))
		goto out;

	ret = T_EXIT_PASS;

out:
	if (pending) {
		rc = cancel_read(&ring);
		if (rc) {
			fprintf(stderr, "cancel read failed: %d\n", rc);
			ret = T_EXIT_FAIL;
		} else {
			pending = 0;
		}
	}

	/* If cancellation failed, retain buffers until process exit. */
	if (!pending) {
		if (br)
			io_uring_free_buf_ring(&ring, br, NR_BUFS, BUF_BGID);
		free(bufs);
	}

	if (mounted && umount2(mnt, MNT_DETACH)) {
		perror("cleanup umount");
		ret = T_EXIT_FAIL;
	}
	if (fd >= 0)
		close(fd);
	if (rmdir(mnt)) {
		perror("rmdir");
		ret = T_EXIT_FAIL;
	}

out_ring:
	io_uring_queue_exit(&ring);
	return ret;
}
