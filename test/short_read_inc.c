/* SPDX-License-Identifier: MIT */
/*
 * Description: Test incremental buffer rings (IOU_PBUF_RING_INC) with short
 *		reads on non-pollable files and pipes.
 *
 *		When an operation requests an explicit length (e.g. 16 bytes)
 *		on a non-pollable file where actual data read is shorter (e.g. 12 bytes),
 *		io_ring_buffer_select() commits upfront based on the requested
 *		length rather than the actual read length, causing misaligned
 *		offsets in subsequent incremental reads.
 *
 *		Reference: https://github.com/axboe/liburing/issues/1555
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "liburing.h"
#include "helpers.h"

#define BUF_BGID	42
#define BUF_SIZE	64
#define REQ_SIZE	16
#define FILE_DATA	"Hello World\n"
#define FILE_DATA_LEN	12

static int no_buf_ring_inc;

/*
 * Test short reads on a pipe (pollable fd). Exercises the locked
 * completion-time commit path where io_should_commit() returns false upfront.
 */
static int test_pipe_short_read(void)
{
	struct io_uring_buf_ring *br;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	int ret, fds[2];
	char *buf;

	ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	if (pipe(fds) < 0) {
		perror("pipe");
		return 1;
	}

	if (posix_memalign((void **) &buf, 4096, BUF_SIZE)) {
		close(fds[0]);
		close(fds[1]);
		io_uring_queue_exit(&ring);
		return 1;
	}

	br = io_uring_setup_buf_ring(&ring, 2, BUF_BGID, IOU_PBUF_RING_INC, &ret);
	if (!br) {
		if (ret == -EINVAL) {
			no_buf_ring_inc = 1;
			free(buf);
			close(fds[0]);
			close(fds[1]);
			io_uring_queue_exit(&ring);
			return 0;
		}
		fprintf(stderr, "buffer ring register failed: %d\n", ret);
		free(buf);
		close(fds[0]);
		close(fds[1]);
		io_uring_queue_exit(&ring);
		return 1;
	}

	memset(buf, 0, BUF_SIZE);
	io_uring_buf_ring_add(br, buf, BUF_SIZE, 0, 1, 0);
	io_uring_buf_ring_advance(br, 1);

	/* Write first 12 bytes and read with requested length 16 */
	if (write(fds[1], FILE_DATA, FILE_DATA_LEN) != FILE_DATA_LEN) {
		perror("pipe write 1");
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, fds[0], NULL, REQ_SIZE, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BUF_BGID;

	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0 || cqe->res != FILE_DATA_LEN) {
		fprintf(stderr, "cqe 1 read failed: %d\n", cqe ? cqe->res : ret);
		return 1;
	}
	io_uring_cqe_seen(&ring, cqe);

	/* Write second 12 bytes and read with requested length 16 */
	if (write(fds[1], FILE_DATA, FILE_DATA_LEN) != FILE_DATA_LEN) {
		perror("pipe write 2");
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, fds[0], NULL, REQ_SIZE, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BUF_BGID;

	ret = io_uring_submit(&ring);
	if (ret != 1) {
		fprintf(stderr, "submit 2: %d\n", ret);
		return 1;
	}

	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0 || cqe->res != FILE_DATA_LEN) {
		fprintf(stderr, "cqe 2 read failed: %d\n", cqe ? cqe->res : ret);
		return 1;
	}
	io_uring_cqe_seen(&ring, cqe);

	/*
	 * In pollable pipes, the kernel commits actual read length (12 bytes),
	 * so second read must be placed contiguously at offset 12.
	 */
	if (memcmp(buf, FILE_DATA, FILE_DATA_LEN) != 0) {
		fprintf(stderr, "pipe chunk 1 mismatch\n");
		return 1;
	}
	if (memcmp(buf + FILE_DATA_LEN, FILE_DATA, FILE_DATA_LEN) != 0) {
		fprintf(stderr, "pipe chunk 2 not contiguous at offset %d\n", FILE_DATA_LEN);
		return 1;
	}

	io_uring_free_buf_ring(&ring, br, 2, BUF_BGID);
	io_uring_queue_exit(&ring);
	free(buf);
	close(fds[0]);
	close(fds[1]);
	return 0;
}

/*
 * Test short reads on a regular file (non-pollable fd).
 * Replicates Issue #1555 where upfront commit on requested length (16)
 * creates a gap when actual file length is 12 bytes.
 */
static int test_file_short_read(void)
{
	struct io_uring_buf_ring *br;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	char fname[64];
	int ret, fd, i;
	char *buf;

	sprintf(fname, ".short-read-inc.%d", getpid());
	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open write");
		return 1;
	}
	if (write(fd, FILE_DATA, FILE_DATA_LEN) != FILE_DATA_LEN) {
		perror("file write");
		unlink(fname);
		return 1;
	}
	close(fd);

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		perror("open read");
		unlink(fname);
		return 1;
	}

	ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		close(fd);
		unlink(fname);
		return 1;
	}

	if (posix_memalign((void **) &buf, 4096, BUF_SIZE)) {
		close(fd);
		unlink(fname);
		io_uring_queue_exit(&ring);
		return 1;
	}

	br = io_uring_setup_buf_ring(&ring, 2, BUF_BGID, IOU_PBUF_RING_INC, &ret);
	if (!br) {
		if (ret == -EINVAL) {
			no_buf_ring_inc = 1;
			free(buf);
			close(fd);
			io_uring_queue_exit(&ring);
			unlink(fname);
			return 0;
		}
		fprintf(stderr, "buffer ring register failed: %d\n", ret);
		free(buf);
		close(fd);
		io_uring_queue_exit(&ring);
		unlink(fname);
		return 1;
	}

	memset(buf, 0, BUF_SIZE);
	io_uring_buf_ring_add(br, buf, BUF_SIZE, 0, 1, 0);
	io_uring_buf_ring_advance(br, 1);

	/* Submit two reads from offset 0 with requested length 16 */
	for (i = 0; i < 2; i++) {
		sqe = io_uring_get_sqe(&ring);
		io_uring_prep_read(sqe, fd, NULL, REQ_SIZE, 0);
		sqe->flags |= IOSQE_BUFFER_SELECT;
		sqe->buf_group = BUF_BGID;
	}

	ret = io_uring_submit(&ring);
	if (ret != 2) {
		fprintf(stderr, "submit 2 reads failed: %d\n", ret);
		goto err;
	}

	for (i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0 || cqe->res != FILE_DATA_LEN) {
			fprintf(stderr, "file read cqe %d failed: %d\n", i, cqe ? cqe->res : ret);
			goto err;
		}
		if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
			fprintf(stderr, "no buffer flag set\n");
			goto err;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	/*
	 * Diagnosis of Issue #1555:
	 * First chunk is at offset 0 (12 bytes).
	 * If the kernel committed requested length 16 upfront:
	 * bytes 12..15 are 0, and chunk 2 is at offset 16.
	 * If the kernel correctly committed actual read length 12:
	 * chunk 2 is at offset 12.
	 */
	if (memcmp(buf, FILE_DATA, FILE_DATA_LEN) != 0) {
		fprintf(stderr, "file chunk 1 mismatch\n");
		goto err;
	}

	if (memcmp(buf + FILE_DATA_LEN, FILE_DATA, FILE_DATA_LEN) != 0) {
		if (memcmp(buf + REQ_SIZE, FILE_DATA, FILE_DATA_LEN) == 0) {
			fprintf(stderr, "Issue #1555 reproduced: chunk 2 offset shifted to %d (requested length) instead of %d (actual read length)\n",
				REQ_SIZE, FILE_DATA_LEN);
			/*
			 * Return failure to alert that upfront commit on non-pollable
			 * file causes buffer misalignment.
			 */
			goto err;
		}
		fprintf(stderr, "file chunk 2 corrupted\n");
		goto err;
	}

	io_uring_free_buf_ring(&ring, br, 2, BUF_BGID);
	io_uring_queue_exit(&ring);
	free(buf);
	close(fd);
	unlink(fname);
	return 0;

err:
	io_uring_free_buf_ring(&ring, br, 2, BUF_BGID);
	io_uring_queue_exit(&ring);
	free(buf);
	close(fd);
	unlink(fname);
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test_pipe_short_read();
	if (ret) {
		fprintf(stderr, "test_pipe_short_read failed\n");
		return T_EXIT_FAIL;
	}
	if (no_buf_ring_inc)
		return T_EXIT_SKIP;

	ret = test_file_short_read();
	if (ret) {
		fprintf(stderr, "test_file_short_read failed\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}
