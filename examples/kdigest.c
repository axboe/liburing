/* SPDX-License-Identifier: MIT */
/*
 * link-cp based proof-of-concept for doing file digests with linked SQEs using
 * the kernel's AF_ALG API. Needs a bit of error handling and short read love.
 */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/if_alg.h>
#include "liburing.h"

#define QD	64
#define BS	(32*1024)

struct io_data {
	size_t offset;
	int index;
	struct iovec iov;
};

static int infd, outfd;
static unsigned inflight;

static int setup_context(unsigned entries, struct io_uring *ring)
{
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}

	return 0;
}

static int get_file_size(int fd, off_t *size)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -1;
	if (S_ISREG(st.st_mode)) {
		*size = st.st_size;
		return 0;
	} else if (S_ISBLK(st.st_mode)) {
		unsigned long long bytes;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;

		*size = bytes;
		return 0;
	}

	return -1;
}

static void queue_rw_pair(struct io_uring *ring, off_t size, off_t offset)
{
	struct io_uring_sqe *sqe;
	struct io_data *data;
	void *ptr;

	ptr = malloc(size + sizeof(*data));
	assert(ptr);
	data = ptr + size;
	data->index = 0;
	data->offset = offset;
	data->iov.iov_base = ptr;
	data->iov.iov_len = size;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_readv(sqe, infd, &data->iov, 1, offset);
	sqe->flags |= IOSQE_IO_LINK;
	io_uring_sqe_set_data(sqe, data);

	sqe = io_uring_get_sqe(ring);
	/*
	 * data must be sent to the hasher in file order. IOSQE_IO_DRAIN is
	 * needed here to avoid concurrent / out of order send I/Os.
	 */
	sqe->flags |= IOSQE_IO_DRAIN;
	io_uring_prep_send(sqe, outfd, ptr, size, MSG_MORE);
	io_uring_sqe_set_data(sqe, data);
}

static int handle_cqe(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct io_data *data = io_uring_cqe_get_data(cqe);
	int ret = 0;

	data->index++;

	if (cqe->res < 0) {
		if (cqe->res == -ECANCELED) {
			queue_rw_pair(ring, BS, data->offset);
			inflight += 2;
		} else {
			fprintf(stderr, "cqe error: %s\n",
				strerror(-cqe->res));
			ret = 1;
		}
	}

	if (data->index == 2) {
		void *ptr = (void *) data - data->iov.iov_len;

		free(ptr);
	}
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int digest_file(struct io_uring *ring, off_t insize)
{
	struct io_uring_cqe *cqe;
	size_t this_size;
	off_t offset;

	offset = 0;
	while (insize) {
		int has_inflight = inflight;
		int depth;

		while (insize && inflight < QD) {
			this_size = BS;
			if (this_size > insize)
				this_size = insize;
			queue_rw_pair(ring, this_size, offset);
			offset += this_size;
			insize -= this_size;
			inflight += 2;
		}

		if (has_inflight != inflight) {
			if (io_uring_submit(ring) < 0)
				return 1;
		}

		if (insize)
			depth = QD;
		else
			depth = 1;
		while (inflight >= depth) {
			int ret;

			ret = io_uring_wait_cqe(ring, &cqe);
			if (ret < 0) {
				fprintf(stderr, "wait cqe: %s\n",
					strerror(-ret));
				return 1;
			}
			if (handle_cqe(ring, cqe))
				return 1;
			inflight--;
		}
	}

	return 0;
}

static int get_result(struct io_uring *ring, const char *alg, const char *file)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int i, ret;
	/* buffer must be large enough to carry longest hash result */
	uint8_t buf[4096];

	sqe = io_uring_get_sqe(ring);
	memset(buf, 0, sizeof(buf));
	io_uring_prep_read(sqe, outfd, buf, sizeof(buf), 0);
	if (io_uring_submit(ring) < 0)
		return 1;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait cqe: %s\n", strerror(-ret));
		return 1;
	}

	if (cqe->res < 0 || cqe->res > sizeof(buf)) {
		fprintf(stderr, "cqe error: %s\n", strerror(-cqe->res));
		ret = 1;
	} else {
		fprintf(stdout, "uring %s(%s) returned(len=%u): ",
			alg, file, cqe->res);
		for (i = 0; i < cqe->res; i++)
			fprintf(stdout, "%02x", buf[i]);
		putc('\n', stdout);
		ret = 0;
	}

	io_uring_cqe_seen(ring, cqe);
	return ret;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	const char *alg = argv[1];
	const char *infile = argv[2];
	size_t alg_len;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};
	int sfd = -1;
	off_t insize;
	int ret;

	if (argc < 3) {
		fprintf(stderr, "%s: algorithm infile\n", argv[0]);
		return 1;
	}

	alg_len = strlen(alg);
	if (alg_len >= sizeof(sa.salg_name)) {
		fprintf(stderr, "algorithm name too long\n");
		return 1;
	}
	/* +1 for null terminator */
	memcpy(sa.salg_name, alg, alg_len + 1);

	infd = open(infile, O_RDONLY);
	if (infd < 0) {
		perror("open infile");
		return 1;
	}

	sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (sfd < 0) {
		if (errno == EAFNOSUPPORT)
			fprintf(stderr, "kernel AF_ALG support not available. "
				"CONFIG_CRYPTO_USER_API_HASH required.\n");
		else
			perror("AF_ALG socket");
		return 1;
	}

	if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		if (errno == ENOENT)
			fprintf(stderr, "AF_ALG bind(%s): hash not available. "
				"See /proc/crypto hash algorithm list.\n",
				alg);
		else
			fprintf(stderr, "AF_ALG bind(%s): %s\n",
				alg, strerror(errno));
		return 1;
	}

	outfd = accept(sfd, NULL, 0);
	if (outfd < 0) {
		perror("AF_ALG accept");
		return 1;
	}

	if (setup_context(QD, &ring))
		return 1;
	if (get_file_size(infd, &insize))
		return 1;

	ret = digest_file(&ring, insize);
	if (ret) {
		fprintf(stderr, "%s digest failed\n", alg);
		return 1;
	}

	ret = get_result(&ring, alg, infile);
	if (ret) {
		fprintf(stderr, "failed to retrieve %s digest result\n", alg);
		return 1;
	}

	if (close(infd) < 0)
		ret |= 1;
	if (close(sfd) < 0)
		ret |= 1;
	if (close(outfd) < 0)
		ret |= 1;
	io_uring_queue_exit(&ring);
	return ret;
}
