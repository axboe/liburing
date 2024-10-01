/* SPDX-License-Identifier: MIT */
/*
 * Proof-of-concept for doing file digests using the kernel's AF_ALG API.
 * Needs a bit of error handling.
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

enum req_state {
	IO_INIT = 0,
	IO_READ,
	IO_READ_COMPLETE,
	IO_WRITE,
	IO_WRITE_COMPLETE,
};

struct req {
	off_t offset;
	enum req_state state;
	struct iovec iov;
};

struct kdigest {
	struct io_uring ring;
	struct req reqs[QD];
	/* heap allocated, aligned QD*BS buffer */
	uint8_t *bufs;
};

static int infd, outfd;

static int get_file_size(int fd, size_t *size)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -1;
	if (S_ISREG(st.st_mode)) {
		*size = st.st_size;
	} else if (S_ISBLK(st.st_mode)) {
		unsigned long long bytes;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
			return -1;

		*size = bytes;
	} else {
		return -1;
	}

	return 0;
}

static int digest_file(struct kdigest *kdigest, size_t insize)
{
	struct io_uring *ring = &kdigest->ring;
	off_t read_off = 0;
	size_t outsize = insize;
	int read_idx = 0, write_idx = 0, inflight = 0;

	while (outsize) {
		int to_wait;
		struct req *req;
		struct io_uring_sqe *sqe;
		int had_inflight = inflight;

		/* Queue up any possible writes. Link flag ensures ordering. */
		sqe = NULL;
		while (kdigest->reqs[write_idx].state == IO_READ_COMPLETE) {
			if (sqe)
				sqe->flags |= IOSQE_IO_LINK;

			req = &kdigest->reqs[write_idx];
			req->state = IO_WRITE;
			sqe = io_uring_get_sqe(ring);
			io_uring_prep_send(sqe, outfd, req->iov.iov_base,
					   req->iov.iov_len, MSG_MORE);
			io_uring_sqe_set_data(sqe, req);
			inflight++;

			write_idx = (write_idx + 1) % QD;
		}

		/* Queue up any reads. Completions may arrive out of order. */
		while (insize && (kdigest->reqs[read_idx].state == IO_INIT
		    || kdigest->reqs[read_idx].state == IO_WRITE_COMPLETE)) {
			size_t this_size = (insize < BS ? insize : BS);

			req = &kdigest->reqs[read_idx];
			req->state = IO_READ;
			req->offset = read_off;
			req->iov.iov_base = &kdigest->bufs[read_idx * BS];
			req->iov.iov_len = this_size;

			sqe = io_uring_get_sqe(ring);
			io_uring_prep_readv(sqe, infd, &req->iov, 1, read_off);
			io_uring_sqe_set_data(sqe, req);

			read_off += this_size;
			insize -= this_size;
			inflight++;

			read_idx = (read_idx + 1) % QD;
		}

		if (had_inflight != inflight) {
			assert(inflight > had_inflight);
			if (io_uring_submit(ring) < 0)
				return 1;
		}

		/* wait for about half queue completion before resubmit */
		for (to_wait = (inflight >> 1) | 1; to_wait; to_wait--) {
			struct io_uring_cqe *cqe;
			int ret;

			ret = io_uring_wait_cqe(ring, &cqe);
			if (ret < 0) {
				fprintf(stderr, "wait cqe: %s\n",
					strerror(-ret));
				return 1;
			}

			req = io_uring_cqe_get_data(cqe);
			assert(req->state == IO_READ || req->state == IO_WRITE);
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);
			if (ret < 0) {
				if (ret == -ECANCELED && req->state == IO_READ) {
					fprintf(stderr, "canceled read@%lld\n",
						(long long)req->offset);
					sqe = io_uring_get_sqe(ring);
					io_uring_prep_readv(sqe, infd,
						&req->iov, 1, req->offset);
					io_uring_sqe_set_data(sqe, req);
					if (io_uring_submit(ring) < 0)
						return 1;
					continue;
				} else {
					fprintf(stderr, "cqe error: %s\n",
						strerror(-ret));
					return 1;
				}
			}

			inflight--;
			req->state++;

			if (req->state == IO_WRITE_COMPLETE)
				outsize -= req->iov.iov_len;
		}
	}
	assert(!inflight);

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
	const char *alg;
	const char *infile;
	size_t alg_len;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};
	int sfd = -1;
	size_t insize;
	int ret;
	struct kdigest kdigest = {};

	if (argc < 3) {
		fprintf(stderr, "%s: algorithm infile\n", argv[0]);
		return 1;
	}

	alg = argv[1];
	infile = argv[2];
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

	if (posix_memalign((void **)&kdigest.bufs, 4096, QD * BS)) {
		fprintf(stderr, "failed to alloc I/O bufs\n");
		return 1;
	}

	ret = io_uring_queue_init(QD, &kdigest.ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return 1;
	}

	if (get_file_size(infd, &insize))
		return 1;

	ret = digest_file(&kdigest, insize);
	if (ret) {
		fprintf(stderr, "%s digest failed\n", alg);
		return 1;
	}

	ret = get_result(&kdigest.ring, alg, infile);
	if (ret) {
		fprintf(stderr, "failed to retrieve %s digest result\n", alg);
		return 1;
	}

	io_uring_queue_exit(&kdigest.ring);
	free(kdigest.bufs);
	if (close(infd) < 0)
		ret |= 1;
	if (close(sfd) < 0)
		ret |= 1;
	if (close(outfd) < 0)
		ret |= 1;
	return ret;
}
