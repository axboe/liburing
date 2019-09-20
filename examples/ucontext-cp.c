/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o ucontext-cp ucontext-cp.c -luring
 */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <ucontext.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "liburing.h"

#define QD	64
#define BS	(32*1024)

typedef struct {
	struct io_uring ring;
	unsigned char stack_buf[SIGSTKSZ];
	ucontext_t ctx_main, ctx_fnew;
} async_context;

typedef struct {
	async_context *pctx;
	int ret;
	int infd;
	int outfd;
} arguments_bundle;

#define DEFINE_AWAIT_OP(operation) \
static ssize_t await_##operation( \
	async_context *pctx, \
	int fd, \
	const struct iovec *ioves, \
	unsigned int nr_vecs, \
	off_t offset) \
{ \
	struct io_uring_sqe *sqe = io_uring_get_sqe(&pctx->ring); \
\
	if (!sqe) { \
		return -1; \
	} \
\
	io_uring_prep_##operation(sqe, fd, ioves, nr_vecs, offset); \
	io_uring_sqe_set_data(sqe, pctx); \
	io_uring_submit(&pctx->ring); \
	swapcontext(&pctx->ctx_fnew, &pctx->ctx_main); \
	struct io_uring_cqe *cqe; \
	if (io_uring_peek_cqe(&pctx->ring, &cqe) < 0) { \
		return -1; \
	} \
	io_uring_cqe_seen(&pctx->ring, cqe); \
\
	return cqe->res; \
}

DEFINE_AWAIT_OP(readv)
DEFINE_AWAIT_OP(writev)
#undef DEFINE_AWAIT_OP

static int setup_context(unsigned entries, async_context *pctx)
{
	int ret;

	ret = io_uring_queue_init(entries, &pctx->ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}

	ret = getcontext(&pctx->ctx_fnew);
	if (ret < 0) {
		perror("getcontext");
		return -1;
	}
	pctx->ctx_fnew.uc_stack.ss_sp = &pctx->stack_buf;
	pctx->ctx_fnew.uc_stack.ss_size = sizeof(pctx->stack_buf);
	pctx->ctx_fnew.uc_link = &pctx->ctx_main;

	return 0;
}

static int copy_file(async_context *pctx, int infd, int outfd, struct iovec* piov)
{
	off_t offset = 0;

	for (;;) {
		ssize_t bytes_read;

		if ((bytes_read = await_readv(pctx, infd, piov, 1, offset)) < 0) {
			perror("await_readv");
			return 1;
		}
		if (bytes_read == 0) return 0;
		piov->iov_len = bytes_read;

		if (await_writev(pctx, outfd, piov, 1, offset) != bytes_read) {
			perror("await_writev");
			return 1;
		}
		if (bytes_read < BS) return 0;
		offset += bytes_read;
	}
}

static void copy_file_wrapper(arguments_bundle *pbundle) {
	struct iovec iov = {
		.iov_base = malloc(BS),
		.iov_len = BS,
	};
	async_context *pctx = pbundle->pctx;

	pbundle->ret = copy_file(pctx, pbundle->infd, pbundle->outfd, &iov);

	free(iov.iov_base);
	swapcontext(&pctx->ctx_fnew, &pctx->ctx_main);
}

int main(int argc, char *argv[])
{
	async_context ctx;
	int infd, outfd;
	struct io_uring_cqe *cqe;

	if (argc < 3) {
		printf("%s: infile outfile\n", argv[0]);
		return 1;
	}

	infd = open(argv[1], O_RDONLY);
	if (infd < 0) {
		perror("open infile");
		return 1;
	}
	outfd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (outfd < 0) {
		perror("open outfile");
		return 1;
	}

	if (setup_context(QD, &ctx))
		return 1;

	arguments_bundle bundle = {
		.pctx = &ctx,
		.ret = -1,
		.infd = infd,
		.outfd = outfd,
	};

	makecontext(&ctx.ctx_fnew, (void (*)(void)) copy_file_wrapper, 1, &bundle);

	if (swapcontext(&ctx.ctx_main, &ctx.ctx_fnew)) {
		perror("swapcontext");
		return 1;
	}

	// event loop
	while (bundle.ret == -1) {
		int ret;
		async_context* pctx;

		// usually be timed waiting
		ret = io_uring_wait_cqe(&ctx.ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait_cqe: %s\n", strerror(-ret));
			return 1;
		}

		pctx = io_uring_cqe_get_data(cqe);
		assert(pctx == &ctx);

		if (swapcontext(&pctx->ctx_main, &pctx->ctx_fnew)) {
			perror("swapcontext");
			return 1;
		}
	}

	close(outfd);
	close(infd);
	io_uring_queue_exit(&ctx.ring);

	return 0;
}
