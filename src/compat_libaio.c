/*
 * Simple wrapper for libaio support
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "liburing/compat.h"
#include "liburing/io_uring.h"
#include "liburing.h"

struct iocb_data {
	void *data;
	struct iocb *iocb;
	struct iovec vec;
	struct iocb_data *next;
};

struct io_context {
	struct io_uring ring;
	struct iocb_data *data;
	struct iocb_data *free_list;
};

#include "compat_libaio.h"

static int iocb_to_sqe(io_context_t ctx, struct io_uring_sqe *sqe,
		       struct iocb *iocb)
{
	unsigned fsync_flags = 0;
	struct iocb_data *data;
	int is_write = 1;

	data = ctx->free_list;
	ctx->free_list = data->next;

	switch (iocb->aio_lio_opcode) {
	case IO_CMD_PREAD:
		is_write = 0;
	case IO_CMD_PWRITE: {
		struct iovec *vec = &data->vec;

		vec->iov_base = iocb->u.c.buf;
		vec->iov_len = iocb->u.c.nbytes;
		if (is_write)
			io_uring_prep_writev(sqe, iocb->aio_fildes, vec, 1,
						iocb->u.c.offset);
		else
			io_uring_prep_readv(sqe, iocb->aio_fildes, vec, 1,
						iocb->u.c.offset);
		sqe->ioprio = iocb->aio_reqprio;
		sqe->rw_flags = iocb->aio_rw_flags;
		break;
		}
	case IO_CMD_FDSYNC:
		fsync_flags = IORING_FSYNC_DATASYNC;
	case IO_CMD_FSYNC:
		io_uring_prep_fsync(sqe, iocb->aio_fildes, fsync_flags);
		break;
	case IO_CMD_POLL:
		io_uring_prep_poll_add(sqe, iocb->aio_fildes,
					iocb->u.poll.events);
		break;
	case IO_CMD_NOOP:
		/* Don't turn this into an io_uring nop, as aio errors them */
		return -EINVAL;
	case IO_CMD_PREADV:
		is_write = 0;
	case IO_CMD_PWRITEV:
		if (is_write)
			io_uring_prep_writev(sqe, iocb->aio_fildes,
						iocb->u.v.vec, iocb->u.v.nr,
						iocb->u.v.offset);
		else
			io_uring_prep_readv(sqe, iocb->aio_fildes,
						iocb->u.v.vec, iocb->u.v.nr,
						iocb->u.v.offset);
		sqe->ioprio = iocb->aio_reqprio;
		sqe->rw_flags = iocb->aio_rw_flags;
		break;
	default:
		fprintf(stderr, "aio: unknown op %d\n", iocb->aio_lio_opcode);
		return -EINVAL;
	}

	data->data = iocb->data;
	data->iocb = iocb;
	io_uring_sqe_set_data(sqe, data);
	return 0;
}

int io_submit(io_context_t ctx, long nr, struct iocb *iocbs[])
{
	struct io_uring *ring = &ctx->ring;
	struct io_uring_sqe *sqe;
	int i, ret;

	if (!nr)
		return 0;

	ret = 0;
	for (i = 0; i < nr; i++) {
		sqe = io_uring_get_sqe(ring);
		ret = iocb_to_sqe(ctx, sqe, iocbs[i]);
		if (ret) {
			/* should probably be a helper */
			ring->sq.sqe_tail--;
			break;
		}
	}

	if (i)
		return io_uring_submit(ring);

	return ret;
}

static int __io_getevents(io_context_t ctx, long min_nr, long nr,
			  struct io_event *events, struct __kernel_timespec *ts,
			  sigset_t *sigmask)
{
	struct io_uring *ring = &ctx->ring;
	struct io_uring_cqe *cqe;
	int ret, total = 0;

	if (!nr)
		return 0;
	if (min_nr > nr)
		min_nr = nr;

	ret = 0;
	while (nr) {
		struct io_event *ev = &events[total];
		struct iocb_data *data;

		if (!min_nr) {
			ret = io_uring_peek_cqe(ring, &cqe);
			if (ret)
				break;
		} else {
			ret = io_uring_wait_cqes(ring, &cqe, min_nr, ts, sigmask);
			if (ret)
				break;
		}

		data = io_uring_cqe_get_data(cqe);
		ev->data = data->data;
		ev->obj = data->iocb;
		ev->res = cqe->res;
		ev->res2 = 0;
		io_uring_cqe_seen(ring, cqe);
		data->next = ctx->free_list;
		ctx->free_list = data;
		total++;
		nr--;
		if (min_nr)
			min_nr--;
	};

	return total ? total : ret;
}

int io_getevents(io_context_t ctx, long min_nr, long nr,
		 struct io_event *events, struct timespec *ts)
{
	struct __kernel_timespec kts, *ktsptr = NULL;

	if (ts) {
		kts.tv_sec = ts->tv_sec;
		kts.tv_nsec = ts->tv_nsec;
		ktsptr = &kts;
	}
	return __io_getevents(ctx, min_nr, nr, events, ktsptr, NULL);
}

int io_pgetevents(io_context_t ctx, long min_nr, long nr,
		  struct io_event *events, struct timespec *ts,
		  sigset_t *sigmask)
{
	struct __kernel_timespec kts, *ktsptr = NULL;

	if (ts) {
		kts.tv_sec = ts->tv_sec;
		kts.tv_nsec = ts->tv_nsec;
		ktsptr = &kts;
	}

	return __io_getevents(ctx, min_nr, nr, events, ktsptr, sigmask);
}

/*
 * We should implement this for POLL requests at least, those are the only
 * requests where it makes sense since nothing else is supported for libaio.
 * We could make this better and make it work in general, since io_uring
 * does support cancel.
 */
int io_cancel(io_context_t ctx, struct iocb *iocb, struct io_event *evt)
{
	return -EINVAL;
}

static int roundup_pow2(int val)
{
	int r;

	if (!val)
		return 0;

	r = 32;
	if (!(val & 0xffff0000u)) {
		val <<= 16;
		r -= 16;
	}
	if (!(val & 0xff000000u)) {
		val <<= 8;
		r -= 8;
	}
	if (!(val & 0xf0000000u)) {
		val <<= 4;
		r -= 4;
	}
	if (!(val & 0xc0000000u)) {
		val <<= 2;
		r -= 2;
	}
	if (!(val & 0x80000000u))
		r -= 1;

	return 1U << (r - 1);
}

int io_queue_init(int maxevents, io_context_t *ctxptr)
{
	io_context_t ctx;
	struct io_uring *ring;
	int i, ret;

	maxevents = roundup_pow2(maxevents);

	ctx = calloc(1, sizeof(*ctx));
	ring = &ctx->ring;
	ret = io_uring_queue_init(maxevents, ring, 0);
	if (ret) {
		free(ctx);
		*ctxptr = NULL;
		return ret;
	}

	ctx->data = malloc(maxevents * sizeof(struct iocb_data));
	for (i = 0; i < maxevents; i++) {
		struct iocb_data *data = &ctx->data[i];

		data->next = ctx->free_list;
		ctx->free_list = data;
	}
	*ctxptr = ctx;
	return 0;
}

int io_setup(unsigned maxevents, io_context_t *ctxp)
{
	return io_queue_init(maxevents, ctxp);
}

int io_destroy(io_context_t ctx)
{
	struct io_uring *ring = &ctx->ring;

	io_uring_queue_exit(ring);
	free(ctx->data);
	free(ctx);
	return 0;
}
