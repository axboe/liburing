/*
 * Simple wrapper for libaio support
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <sys/eventfd.h>

#include "liburing/compat.h"
#include "liburing/io_uring.h"
#include "liburing.h"

#include "compat_libaio.h"

struct aio_ring {
	unsigned id;		 /** kernel internal index number */
	unsigned nr;		 /** number of io_events */
	unsigned head;
	unsigned tail;

	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length;	/** size of aio_ring */

	struct io_event events[0];
};

#define AIO_RING_MAGIC	0xa10a10a1

#define PAGE_SIZE	4096

struct io_context {
	union {
		struct {
			struct io_uring ring;
			pthread_mutex_t submit_lock;
			pthread_mutex_t complete_lock;
			pthread_t event_thread;
			int eventfd;
			int do_exit;
			unsigned aioring_tail;
			uint64_t event_val;
		};
		char pad[PAGE_SIZE];
	};

	struct aio_ring aio_ring;
};

static struct io_context *t_to_ctx(io_context_t __ctx)
{
	return (void *) __ctx - offsetof(struct io_context, aio_ring);
}

struct io_completion {
	struct iocb *iocb;
	void *data;
	int eventfd;
	size_t ret;
};

static int handle_event(struct io_context *ctx)
{
	struct io_uring_cqe *cqe;
	struct io_event *ev;
	struct io_completion *ic;
	int ret;

	assert((*ctx->ring.cq.koverflow) == 0);

	pthread_mutex_lock(&ctx->complete_lock);
	ret = io_uring_peek_cqe(&ctx->ring, &cqe);
	if (ret) {
		pthread_mutex_unlock(&ctx->complete_lock);
		return 0;
	}

	ev = &ctx->aio_ring.events[ctx->aioring_tail];
	ic = io_uring_cqe_get_data(cqe);
	if (ic->ret != cqe->res)
		fprintf(stderr, "res=%ld, ret=%d\n", (long) ic->ret, cqe->res);
	assert(ic->ret == cqe->res);
	ev->obj = ic->iocb;
	ev->data = ic->data;
	ev->res = cqe->res;
	ev->res2 = 0;
	io_uring_cqe_seen(&ctx->ring, cqe);

	asm volatile("mfence" ::: "memory");
	ctx->aioring_tail = (ctx->aioring_tail + 1) & (*ctx->ring.cq.kring_mask);
	ctx->aio_ring.tail = ctx->aioring_tail;

	if (ic->eventfd != -1) {
		uint64_t val = ++ctx->event_val;
		ret = write(ic->eventfd, &val, sizeof(val));
		if (ret != sizeof(val))
			fprintf(stderr, "eventfd write bad\n");
	} else
		fprintf(stderr, "no event signalling\n");
	free(ic);
	pthread_mutex_unlock(&ctx->complete_lock);
	return 1;
}

static void *event_thread(void *data)
{
	struct io_context *ctx = data;
	uint64_t val;
	int ret;

	while (!ctx->do_exit) {
		ret = read(ctx->eventfd, &val, sizeof(val));
		if (ret < 0) {
			fprintf(stderr, "event thread exits %d\n", errno);
			break;
		}
		while (handle_event(ctx))
			;
	}

	return NULL;
}

static int start_event_thread(struct io_context *ctx)
{
	int ret;

	if (ctx->eventfd != -1)
		return 0;

	ret = eventfd(0, EFD_CLOEXEC);
	if (ret < 0) {
		fprintf(stderr, "libaio: eventfd failed\n");
		return 1;
	}

	ctx->eventfd = ret;
	ret = io_uring_register_eventfd(&ctx->ring, ctx->eventfd);
	if (ret) {
		fprintf(stderr, "libaio: eventfd reg failed\n");
		close(ctx->eventfd);
		ctx->eventfd = -1;
		return 1;
	}
	pthread_create(&ctx->event_thread, NULL, event_thread, ctx);
	return 0;
}

static int iocb_to_sqe(struct io_context *ctx, struct io_uring_sqe *sqe,
		       struct iocb *iocb, struct iovec *vec)
{
	struct io_completion *ic;
	unsigned fsync_flags = 0;
	int i, is_write = 1;
	size_t ret = 0;

	if (iocb->u.c.flags & (1 << 0))
		start_event_thread(ctx);

	switch (iocb->aio_lio_opcode) {
	case IO_CMD_PREAD:
		is_write = 0;
	case IO_CMD_PWRITE: {
		vec->iov_base = iocb->u.c.buf;
		vec->iov_len = iocb->u.c.nbytes;
		ret = vec->iov_len;
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
		for (i = 0; i < iocb->u.v.nr; i++)
			ret += iocb->u.v.vec[i].iov_len;
		sqe->ioprio = iocb->aio_reqprio;
		sqe->rw_flags = iocb->aio_rw_flags;
		break;
	default:
		fprintf(stderr, "aio: unknown op %d\n", iocb->aio_lio_opcode);
		return -EINVAL;
	}

	ic = malloc(sizeof(*ic));
	ic->iocb = iocb;
	ic->data = iocb->data;
	if (iocb->u.c.flags & (1 << 0))
		ic->eventfd = iocb->u.c.resfd;
	else
		ic->eventfd = -1;
	ic->ret = ret;
	io_uring_sqe_set_data(sqe, ic);
	return 0;
}

int io_submit(io_context_t __ctx, long nr, struct iocb *iocbs[])
{
	struct io_context *ctx = t_to_ctx(__ctx);
	struct io_uring *ring = &ctx->ring;
	struct io_uring_sqe *sqe;
	struct iovec vecs[128];
	int i, ret;

	if (!nr)
		return 0;
	assert(nr <= 128);

	pthread_mutex_lock(&ctx->submit_lock);
	ret = 0;
	for (i = 0; i < nr; i++) {
		sqe = io_uring_get_sqe(ring);
		ret = iocb_to_sqe(ctx, sqe, iocbs[i], &vecs[i]);
		if (ret) {
			/* should probably be a helper */
			ring->sq.sqe_tail--;
			break;
		}
	}

	if (i)
		ret = io_uring_submit(ring);

	pthread_mutex_unlock(&ctx->submit_lock);
	return ret;
}

static int __io_getevents(struct io_context *ctx, long min_nr, long nr,
			  struct io_event *events, struct __kernel_timespec *ts,
			  sigset_t *sigmask)
{
	struct io_uring *ring = &ctx->ring;
	struct io_uring_cqe *cqe;
	int ret, total = 0;
	struct io_completion *ic;

	if (!nr)
		return 0;
	if (min_nr > nr)
		min_nr = nr;

	pthread_mutex_lock(&ctx->complete_lock);
	ret = 0;
	ic = malloc(sizeof(*ic));
	while (nr) {
		struct io_event *ev = &events[total];

		if (!min_nr) {
			ret = io_uring_peek_cqe(ring, &cqe);
			if (ret)
				break;
		} else {
			ret = io_uring_wait_cqes(ring, &cqe, min_nr, ts, sigmask);
			if (ret)
				break;
		}

		ic = io_uring_cqe_get_data(cqe);
		ev->data = ic->data;
		ev->obj = ic->iocb;
		ev->res = cqe->res;
		ev->res2 = 0;
		io_uring_cqe_seen(ring, cqe);
		total++;
		nr--;
		if (min_nr)
			min_nr--;
	};
	free(ic);
	pthread_mutex_unlock(&ctx->complete_lock);
	return total ? total : ret;
}

int io_getevents(io_context_t __ctx, long min_nr, long nr,
		 struct io_event *events, struct timespec *ts)
{
	struct __kernel_timespec kts, *ktsptr = NULL;
	struct io_context *ctx = t_to_ctx(__ctx);

	if (ts) {
		kts.tv_sec = ts->tv_sec;
		kts.tv_nsec = ts->tv_nsec;
		ktsptr = &kts;
	}
	return __io_getevents(ctx, min_nr, nr, events, ktsptr, NULL);
}

int io_pgetevents(io_context_t __ctx, long min_nr, long nr,
		  struct io_event *events, struct timespec *ts,
		  sigset_t *sigmask)
{
	struct __kernel_timespec kts, *ktsptr = NULL;
	struct io_context *ctx = t_to_ctx(__ctx);

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

static int mutex_init_pshared(pthread_mutex_t *mutex)
{
	pthread_mutexattr_t mattr;
	int ret;

	ret = pthread_mutexattr_init(&mattr);
	if (ret) {
		fprintf(stderr, "pthread_mutexattr_init: %s\n", strerror(ret));
		return ret;
	}

	ret = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		fprintf(stderr, "pthread_mutexattr_setpshared: %s\n", strerror(ret));
		pthread_mutexattr_destroy(&mattr);
		return ret;
	}
	ret = pthread_mutex_init(mutex, &mattr);
	if (ret) {
		fprintf(stderr, "pthread_mutex_init: %s\n", strerror(ret));
		pthread_mutexattr_destroy(&mattr);
		return ret;
	}

	pthread_mutexattr_destroy(&mattr);
	return 0;
}

int io_queue_init(int maxevents, io_context_t *ctxptr)
{
	struct io_context *ctx;
	struct io_uring *ring;
	size_t len;
	void *ptr;
	int ret;

	maxevents = roundup_pow2(maxevents);
	len = sizeof(*ctx) + maxevents * sizeof(struct io_event);

	if (posix_memalign(&ptr, PAGE_SIZE, len))
		return -ENOMEM;

	ctx = ptr;
	ring = &ctx->ring;
	ret = io_uring_queue_init(maxevents, ring, 0);
	if (ret) {
		free(ctx);
		*ctxptr = NULL;
		return ret;
	}

	ctx->aio_ring.id = ~0U;
	ctx->aio_ring.nr = maxevents;
	ctx->aio_ring.magic = AIO_RING_MAGIC;
	ctx->aio_ring.compat_features = 1;
	ctx->aio_ring.incompat_features = 0;
	ctx->aio_ring.header_length = sizeof(struct aio_ring);
	*ctxptr = (void *) &ctx->aio_ring;

	mutex_init_pshared(&ctx->submit_lock);
	mutex_init_pshared(&ctx->complete_lock);

	ctx->eventfd = -1;
	return 0;
}

int io_setup(unsigned maxevents, io_context_t *ctxp)
{
	return io_queue_init(maxevents, ctxp);
}

int io_destroy(io_context_t __ctx)
{
	struct io_context *ctx = t_to_ctx(__ctx);
	struct io_uring *ring = &ctx->ring;

	if (ctx->eventfd != -1) {
		uint64_t val = -1ULL;
		void *tret;
		int ret;

		ctx->do_exit = 1;
		ret = write(ctx->eventfd, &val, sizeof(val));
		assert(ret == sizeof(val));
		pthread_join(ctx->event_thread, &tret);
		io_uring_unregister_eventfd(ring);
		close(ctx->eventfd);
	}
	io_uring_queue_exit(ring);
	pthread_mutex_destroy(&ctx->submit_lock);
	pthread_mutex_destroy(&ctx->complete_lock);
	free(ctx);
	return 0;
}
