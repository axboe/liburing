#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "compat.h"
#include "io_uring.h"
#include "liburing.h"
#include "barrier.h"

static int __io_uring_get_cqe(struct io_uring *ring,
			      struct io_uring_cqe **cqe_ptr, int wait)
{
	struct io_uring_cq *cq = &ring->cq;
	const unsigned mask = *cq->kring_mask;
	unsigned head;
	int ret;

	*cqe_ptr = NULL;
	head = *cq->khead;
	do {
		/*
		 * It's necessary to use a read_barrier() before reading
		 * the CQ tail, since the kernel updates it locklessly. The
		 * kernel has the matching store barrier for the update. The
		 * kernel also ensures that previous stores to CQEs are ordered
		 * with the tail update.
		 */
		read_barrier();
		if (head != *cq->ktail) {
			*cqe_ptr = &cq->cqes[head & mask];
			break;
		}
		if (!wait)
			break;
		ret = io_uring_enter(ring->ring_fd, 0, 1,
					IORING_ENTER_GETEVENTS, NULL);
		if (ret < 0)
			return -errno;
	} while (1);

	return 0;
}

/*
 * Return an IO completion, if one is readily available. Returns 0 with
 * cqe_ptr filled in on success, -errno on failure.
 */
int io_uring_peek_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
	return __io_uring_get_cqe(ring, cqe_ptr, 0);
}

/*
 * Return an IO completion, waiting for it if necessary. Returns 0 with
 * cqe_ptr filled in on success, -errno on failure.
 */
int io_uring_wait_cqe(struct io_uring *ring, struct io_uring_cqe **cqe_ptr)
{
	return __io_uring_get_cqe(ring, cqe_ptr, 1);
}

/*
 * Returns true if we're not using SQ thread (thus nobody submits but us)
 * or if IORING_SQ_NEED_WAKEUP is set, so submit thread must be explicitly
 * awakened. For the latter case, we set the thread wakeup flag.
 */
static inline bool sq_ring_needs_enter(struct io_uring *ring, unsigned *flags)
{
	if (!(ring->flags & IORING_SETUP_SQPOLL))
		return true;
	if ((*ring->sq.kflags & IORING_SQ_NEED_WAKEUP)) {
		*flags |= IORING_ENTER_SQ_WAKEUP;
		return true;
	}

	return false;
}

/*
 * Submit sqes acquired from io_uring_get_sqe() to the kernel.
 *
 * Returns number of sqes submitted
 */
static int __io_uring_submit(struct io_uring *ring, unsigned wait_nr)
{
	struct io_uring_sq *sq = &ring->sq;
	const unsigned mask = *sq->kring_mask;
	unsigned ktail, ktail_next, submitted, to_submit;
	unsigned flags;
	int ret;

	if (sq->sqe_head == sq->sqe_tail)
		return 0;

	/*
	 * Fill in sqes that we have queued up, adding them to the kernel ring
	 */
	submitted = 0;
	ktail = ktail_next = *sq->ktail;
	to_submit = sq->sqe_tail - sq->sqe_head;
	while (to_submit--) {
		ktail_next++;
		read_barrier();

		sq->array[ktail & mask] = sq->sqe_head & mask;
		ktail = ktail_next;

		sq->sqe_head++;
		submitted++;
	}

	if (!submitted)
		return 0;

	if (*sq->ktail != ktail) {
		/*
		 * First write barrier ensures that the SQE stores are updated
		 * with the tail update. This is needed so that the kernel
		 * will never see a tail update without the preceeding sQE
		 * stores being done.
		 */
		write_barrier();
		*sq->ktail = ktail;
		/*
		 * The kernel has the matching read barrier for reading the
		 * SQ tail.
		 */
		write_barrier();
	}

	flags = 0;
	if (wait_nr || sq_ring_needs_enter(ring, &flags)) {
		if (wait_nr) {
			if (wait_nr > submitted)
				wait_nr = submitted;
			flags |= IORING_ENTER_GETEVENTS;
		}

		ret = io_uring_enter(ring->ring_fd, submitted, wait_nr, flags,
					NULL);
		if (ret < 0)
			return -errno;
	} else
		ret = submitted;

	return ret;
}

/*
 * Submit sqes acquired from io_uring_get_sqe() to the kernel.
 *
 * Returns number of sqes submitted
 */
int io_uring_submit(struct io_uring *ring)
{
	return __io_uring_submit(ring, 0);
}

/*
 * Like io_uring_submit(), but allows waiting for events as well.
 *
 * Returns number of sqes submitted
 */
int io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr)
{
	return __io_uring_submit(ring, wait_nr);
}

/*
 * Return an sqe to fill. Application must later call io_uring_submit()
 * when it's ready to tell the kernel about it. The caller may call this
 * function multiple times before calling io_uring_submit().
 *
 * Returns a vacant sqe, or NULL if we're full.
 */
struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	unsigned next = sq->sqe_tail + 1;
	struct io_uring_sqe *sqe;

	/*
	 * All sqes are used
	 */
	if (next - sq->sqe_head > *sq->kring_entries)
		return NULL;

	sqe = &sq->sqes[sq->sqe_tail & *sq->kring_mask];
	sq->sqe_tail = next;
	return sqe;
}
