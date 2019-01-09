#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "io_uring.h"
#include "liburing.h"
#include "barrier.h"

static int __io_uring_get_completion(int fd, struct io_uring_cq *cq,
				     struct io_uring_cqe **cqe_ptr, int wait)
{
	const unsigned mask = *cq->kring_mask;
	unsigned head;
	int ret;

	*cqe_ptr = NULL;
	head = *cq->khead;
	do {
		read_barrier();
		if (head != *cq->ktail) {
			*cqe_ptr = &cq->cqes[head & mask];
			break;
		}
		if (!wait)
			break;
		ret = io_uring_enter(fd, 0, 1, IORING_ENTER_GETEVENTS);
		if (ret < 0)
			return -errno;
	} while (1);

	if (*cqe_ptr) {
		*cq->khead = head + 1;
		write_barrier();
	}

	return 0;
}

/*
 * Return an IO completion, if one is readily available
 */
int io_uring_get_completion(struct io_uring *ring,
			    struct io_uring_cqe **cqe_ptr)
{
	return __io_uring_get_completion(ring->ring_fd, &ring->cq, cqe_ptr, 0);
}

/*
 * Return an IO completion, waiting for it if necessary
 */
int io_uring_wait_completion(struct io_uring *ring,
			     struct io_uring_cqe **cqe_ptr)
{
	return __io_uring_get_completion(ring->ring_fd, &ring->cq, cqe_ptr, 1);
}

/*
 * Submit sqes acquired from io_uring_get_sqe() to the kernel.
 *
 * Returns number of sqes submitted
 */
int io_uring_submit(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	const unsigned mask = *sq->kring_mask;
	unsigned ktail, ktail_next, submitted;

	/*
	 * If we have pending IO in the kring, submit it first
	 */
	read_barrier();
	if (*sq->khead != *sq->ktail) {
		submitted = *sq->kring_entries;
		goto submit;
	}

	if (sq->sqe_head == sq->sqe_tail)
		return 0;

	/*
	 * Fill in sqes that we have queued up, adding them to the kernel ring
	 */
	submitted = 0;
	ktail = ktail_next = *sq->ktail;
	while (sq->sqe_head < sq->sqe_tail) {
		ktail_next++;
		read_barrier();
		if (ktail_next == *sq->khead)
			break;

		sq->array[ktail & mask] = sq->sqe_head & mask;
		ktail = ktail_next;

		sq->sqe_head++;
		submitted++;
	}

	if (!submitted)
		return 0;

	if (*sq->ktail != ktail) {
		write_barrier();
		*sq->ktail = ktail;
		write_barrier();
	}

submit:
	return io_uring_enter(ring->ring_fd, submitted, 0,
				IORING_ENTER_GETEVENTS);
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

static int io_uring_mmap(int fd, struct io_uring_params *p,
			 struct io_uring_sq *sq, struct io_uring_cq *cq)
{
	size_t size;
	void *ptr;
	int ret;

	sq->ring_sz = p->sq_off.array + p->sq_entries * sizeof(unsigned);
	ptr = mmap(0, sq->ring_sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (ptr == MAP_FAILED)
		return -errno;
	sq->khead = ptr + p->sq_off.head;
	sq->ktail = ptr + p->sq_off.tail;
	sq->kring_mask = ptr + p->sq_off.ring_mask;
	sq->kring_entries = ptr + p->sq_off.ring_entries;
	sq->kflags = ptr + p->sq_off.flags;
	sq->kdropped = ptr + p->sq_off.dropped;
	sq->array = ptr + p->sq_off.array;

	size = p->sq_entries * sizeof(struct io_uring_sqe),
	sq->sqes = mmap(0, size, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE, fd,
				IORING_OFF_SQES);
	if (sq->sqes == MAP_FAILED) {
		ret = -errno;
err:
		munmap(sq->khead, sq->ring_sz);
		return ret;
	}

	cq->ring_sz = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);
	ptr = mmap(0, cq->ring_sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
	if (ptr == MAP_FAILED) {
		ret = -errno;
		munmap(sq->sqes, p->sq_entries * sizeof(struct io_uring_sqe));
		goto err;
	}
	cq->khead = ptr + p->cq_off.head;
	cq->ktail = ptr + p->cq_off.tail;
	cq->kring_mask = ptr + p->cq_off.ring_mask;
	cq->kring_entries = ptr + p->cq_off.ring_entries;
	cq->koverflow = ptr + p->cq_off.overflow;
	cq->cqes = ptr + p->cq_off.cqes;
	return 0;
}

/*
 * Returns -1 on error, or zero on success. On success, 'ring'
 * contains the necessary information to read/write to the rings.
 */
int io_uring_queue_init(unsigned entries, struct io_uring_params *p,
			struct iovec *iovecs, struct io_uring *ring)
{
	int fd, ret;

	fd = io_uring_setup(entries, iovecs, p);
	if (fd < 0)
		return fd;

	memset(ring, 0, sizeof(*ring));
	ret = io_uring_mmap(fd, p, &ring->sq, &ring->cq);
	if (!ret)
		ring->ring_fd = fd;
	return ret;
}

void io_uring_queue_exit(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	struct io_uring_cq *cq = &ring->cq;

	munmap(sq->sqes, *sq->kring_entries * sizeof(struct io_uring_sqe));
	munmap(sq->khead, sq->ring_sz);
	munmap(cq->khead, cq->ring_sz);
	close(ring->ring_fd);
}
