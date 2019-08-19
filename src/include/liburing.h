#ifndef LIB_URING_H
#define LIB_URING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/uio.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include "liburing/compat.h"
#include "liburing/io_uring.h"
#include "liburing/barrier.h"

/*
 * Library interface to io_uring
 */
struct io_uring_sq {
	unsigned *khead;
	unsigned *ktail;
	unsigned *kring_mask;
	unsigned *kring_entries;
	unsigned *kflags;
	unsigned *kdropped;
	unsigned *array;
	struct io_uring_sqe *sqes;

	unsigned sqe_head;
	unsigned sqe_tail;

	size_t ring_sz;
	void *ring_ptr;
};

struct io_uring_cq {
	unsigned *khead;
	unsigned *ktail;
	unsigned *kring_mask;
	unsigned *kring_entries;
	unsigned *koverflow;
	struct io_uring_cqe *cqes;

	size_t ring_sz;
	void *ring_ptr;
};

struct io_uring {
	struct io_uring_sq sq;
	struct io_uring_cq cq;
	unsigned flags;
	int ring_fd;
};

/*
 * System calls
 */
extern int io_uring_setup(unsigned entries, struct io_uring_params *p);
extern int io_uring_enter(unsigned fd, unsigned to_submit,
	unsigned min_complete, unsigned flags, sigset_t *sig);
extern int io_uring_register(int fd, unsigned int opcode, const void *arg,
	unsigned int nr_args);

/*
 * Library interface
 */
extern int io_uring_queue_init(unsigned entries, struct io_uring *ring,
	unsigned flags);
extern int io_uring_queue_mmap(int fd, struct io_uring_params *p,
	struct io_uring *ring);
extern void io_uring_queue_exit(struct io_uring *ring);
extern int io_uring_peek_cqe(struct io_uring *ring,
	struct io_uring_cqe **cqe_ptr);
extern int io_uring_wait_cqe(struct io_uring *ring,
	struct io_uring_cqe **cqe_ptr);
extern int io_uring_submit(struct io_uring *ring);
extern int io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr);
extern struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring);

extern int io_uring_register_buffers(struct io_uring *ring,
					const struct iovec *iovecs,
					unsigned nr_iovecs);
extern int io_uring_unregister_buffers(struct io_uring *ring);
extern int io_uring_register_files(struct io_uring *ring, const int *files,
					unsigned nr_files);
extern int io_uring_unregister_files(struct io_uring *ring);
extern int io_uring_register_eventfd(struct io_uring *ring, int fd);
extern int io_uring_unregister_eventfd(struct io_uring *ring);

#define io_uring_for_each_cqe(ring, head, cqe)					\
	/*									\
	 * io_uring_smp_load_acquire() enforces the order of tail		\
	 * and CQE reads.							\
	 */									\
	for (head = *(ring)->cq.khead;						\
	     (cqe = (head != io_uring_smp_load_acquire((ring)->cq.ktail) ?	\
		&(ring)->cq.cqes[head & (*(ring)->cq.kring_mask)] : NULL));	\
	     head++)								\


/*
 * Must be called after io_uring_for_each_cqe()
 */
static inline void io_uring_cq_advance(struct io_uring *ring,
				       unsigned nr)
{
	if (nr) {
		struct io_uring_cq *cq = &ring->cq;

		/*
		 * Ensure that the kernel only sees the new value of the head
		 * index after the CQEs have been read.
		 */
		io_uring_smp_store_release(cq->khead, *cq->khead + nr);
	}
}

/*
 * Must be called after io_uring_{peek,wait}_cqe() after the cqe has
 * been processed by the application.
 */
static inline void io_uring_cqe_seen(struct io_uring *ring,
				     struct io_uring_cqe *cqe)
{
	if (cqe)
		io_uring_cq_advance(ring, 1);
}

/*
 * Command prep helpers
 */
static inline void io_uring_sqe_set_data(struct io_uring_sqe *sqe, void *data)
{
	sqe->user_data = (unsigned long) data;
}

static inline void *io_uring_cqe_get_data(struct io_uring_cqe *cqe)
{
	return (void *) (uintptr_t) cqe->user_data;
}

static inline void io_uring_sqe_set_flags(struct io_uring_sqe *sqe,
					  unsigned flags)
{
	sqe->flags = flags;
}

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    off_t offset)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = op;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
}

static inline void io_uring_prep_readv(struct io_uring_sqe *sqe, int fd,
				       const struct iovec *iovecs,
				       unsigned nr_vecs, off_t offset)
{
	io_uring_prep_rw(IORING_OP_READV, sqe, fd, iovecs, nr_vecs, offset);
}

static inline void io_uring_prep_read_fixed(struct io_uring_sqe *sqe, int fd,
					    void *buf, unsigned nbytes,
					    off_t offset)
{
	io_uring_prep_rw(IORING_OP_READ_FIXED, sqe, fd, buf, nbytes, offset);
}

static inline void io_uring_prep_writev(struct io_uring_sqe *sqe, int fd,
					const struct iovec *iovecs,
					unsigned nr_vecs, off_t offset)
{
	io_uring_prep_rw(IORING_OP_WRITEV, sqe, fd, iovecs, nr_vecs, offset);
}

static inline void io_uring_prep_write_fixed(struct io_uring_sqe *sqe, int fd,
					     const void *buf, unsigned nbytes,
					     off_t offset)
{
	io_uring_prep_rw(IORING_OP_WRITE_FIXED, sqe, fd, buf, nbytes, offset);
}

static inline void io_uring_prep_poll_add(struct io_uring_sqe *sqe, int fd,
					  short poll_mask)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_POLL_ADD;
	sqe->fd = fd;
	sqe->poll_events = poll_mask;
}

static inline void io_uring_prep_poll_remove(struct io_uring_sqe *sqe,
					     void *user_data)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_POLL_REMOVE;
	sqe->addr = (unsigned long) user_data;
}

static inline void io_uring_prep_fsync(struct io_uring_sqe *sqe, int fd,
				       unsigned fsync_flags)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_FSYNC;
	sqe->fd = fd;
	sqe->fsync_flags = fsync_flags;
}

static inline void io_uring_prep_nop(struct io_uring_sqe *sqe)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_NOP;
}

#ifdef __cplusplus
}
#endif

#endif
