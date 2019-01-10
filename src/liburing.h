#ifndef LIB_URING_H
#define LIB_URING_H

#include <sys/uio.h>
#include "io_uring.h"

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
};

struct io_uring_cq {
	unsigned *khead;
	unsigned *ktail;
	unsigned *kring_mask;
	unsigned *kring_entries;
	unsigned *koverflow;
	struct io_uring_cqe *cqes;

	size_t ring_sz;
};

struct io_uring {
	struct io_uring_sq sq;
	struct io_uring_cq cq;
	int ring_fd;
};

/*
 * System calls
 */
extern int io_uring_setup(unsigned entries, struct io_uring_params *p);
extern int io_uring_enter(unsigned fd, unsigned to_submit,
	unsigned min_complete, unsigned flags);
extern int io_uring_register(int fd, unsigned int opcode, void *arg);

/*
 * Library interface
 */
extern int io_uring_queue_init(unsigned entries, struct io_uring_params *p,
	struct io_uring *ring);
extern void io_uring_queue_exit(struct io_uring *ring);
extern int io_uring_get_completion(struct io_uring *ring,
	struct io_uring_cqe **cqe_ptr);
extern int io_uring_wait_completion(struct io_uring *ring,
	struct io_uring_cqe **cqe_ptr);
extern int io_uring_submit(struct io_uring *ring);
extern struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring);

#endif
