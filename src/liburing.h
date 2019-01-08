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
	struct io_uring_iocb *iocbs;

	unsigned iocb_head;
	unsigned iocb_tail;

	size_t ring_sz;
};

struct io_uring_cq {
	unsigned *khead;
	unsigned *ktail;
	unsigned *kring_mask;
	unsigned *kring_entries;
	unsigned *koverflow;
	struct io_uring_event *events;

	size_t ring_sz;
};

/*
 * System calls
 */
extern int io_uring_setup(unsigned entries, struct iovec *iovecs,
	struct io_uring_params *p);
extern int io_uring_enter(unsigned fd, unsigned to_submit,
	unsigned min_complete, unsigned flags);

/*
 * Library interface
 */
extern int io_uring_queue_init(unsigned entries, struct io_uring_params *p,
	struct iovec *iovecs, struct io_uring_sq *sq, struct io_uring_cq *cq);
extern void io_uring_queue_exit(int fd, struct io_uring_sq *sq,
	struct io_uring_cq *cq);
extern int io_uring_get_completion(int fd, struct io_uring_cq *cq,
	struct io_uring_event **ev_ptr);
extern int io_uring_wait_completion(int fd, struct io_uring_cq *cq,
	struct io_uring_event **ev_ptr);
extern int io_uring_submit(int fd, struct io_uring_sq *sq);
extern struct io_uring_iocb *io_uring_get_iocb(struct io_uring_sq *sq);

#endif
