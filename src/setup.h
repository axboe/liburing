/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_SETUP_H
#define LIBURING_SETUP_H

#include <errno.h>
#include <stddef.h>

int __io_uring_queue_init_params(unsigned entries, struct io_uring *ring,
				 struct io_uring_params *p, void *buf,
				 size_t buf_size);
void io_uring_unmap_rings(struct io_uring_sq *sq, struct io_uring_cq *cq);
int io_uring_mmap(int fd, struct io_uring_params *p, struct io_uring_sq *sq,
		  struct io_uring_cq *cq);
void io_uring_setup_ring_pointers(struct io_uring_params *p,
				  struct io_uring_sq *sq,
				  struct io_uring_cq *cq);

/*
 * Multiply @count by @elem into *@out. Returns 0 on success and
 * -EOVERFLOW if the multiplication would wrap; *@out is unspecified on
 * error.
 *
 * Every product fed to mmap()/munmap() or used as a buffer size must go
 * through this helper. The kernel caps most user-supplied counts before
 * they reach these sites, but that invariant lives in a different
 * function from the multiplication, so a reviewer cannot verify safety
 * locally. Routing every `count * elem` through __size_mul makes the
 * overflow check co-located with the operation it protects, and removes
 * the silent-wrap-into-undersized-allocation class of bug regardless of
 * what future callers or kernel changes do to the input ranges.
 */
static inline int __size_mul(size_t count, size_t elem, size_t *out)
{
	if (__builtin_mul_overflow(count, elem, out))
		return -EOVERFLOW;
	return 0;
}

#endif
