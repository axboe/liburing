#ifndef T_LIBURING_BPF_DEFS_H_
#define T_LIBURING_BPF_DEFS_H_

#include <linux/types.h>
#include <linux/errno.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "liburing/io_uring.h"

struct io_ring_ctx {};

struct iou_loop_params {
	__u32 cq_wait_idx;
};

struct io_uring {
	__u32 head;
	__u32 tail;
};

enum {
	IOU_REGION_MEM = 0,
	IOU_REGION_CQ = 1,
	IOU_REGION_SQ = 2,
};

enum {
	IOU_LOOP_CONTINUE = 0,
	IOU_LOOP_STOP = 1,
};

struct io_uring_bpf_ops {
	int (*loop_step)(struct io_ring_ctx *, struct iou_loop_params *);
	__u32 ring_fd;
};

extern __u8 *bpf_io_uring_get_region(struct io_ring_ctx *ctx, __u32 region_id, const size_t rdwr_buf_size) __weak __ksym;
extern int bpf_io_uring_submit_sqes(struct io_ring_ctx *ctx, __u32 nr) __weak __ksym;

#endif /* T_LIBURING_BPF_DEFS_H_ */
