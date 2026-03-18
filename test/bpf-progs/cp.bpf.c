/* SPDX-License-Identifier: GPL-2.0 */
#include "../bpf_defs.h"
#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum {
	REQ_TOKEN_READ = 1,
	REQ_TOKEN_WRITE
};

const volatile unsigned cq_hdr_offset;
const volatile unsigned sq_hdr_offset;
const volatile unsigned cqes_offset;
const volatile unsigned sq_entries;
const volatile unsigned cq_entries;

int input_fd;
int output_fd;
void *buffer_uptr;
unsigned nr_infligt;
unsigned cur_offset;
size_t buffer_size;
int cp_result;

#define t_min(a, b) ((a) < (b) ? (a) : (b))

static inline void sqe_prep_rw(struct io_uring_sqe *sqe, unsigned opcode,
				   int fd, void *addr,
				   __u32 len, __u64 offset)
{
	*sqe = (struct io_uring_sqe){};
	sqe->opcode = opcode;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (__u64)(unsigned long)addr;
	sqe->len = len;
}

static int issue_next_req(struct io_ring_ctx *ring, struct io_uring_sqe *sqes,
			  int type, size_t size)
{
	struct io_uring_sqe *sqe = sqes;
	__u8 req_type;
	int fd, ret;

	if (type == REQ_TOKEN_READ) {
		req_type = IORING_OP_READ;
		fd = input_fd;
	} else {
		req_type = IORING_OP_WRITE;
		fd = output_fd;
	}

	sqe_prep_rw(sqes, req_type, fd, buffer_uptr, size, cur_offset);
	sqe->user_data = type;

	ret = bpf_io_uring_submit_sqes(ring, 1);
	if (ret != 1) {
		cp_result = ret;
		return ret < 0 ? ret : -EFAULT;
	}
	return 0;
}

SEC("struct_ops.s/cp_loop_step")
int BPF_PROG(cp_loop_step, struct io_ring_ctx *ring, struct iou_loop_params *ls)
{
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	struct io_uring *cq_hdr;
	void *rings;
	int ret;

	sqes = (void *)bpf_io_uring_get_region(ring, IOU_REGION_SQ,
				sq_entries * sizeof(struct io_uring_sqe));
	rings = (void *)bpf_io_uring_get_region(ring, IOU_REGION_CQ,
				cqes_offset + cq_entries * sizeof(struct io_uring_cqe));
	if (!rings || !sqes)
		return IOU_LOOP_STOP;
	cq_hdr = rings + cq_hdr_offset;
	cqes = rings + cqes_offset;

	if (!nr_infligt) {
		nr_infligt++;
		ret = issue_next_req(ring, sqes, REQ_TOKEN_READ,
				     buffer_size);
		if (ret)
			return IOU_LOOP_STOP;
	}

	if (cq_hdr->tail != cq_hdr->head) {
		struct io_uring_cqe *cqe;

		if (cq_hdr->tail - cq_hdr->head != 1) {
			cp_result = -ERANGE;
			return IOU_LOOP_STOP;
		}

		cqe = &cqes[cq_hdr->head & (cq_entries - 1)];
		if (cqe->res < 0) {
			cp_result = cqe->res;
			return IOU_LOOP_STOP;
		}

		switch (cqe->user_data) {
		case REQ_TOKEN_READ:
			if (cqe->res == 0) {
				cp_result = 0;
				return IOU_LOOP_STOP;
			}
			ret = issue_next_req(ring, sqes, REQ_TOKEN_WRITE,
					     cqe->res);
			if (ret)
				return IOU_LOOP_STOP;
			break;
		case REQ_TOKEN_WRITE:
			cur_offset += cqe->res;
			ret = issue_next_req(ring, sqes, REQ_TOKEN_READ,
					     buffer_size);
			if (ret)
				return IOU_LOOP_STOP;
			break;
		default:
			bpf_printk("invalid token\n");
			cp_result = -EINVAL;
			return IOU_LOOP_STOP;
		};

		cq_hdr->head++;
	}

	ls->cq_wait_idx = cq_hdr->head + 1;
	return IOU_LOOP_CONTINUE;
}

SEC(".struct_ops.link")
struct io_uring_bpf_ops cp_ops = {
	.loop_step = (void *)cp_loop_step,
};
