/* SPDX-License-Identifier: GPL-2.0 */
#include "../bpf_defs.h"
#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define REQ_TOKEN 0xabba1741

const unsigned max_inflight = 8;
const volatile unsigned cq_hdr_offset;
const volatile unsigned sq_hdr_offset;
const volatile unsigned cqes_offset;
const volatile unsigned cq_entries;
const volatile unsigned sq_entries;

unsigned reqs_inflight = 0;
int reqs_to_run;

#define t_min(a, b) ((a) < (b) ? (a) : (b))

static unsigned nr_to_submit(void)
{
	unsigned to_submit = 0;
	unsigned inflight = reqs_inflight;

	if (inflight < max_inflight) {
		to_submit = max_inflight - inflight;
		to_submit = t_min(to_submit, reqs_to_run - inflight);
	}
	return to_submit;
}

SEC("struct_ops.s/nops_loop_step")
int BPF_PROG(nops_loop_step, struct io_ring_ctx *ring, struct iou_loop_params *ls)
{
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	struct io_uring *cq_hdr;
	unsigned to_submit;
	unsigned to_wait;
	unsigned nr_cqes;
	void *rings;
	int ret, i;

	sqes = (void *)bpf_io_uring_get_region(ring, IOU_REGION_SQ,
				sq_entries * sizeof(struct io_uring_sqe));
	rings = (void *)bpf_io_uring_get_region(ring, IOU_REGION_CQ,
				cqes_offset + cq_entries * sizeof(struct io_uring_cqe));
	if (!rings || !sqes)
		return IOU_LOOP_STOP;
	cq_hdr = rings + cq_hdr_offset;
	cqes = rings + cqes_offset;

	to_submit = nr_to_submit();
	if (to_submit) {
		for (i = 0; i < to_submit; i++) {
			struct io_uring_sqe *sqe = &sqes[i];

			*sqe = (struct io_uring_sqe){};
			sqe->opcode = IORING_OP_NOP;
			sqe->user_data = REQ_TOKEN;
		}

		ret = bpf_io_uring_submit_sqes(ring, to_submit);
		if (ret != to_submit)
			return IOU_LOOP_STOP;
		reqs_inflight += to_submit;
	}

	nr_cqes = cq_hdr->tail - cq_hdr->head;
	nr_cqes = t_min(nr_cqes, max_inflight);
	for (i = 0; i < nr_cqes; i++) {
		struct io_uring_cqe *cqe = &cqes[cq_hdr->head & (cq_entries - 1)];

		if (cqe->user_data != REQ_TOKEN)
			return IOU_LOOP_STOP;
		cq_hdr->head++;
	}

	reqs_inflight -= nr_cqes;
	reqs_to_run -= nr_cqes;

	if (reqs_to_run <= 0 && !reqs_inflight)
		return IOU_LOOP_STOP;

	to_wait = reqs_inflight;
	/* Don't sleep if there are still CQEs left */
	if (cq_hdr->tail != cq_hdr->head)
		to_wait = 0;
	ls->cq_wait_idx = cq_hdr->head + to_wait;
	return IOU_LOOP_CONTINUE;
}

SEC(".struct_ops.link")
struct io_uring_bpf_ops nops_ops = {
	.loop_step = (void *)nops_loop_step,
};
