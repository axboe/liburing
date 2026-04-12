/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "liburing.h"
#include "nops.skel.h"
#include "helpers.h"

static struct nops_bpf *skel;
static struct bpf_link *nops_bpf_link;

#define CQ_ENTRIES 8
#define SQ_ENTRIES 8
#define NR_ITERS 1000

static int setup_ring_ops(struct io_uring *ring)
{
	struct io_uring_params params;
	int ret;

	memset(&params, 0, sizeof(params));
	params.cq_entries = CQ_ENTRIES;
	params.flags = IORING_SETUP_SINGLE_ISSUER |
			IORING_SETUP_DEFER_TASKRUN |
			IORING_SETUP_NO_SQARRAY |
			IORING_SETUP_CQSIZE |
			IORING_SETUP_SQ_REWIND;

	ret = t_create_ring_params(SQ_ENTRIES, ring, &params);
	if (ret == T_SETUP_SKIP) {
		printf("Can't setup a ring, skip\n");
		return T_EXIT_SKIP;
	}
	if (ret != T_SETUP_OK)
		return T_EXIT_FAIL;

	skel = nops_bpf__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		return T_EXIT_FAIL;
	}

	skel->struct_ops.nops_ops->ring_fd = ring->ring_fd;
	skel->bss->reqs_to_run = NR_ITERS;
	skel->rodata->cq_head_offset = params.cq_off.head;
	skel->rodata->cq_tail_offset = params.cq_off.tail;

	skel->rodata->cqes_offset = params.cq_off.cqes;
	skel->rodata->cq_entries = CQ_ENTRIES;
	skel->rodata->sq_entries = SQ_ENTRIES;

	ret = nops_bpf__load(skel);
	if (ret) {
		if (ret == -ESRCH) {
			printf("io_uring BPF ops are not supported\n");
			return T_EXIT_SKIP;
		}
		fprintf(stderr, "failed to load skeleton\n");
		return T_EXIT_FAIL;
	}

	nops_bpf_link = bpf_map__attach_struct_ops(skel->maps.nops_ops);
	if (!nops_bpf_link) {
		fprintf(stderr, "failed to attach ops\n");
		return T_EXIT_FAIL;
	}
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	unsigned left;
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = setup_ring_ops(&ring);
	if (ret != T_EXIT_PASS)
		return ret;

	ret = io_uring_enter(ring.ring_fd, 0, 0, IORING_ENTER_GETEVENTS, NULL);
	if (ret) {
		fprintf(stderr, "run failed\n");
		return T_EXIT_FAIL;
	}

	left = skel->bss->reqs_to_run;
	if (left) {
		fprintf(stderr, "Run failed, couldn't submit all nops %i / %i\n",
			NR_ITERS - left, NR_ITERS);
		return T_EXIT_FAIL;
	}

	bpf_link__destroy(nops_bpf_link);
	nops_bpf__destroy(skel);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
}
