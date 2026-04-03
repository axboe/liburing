/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "liburing.h"
#include "cp.skel.h"
#include "helpers.h"

static struct cp_bpf *skel;
static struct bpf_link *cp_bpf_link;

static char *in_fname;
static char *out_fname;

static size_t buffer_size = 4096;
static int input_fd;
static int output_fd;
static void *buffer;

#define CQ_ENTRIES 8
#define SQ_ENTRIES 8

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

	skel = cp_bpf__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		return T_EXIT_FAIL;
	}

	skel->struct_ops.cp_ops->ring_fd = ring->ring_fd;
	skel->rodata->sq_hdr_offset = params.sq_off.head;
	skel->rodata->cq_hdr_offset = params.cq_off.head;
	skel->rodata->cqes_offset = params.cq_off.cqes;
	skel->rodata->cq_entries = CQ_ENTRIES;
	skel->rodata->sq_entries = SQ_ENTRIES;
	skel->bss->input_fd = input_fd;
	skel->bss->output_fd = output_fd;
	skel->bss->buffer_uptr = buffer;
	skel->bss->buffer_size = buffer_size;
	skel->bss->cp_result = -EBUSY;

	ret = cp_bpf__load(skel);
	if (ret) {
		if (ret == -ESRCH) {
			printf("io_uring BPF ops are not supported\n");
			return T_EXIT_SKIP;
		}
		fprintf(stderr, "failed to load skeleton\n");
		return T_EXIT_FAIL;
	}

	cp_bpf_link = bpf_map__attach_struct_ops(skel->maps.cp_ops);
	if (!cp_bpf_link) {
		fprintf(stderr, "failed to attach ops\n");
		return T_EXIT_FAIL;
	}
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	size_t file_size;
	struct stat st;
	int ret;

	if (argc != 3)
		return T_EXIT_SKIP;

	in_fname = argv[1];
	out_fname = argv[2];

	input_fd = open(in_fname, O_RDONLY | O_DIRECT);
	output_fd = open(out_fname, O_WRONLY | O_DIRECT | O_CREAT, 0644);
	if (input_fd < 0 || output_fd < 0) {
		fprintf(stderr, "can't open files");
		return T_EXIT_FAIL;
	}
	if (fstat(input_fd, &st) == -1) {
		fprintf(stderr, "stat failed\n");
		return T_EXIT_FAIL;
	}
	file_size = st.st_size;

	buffer = aligned_alloc(4096, buffer_size);
	if (!buffer) {
		fprintf(stderr, "can't allocate buffer\n");
		return T_EXIT_FAIL;
	}

	ret = setup_ring_ops(&ring);
	if (ret != T_EXIT_PASS)
		return ret;

	if (ftruncate(output_fd, file_size) == -1) {
		fprintf(stderr, "ftruncate failed\n");
		return T_EXIT_FAIL;
	}

	ret = io_uring_enter(ring.ring_fd, 0, 0, IORING_ENTER_GETEVENTS, NULL);
	if (ret) {
		fprintf(stderr, "run failed\n");
		return T_EXIT_FAIL;
	}

	ret = skel->bss->cp_result;
	if (ret) {
		fprintf(stderr, "cp failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	bpf_link__destroy(cp_bpf_link);
	cp_bpf__destroy(skel);
	return 0;
}
