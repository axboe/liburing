#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "../../src/include/liburing/io_uring/bpf_filter.h"

SEC("io_uring_filter")
int nop_deny_filter(struct io_uring_bpf_ctx *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
