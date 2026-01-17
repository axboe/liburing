#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/socket.h>

#include "../../src/include/liburing/io_uring/bpf_filter.h"

SEC("io_uring_filter")
int socket_allow_filter(struct io_uring_bpf_ctx *ctx)
{
	return 1;
}

char _license[] SEC("license") = "GPL";
