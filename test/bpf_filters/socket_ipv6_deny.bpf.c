#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/socket.h>

#include "../../src/include/liburing/io_uring/bpf_filter.h"

SEC("io_uring_filter")
int socket_ipv6_deny_filter(struct io_uring_bpf_ctx *ctx)
{
	if (ctx->socket.family == AF_INET6)
		return 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
