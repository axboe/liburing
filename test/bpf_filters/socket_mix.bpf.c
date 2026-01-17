#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/socket.h>

#include "../../src/include/liburing/io_uring/bpf_filter.h"

SEC("io_uring_filter")
int socket_mix_filter(struct io_uring_bpf_ctx *ctx)
{
	/* Only allow AF_INET and AF_INET6 */
	if (ctx->socket.family != AF_INET && ctx->socket.family != AF_INET6)
		return 0;
	/* Only allow SOCK_STREAM (TCP) */
	if (ctx->socket.type != SOCK_STREAM)
		return 0;
	/* Only allow IPPROTO_TCP or default (0) */
	if (ctx->socket.protocol != IPPROTO_TCP && ctx->socket.protocol != 0)
		return 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
