/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Header file for the io_uring BPF filters.
 */
#ifndef LINUX_IO_URING_BPF_FILTER_H
#define LINUX_IO_URING_BPF_FILTER_H

#include <linux/types.h>

struct io_uring_bpf_ctx {
	__u8	opcode;
	__u8	sqe_flags;
	__u8	pad[6];
	__u64	user_data;
	union {
		__u64	resv[6];
		struct {
			__u32	family;
			__u32	type;
			__u32	protocol;
		} socket;
	};
};

enum {
	/*
	 * If set, any currently unset opcode will have a deny filter attached
	 */
	IO_URING_BPF_FILTER_DENY_REST	= 1,
};

struct io_uring_bpf_filter {
	__u32	opcode;		/* io_uring opcode to filter */
	__u32	flags;
	__s32	prog_fd;	/* BPF program fd */
	__u32	reserved[3];
};

enum {
	IO_URING_BPF_CMD_FILTER	= 1,
};

struct io_uring_bpf {
	__u16	cmd_type;	/* IO_URING_BPF_* values */
	__u16	cmd_flags;	/* none so far */
	__u32	resv;
	union {
		struct io_uring_bpf_filter	filter;
	};
};

#endif
