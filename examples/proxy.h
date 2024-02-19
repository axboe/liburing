/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_PROXY_H
#define LIBURING_PROXY_H

/*
 * Generic opcode agnostic encoding to sqe/cqe->user_data
 */
struct userdata {
	union {
		struct {
			uint16_t op_tid; /* 3 bits op, 13 bits tid */
			uint16_t bid;
			uint16_t fd;
		};
		uint64_t val;
	};
};

#define OP_SHIFT	(12)
#define TID_MASK	((1U << 12) - 1)

/*
 * Packs the information that we will need at completion time into the
 * sqe->user_data field, which is passed back in the completion in
 * cqe->user_data. Some apps would need more space than this, and in fact
 * I'd love to pack the requested IO size in here, and it's not uncommon to
 * see apps use this field as just a cookie to either index a data structure
 * at completion time, or even just put the pointer to the associated
 * structure into this field.
 */
static inline void __encode_userdata(struct io_uring_sqe *sqe, int tid, int op,
				     int bid, int fd)
{
	struct userdata ud = {
		.op_tid = (op << OP_SHIFT) | tid,
		.bid = bid,
		.fd = fd
	};

	io_uring_sqe_set_data64(sqe, ud.val);
}

static inline int cqe_to_op(struct io_uring_cqe *cqe)
{
	struct userdata ud = { .val = cqe->user_data };

	return ud.op_tid >> OP_SHIFT;
}

static inline int cqe_to_bid(struct io_uring_cqe *cqe)
{
	struct userdata ud = { .val = cqe->user_data };

	return ud.bid;
}

static inline int cqe_to_fd(struct io_uring_cqe *cqe)
{
	struct userdata ud = { .val = cqe->user_data };

	return ud.fd;
}

#endif
