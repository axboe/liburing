/* SPDX-License-Identifier: MIT */
#define IOURINGINLINE

#ifdef __clang__
// clang doesn't seem to particularly like that we're including a header that
// deliberately contains function definitions so we explicitly silence it
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#endif

#include "liburing.h"

struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring)
{
	return _io_uring_get_sqe(ring);
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif
