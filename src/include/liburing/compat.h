/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_COMPAT_H
#define LIBURING_COMPAT_H

#if !defined(CONFIG_HAVE_KERNEL_RWF_T)
typedef int __kernel_rwf_t;
#endif

#if !defined(CONFIG_HAVE_KERNEL_TIMESPEC)
struct __kernel_timespec {
	int64_t		tv_sec;
	long long	tv_nsec;
};
#else
#include <linux/time_types.h>
#endif

#endif
