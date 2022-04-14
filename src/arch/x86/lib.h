/* SPDX-License-Identifier: MIT */

#ifndef __INTERNAL__LIBURING_LIB_H
	#error "This file should be included from src/lib.h (liburing)"
#endif

#ifndef LIBURING_ARCH_X86_LIB_H
#define LIBURING_ARCH_X86_LIB_H

static inline long get_page_size(void)
{
	return 4096;
}

#endif /* #ifndef LIBURING_ARCH_X86_LIB_H */
