/* SPDX-License-Identifier: MIT */

#ifndef LIBURING_ARCH_X86_LIB_H
#define LIBURING_ARCH_X86_LIB_H

#ifndef LIBURING_LIB_H
#  error "This file should be included from src/lib.h (liburing)"
#endif

#if defined(__x86_64__)

static inline long __arch_impl_get_page_size(void)
{
	return 4096;
}

#else /* #if defined(__x86_64__) */

/*
 * TODO: Add x86 (32-bit) support here.
 */
#error "x86 (32-bit) is currently not supported for nolibc builds"

#endif /* #if defined(__x86_64__) */

#endif /* #ifndef LIBURING_ARCH_X86_LIB_H */
