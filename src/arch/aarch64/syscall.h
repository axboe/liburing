/* SPDX-License-Identifier: MIT */

#ifndef __INTERNAL__LIBURING_SYSCALL_H
	#error "This file should be included from src/syscall.h (liburing)"
#endif

#ifndef LIBURING_ARCH_AARCH64_SYSCALL_H
#define LIBURING_ARCH_AARCH64_SYSCALL_H

#if defined(__aarch64__)

#define __do_syscallN(...) ({						\
	__asm__ volatile (						\
		"svc 0"							\
		: "=r"(x0)						\
		: __VA_ARGS__						\
		: "memory", "cc");					\
	(long) x0;							\
})

#define __do_syscall0(__n) ({						\
	register long x8 __asm__("x8") = __n;				\
	register long x0 __asm__("x0");					\
									\
	__do_syscallN("r" (x8));					\
})

#define __do_syscall1(__n, __a) ({					\
	register long x8 __asm__("x8") = __n;				\
	register __typeof__(__a) x0 __asm__("x0") = __a;		\
									\
	__do_syscallN("r" (x8), "0" (x0));				\
})

#define __do_syscall2(__n, __a, __b) ({					\
	register long x8 __asm__("x8") = __n;				\
	register __typeof__(__a) x0 __asm__("x0") = __a;		\
	register __typeof__(__b) x1 __asm__("x1") = __b;		\
									\
	__do_syscallN("r" (x8), "0" (x0), "r" (x1));			\
})

#define __do_syscall3(__n, __a, __b, __c) ({				\
	register long x8 __asm__("x8") = __n;				\
	register __typeof__(__a) x0 __asm__("x0") = __a;		\
	register __typeof__(__b) x1 __asm__("x1") = __b;		\
	register __typeof__(__c) x2 __asm__("x2") = __c;		\
									\
	__do_syscallN("r" (x8), "0" (x0), "r" (x1), "r" (x2));		\
})

#define __do_syscall4(__n, __a, __b, __c, __d) ({			\
	register long x8 __asm__("x8") = __n;				\
	register __typeof__(__a) x0 __asm__("x0") = __a;		\
	register __typeof__(__b) x1 __asm__("x1") = __b;		\
	register __typeof__(__c) x2 __asm__("x2") = __c;		\
	register __typeof__(__d) x3 __asm__("x3") = __d;		\
									\
	__do_syscallN("r" (x8), "0" (x0), "r" (x1), "r" (x2), "r" (x3));\
})

#define __do_syscall5(__n, __a, __b, __c, __d, __e) ({			\
	register long x8 __asm__("x8") = __n;				\
	register __typeof__(__a) x0 __asm__("x0") = __a;		\
	register __typeof__(__b) x1 __asm__("x1") = __b;		\
	register __typeof__(__c) x2 __asm__("x2") = __c;		\
	register __typeof__(__d) x3 __asm__("x3") = __d;		\
	register __typeof__(__e) x4 __asm__("x4") = __e;		\
									\
	__do_syscallN("r" (x8), "0" (x0), "r" (x1), "r" (x2), "r" (x3),	\
			"r"(x4));					\
})

#define __do_syscall6(__n, __a, __b, __c, __d, __e, __f) ({		\
	register long x8 __asm__("x8") = __n;				\
	register __typeof__(__a) x0 __asm__("x0") = __a;		\
	register __typeof__(__b) x1 __asm__("x1") = __b;		\
	register __typeof__(__c) x2 __asm__("x2") = __c;		\
	register __typeof__(__d) x3 __asm__("x3") = __d;		\
	register __typeof__(__e) x4 __asm__("x4") = __e;		\
	register __typeof__(__f) x5 __asm__("x5") = __f;		\
									\
	__do_syscallN("r" (x8), "0" (x0), "r" (x1), "r" (x2), "r" (x3),	\
			"r" (x4), "r"(x5));				\
})


static inline void *__sys_mmap(void *addr, size_t length, int prot, int flags,
			       int fd, off_t offset)
{
	return (void *) __do_syscall6(__NR_mmap, addr, length, prot, flags, fd,
				      offset);
}

static inline int __sys_munmap(void *addr, size_t length)
{
	return (int) __do_syscall2(__NR_munmap, addr, length);
}

static inline int __sys_madvise(void *addr, size_t length, int advice)
{
	return (int) __do_syscall3(__NR_madvise, addr, length, advice);
}

static inline int __sys_getrlimit(int resource, struct rlimit *rlim)
{
	return (int) __do_syscall2(__NR_getrlimit, resource, rlim);
}

static inline int __sys_setrlimit(int resource, const struct rlimit *rlim)
{
	return (int) __do_syscall2(__NR_setrlimit, resource, rlim);
}

static inline int __sys_close(int fd)
{
	return (int) __do_syscall1(__NR_close, fd);
}

static inline int ____sys_io_uring_register(int fd, unsigned opcode,
					    const void *arg, unsigned nr_args)
{
	return (int) __do_syscall4(__NR_io_uring_register, fd, opcode, arg,
				   nr_args);
}

static inline int ____sys_io_uring_setup(unsigned entries,
					 struct io_uring_params *p)
{
	return (int) __do_syscall2(__NR_io_uring_setup, entries, p);
}

static inline int ____sys_io_uring_enter2(int fd, unsigned to_submit,
					  unsigned min_complete, unsigned flags,
					  sigset_t *sig, int sz)
{
	return (int) __do_syscall6(__NR_io_uring_enter, fd, to_submit,
				   min_complete, flags, sig, sz);
}

static inline int ____sys_io_uring_enter(int fd, unsigned to_submit,
					 unsigned min_complete, unsigned flags,
					 sigset_t *sig)
{
	return ____sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
				       _NSIG / 8);
}

#else /* #if defined(__aarch64__) */

#include "../generic/syscall.h"

#endif /* #if defined(__aarch64__) */

#endif /* #ifndef LIBURING_ARCH_AARCH64_SYSCALL_H */
