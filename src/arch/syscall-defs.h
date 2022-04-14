/* SPDX-License-Identifier: MIT */

#ifndef LIBURING_ARCH_SYSCALL_DEFS_H
#define LIBURING_ARCH_SYSCALL_DEFS_H

static inline void *__sys_mmap(void *addr, size_t length, int prot, int flags,
			       int fd, off_t offset)
{
	int nr;

#if defined(__i386__)
	nr = __NR_mmap2;
	offset >>= 12;
#else
	nr = __NR_mmap;
#endif
	return (void *) __do_syscall6(nr, addr, length, prot, flags, fd, offset);
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

#endif
