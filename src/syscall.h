/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_SYSCALL_H
#define LIBURING_SYSCALL_H

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#ifdef __alpha__
/*
 * alpha and mips are exception, other architectures have
 * common numbers for new system calls.
 */
# ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup		535
# endif
# ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter		536
# endif
# ifndef __NR_io_uring_register
#  define __NR_io_uring_register	537
# endif
#elif defined __mips__
# ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup           (__NR_Linux + 425)
# endif
# ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter           (__NR_Linux + 426)
# endif
# ifndef __NR_io_uring_register
#  define __NR_io_uring_register        (__NR_Linux + 427)
# endif
#else /* !__alpha__ and !__mips__ */
# ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup		425
# endif
# ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter		426
# endif
# ifndef __NR_io_uring_register
#  define __NR_io_uring_register	427
# endif
#endif


struct io_uring_params;

/*
 * System calls
 */
int __sys_io_uring_setup(unsigned entries, struct io_uring_params *p);
int __sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
			 unsigned flags, sigset_t *sig);
int __sys_io_uring_enter2(int fd, unsigned to_submit, unsigned min_complete,
			  unsigned flags, sigset_t *sig, int sz);
int __sys_io_uring_register(int fd, unsigned int opcode, const void *arg,
			    unsigned int nr_args);



static inline int ____sys_io_uring_register(int fd, unsigned opcode,
					    const void *arg, unsigned nr_args)
{
	int ret;

	ret = syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
	return (ret < 0) ? -errno : ret;
}

static inline int ____sys_io_uring_setup(unsigned entries,
					 struct io_uring_params *p)
{
	int ret;

	ret = syscall(__NR_io_uring_setup, entries, p);
	return (ret < 0) ? -errno : ret;
}

static inline int ____sys_io_uring_enter2(int fd, unsigned to_submit,
					  unsigned min_complete, unsigned flags,
					  sigset_t *sig, int sz)
{
	int ret;

	ret = syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
		      sig, sz);
	return (ret < 0) ? -errno : ret;
}

static inline int ____sys_io_uring_enter(int fd, unsigned to_submit,
					 unsigned min_complete, unsigned flags,
					 sigset_t *sig)
{
	return ____sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
				       _NSIG / 8);
}

#endif
