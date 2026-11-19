/* SPDX-License-Identifier: MIT */

#include "syscall.h"
#include <liburing.h>
#include "liburing/sanitize.h"

int io_uring_enter(unsigned int fd, unsigned int to_submit,
                   unsigned int min_complete, unsigned int flags, sigset_t *sig)
{
        /* The kernel copies _NSIG/8 bytes from 'sig' (see the
         * __sys_io_uring_enter() wrappers), so check exactly that span. */
        if (sig)
                liburing_sanitize_region(sig, _NSIG / 8);

        return __sys_io_uring_enter(fd, to_submit, min_complete, flags, sig);
}

int io_uring_enter2(unsigned int fd, unsigned int to_submit,
                    unsigned int min_complete, unsigned int flags,
                    void *arg, size_t sz)
{
        /* With IORING_ENTER_EXT_ARG_REG 'arg' carries a registered wait
         * region offset, not a pointer: it must not be dereferenced here. */
        if (arg && !(flags & IORING_ENTER_EXT_ARG_REG))
                liburing_sanitize_region(arg, sz);

        return __sys_io_uring_enter2(fd, to_submit, min_complete, flags, arg,
                                     sz);
}

int io_uring_setup(unsigned int entries, struct io_uring_params *p)
{
        return __sys_io_uring_setup(entries, p);
}

int io_uring_register(unsigned int fd, unsigned int opcode, const void *arg,
                      unsigned int nr_args)
{
        return __sys_io_uring_register(fd, opcode, arg, nr_args);
}
