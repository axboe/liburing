/* SPDX-License-Identifier: MIT */
/*
 * Description: exercise the kernel-read argument spans of io_uring_enter()
 * and io_uring_enter2() with a definitely-invalid ring fd. The wrappers
 * sanitize the argument span before issuing the syscall, so a fully
 * initialized sigset must come back as a plain -EBADF rather than a
 * sanitizer abort under --enable-sanitizer builds, and the
 * IORING_ENTER_EXT_ARG_REG path must not treat its offset argument as a
 * pointer.
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "helpers.h"
#include "liburing.h"

static int bad_fd(void)
{
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0) {
                fprintf(stderr, "socket: %s\n", strerror(errno));
                return -1;
        }
        close(fd);
        return fd;
}

int main(int argc, char *argv[])
{
        sigset_t sig;
        int fd, ret;

        if (argc > 1) {
                fprintf(stderr, "unexpected argument\n");
                return T_EXIT_FAIL;
        }

        fd = bad_fd();
        if (fd < 0)
                return T_EXIT_FAIL;

        sigemptyset(&sig);
        sigaddset(&sig, SIGUSR1);

        /* io_uring_enter(): the sigset span is checked, the fd is not. */
        ret = io_uring_enter(fd, 0, 0, 0, &sig);
        if (ret != -EBADF) {
                fprintf(stderr, "enter: got %d, wanted -EBADF\n", ret);
                return T_EXIT_FAIL;
        }

        /* io_uring_enter2(): same, through the arg/sz pair. */
        ret = io_uring_enter2(fd, 0, 0, 0, &sig, sizeof(sig));
        if (ret != -EBADF) {
                fprintf(stderr, "enter2: got %d, wanted -EBADF\n", ret);
                return T_EXIT_FAIL;
        }

        /*
         * IORING_ENTER_EXT_ARG_REG: 'arg' is a registered wait region offset
         * and must not be dereferenced. Any value must reach the syscall
         * untouched: the invalid fd turns it into -EBADF, while kernels that
         * predate the flag reject the flag itself with -EINVAL. Either way
         * the bogus offset never gets dereferenced along the way.
         */
        ret = io_uring_enter2(fd, 0, 0, IORING_ENTER_EXT_ARG_REG,
                              (void *)(uintptr_t)0xdeadbeef, 8);
        if (ret != -EBADF && ret != -EINVAL) {
                fprintf(stderr, "enter2(ext-arg-reg): got %d\n", ret);
                return T_EXIT_FAIL;
        }

        return T_EXIT_PASS;
}
