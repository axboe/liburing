/* SPDX-License-Identifier: MIT */
/*
 * Description: test that per-task io_uring restrictions survive exec
 *
 * Per-task restrictions must keep applying to rings created after exec,
 * including when the task already used io_uring before exec. Kernels
 * before "io_uring: preserve task restrictions across exec" freed the
 * restrictions together with the task context on exec, so the new image
 * could create unrestricted rings.
 *
 * The test registers restrictions in a child, optionally uses a ring, and
 * re-execs itself; the new image checks that a fresh ring is still
 * restricted. Both the opcode allowlist and a BPF filter are covered.
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/filter.h>

#include "liburing.h"
#include "liburing/io_uring/bpf_filter.h"
#include "helpers.h"
#include "../src/syscall.h"

/* Set in the environment of the re-exec'd image. */
#define EXEC_CHILD_ENV	"LIBURING_TASK_RESTRICT_EXEC_CHILD"

static int register_task_restrictions(struct io_uring_restriction *res,
				      unsigned int nr_res)
{
	struct {
		__u16 flags;
		__u16 nr_res;
		__u32 resv[3];
		struct io_uring_restriction restrictions[];
	} *arg;
	size_t sz;
	int ret;

	sz = sizeof(*arg) + nr_res * sizeof(struct io_uring_restriction);
	arg = calloc(1, sz);
	if (!arg)
		return -ENOMEM;

	arg->nr_res = nr_res;
	memcpy(arg->restrictions, res, nr_res * sizeof(*res));

	ret = __sys_io_uring_register(-1, IORING_REGISTER_RESTRICTIONS, arg, 1);
	free(arg);
	return ret;
}

/* Allow only NOP, as an opcode allowlist */
static int restrict_to_nop_allowlist(void)
{
	struct io_uring_restriction res = {
		.opcode = IORING_RESTRICTION_SQE_OP,
		.sqe_op = IORING_OP_NOP,
	};

	return register_task_restrictions(&res, 1);
}

/* Allow only NOP, as a BPF filter on NOP that denies every other opcode */
static int restrict_to_nop_bpf(void)
{
	struct sock_filter allow[] = {
		BPF_STMT(BPF_RET | BPF_K, 1),
	};
	struct io_uring_bpf bpf = {
		.cmd_type = IO_URING_BPF_CMD_FILTER,
		.filter = {
			.opcode = IORING_OP_NOP,
			.flags = IO_URING_BPF_FILTER_DENY_REST,
			.filter_len = 1,
			.filter_ptr = (unsigned long) (uintptr_t) allow,
		},
	};

	return io_uring_register_bpf_filter_task(&bpf);
}

/* Submit the prepared SQE on @ring and return its result */
static int submit_one(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_submit(ring);
	if (ret != 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return -1000;
	}
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret) {
		fprintf(stderr, "wait: %d\n", ret);
		return -1000;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

/* Use io_uring in this task: set up a ring and run a NOP on it */
static int use_ring(void)
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	int ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup before exec: %d\n", ret);
		return T_EXIT_FAIL;
	}
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	ret = submit_one(&ring);
	io_uring_queue_exit(&ring);
	if (ret) {
		fprintf(stderr, "nop before exec: %d\n", ret);
		return T_EXIT_FAIL;
	}
	return T_EXIT_PASS;
}

/* In the re-exec'd image: a fresh ring must still deny anything but NOP */
static int exec_child(void)
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	int ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup after exec: %d\n", ret);
		return T_EXIT_FAIL;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	ret = submit_one(&ring);
	if (ret) {
		fprintf(stderr, "nop after exec: %d (expected 0)\n", ret);
		goto fail;
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read(sqe, 0, NULL, 0, 0);
	ret = submit_one(&ring);
	if (ret != -EACCES) {
		fprintf(stderr, "read after exec: %d (expected -EACCES): "
				"restrictions were dropped on exec\n", ret);
		goto fail;
	}

	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
fail:
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

/*
 * Restrict a child to NOP, optionally use a ring, then exec this test
 * again with EXEC_CHILD_ENV set and return the exec'd image's verdict.
 */
static int test_exec(int bpf, int ring_before_exec)
{
	int status, ret;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return T_EXIT_FAIL;
	}

	if (pid == 0) {
		/* Like seccomp, needs no_new_privs without CAP_SYS_ADMIN */
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

		ret = bpf ? restrict_to_nop_bpf() : restrict_to_nop_allowlist();
		if (ret == -EINVAL || ret == -EBADF)
			_exit(T_EXIT_SKIP);
		if (ret) {
			fprintf(stderr, "register restrictions: %d\n", ret);
			_exit(T_EXIT_FAIL);
		}

		if (ring_before_exec && use_ring() != T_EXIT_PASS)
			_exit(T_EXIT_FAIL);

		setenv(EXEC_CHILD_ENV, "1", 1);
		execl("/proc/self/exe", "/proc/self/exe", (char *) NULL);
		perror("exec");
		_exit(T_EXIT_FAIL);
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return T_EXIT_FAIL;
	}
	if (!WIFEXITED(status))
		return T_EXIT_FAIL;
	return WEXITSTATUS(status);
}

int main(int argc, char *argv[])
{
	int bpf, ring_before_exec, ret, ran = 0;

	if (getenv(EXEC_CHILD_ENV))
		return exec_child();
	if (argc > 1)
		return T_EXIT_SKIP;

	for (bpf = 0; bpf <= 1; bpf++) {
		for (ring_before_exec = 0; ring_before_exec <= 1; ring_before_exec++) {
			ret = test_exec(bpf, ring_before_exec);
			if (ret == T_EXIT_SKIP)
				continue;
			if (ret != T_EXIT_PASS) {
				fprintf(stderr, "test_exec(%s, ring_before_exec=%d) failed\n",
					bpf ? "bpf" : "allowlist", ring_before_exec);
				return T_EXIT_FAIL;
			}
			ran++;
		}
	}

	if (!ran) {
		printf("Per-task restrictions not supported, skipping\n");
		return T_EXIT_SKIP;
	}
	return T_EXIT_PASS;
}
