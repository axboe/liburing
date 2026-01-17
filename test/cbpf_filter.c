/* SPDX-License-Identifier: MIT */
/*
 * Test classic BPF (cBPF) filtering for io_uring operations.
 *
 * This test demonstrates using cBPF filters to restrict io_uring operations.
 * Unlike eBPF which requires a separate compiled program, cBPF filters can
 * be defined inline as an array of sock_filter instructions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/filter.h>

#include "liburing.h"
#include "liburing/io_uring/bpf_filter.h"
#include "helpers.h"

/*
 * cBPF filter context layout (struct io_uring_bpf_ctx):
 *   offset 0:  opcode (u8)
 *   offset 1:  sqe_flags (u8)
 *   offset 2:  pdu_size (u8)
 *   offset 3:  pad[5]
 *   offset 8:  user_data (u64)
 *   offset 16: union (socket: family/type/protocol at 16/20/24)
 */
#define CTX_OFF_OPCODE		0
#define CTX_OFF_SQE_FLAGS	1
#define CTX_OFF_USER_DATA	8
#define CTX_OFF_SOCKET_FAMILY	16
#define CTX_OFF_SOCKET_TYPE	20
#define CTX_OFF_SOCKET_PROTO	24

/*
 * Simple cBPF filter that allows all operations.
 * Returns 1 (non-zero) to allow.
 */
static struct sock_filter allow_all_filter[] = {
	/* return 1 (allow) */
	BPF_STMT(BPF_RET | BPF_K, 1),
};

/*
 * Simple cBPF filter that denies all operations.
 * Returns 0 to deny.
 */
static struct sock_filter deny_all_filter[] = {
	/* return 0 (deny) */
	BPF_STMT(BPF_RET | BPF_K, 0),
};

/*
 * cBPF filter that only allows AF_INET sockets (denies AF_INET6, etc).
 * Checks the socket family field in the context.
 */
static struct sock_filter allow_inet_only_filter[] = {
	/* Load socket family (32-bit at offset 16) */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, CTX_OFF_SOCKET_FAMILY),
	/* Jump if family == AF_INET (2), allow; else deny */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 1),
	/* Allow: return 1 */
	BPF_STMT(BPF_RET | BPF_K, 1),
	/* Deny: return 0 */
	BPF_STMT(BPF_RET | BPF_K, 0),
};

/*
 * cBPF filter that only allows TCP sockets (SOCK_STREAM).
 */
static struct sock_filter allow_tcp_only_filter[] = {
	/* Load socket type (32-bit at offset 20) */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, CTX_OFF_SOCKET_TYPE),
	/* Mask off SOCK_CLOEXEC/SOCK_NONBLOCK flags */
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
	/* Jump if type == SOCK_STREAM (1), allow; else deny */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 0, 1),
	/* Allow: return 1 */
	BPF_STMT(BPF_RET | BPF_K, 1),
	/* Deny: return 0 */
	BPF_STMT(BPF_RET | BPF_K, 0),
};

/* Register a BPF filter with io_uring */
static int register_bpf_filter(struct sock_filter *filter, unsigned int len,
			       __u32 opcode, int deny_rest)
{
	unsigned int flags = deny_rest ? IO_URING_BPF_FILTER_DENY_REST : 0;

	return io_uring_register_bpf_filter_task(filter, len, opcode, flags);
}

/* Test NOP operation */
static int test_nop(struct io_uring *ring, const char *desc, int should_succeed)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		printf("FAIL (get_sqe)\n");
		return -1;
	}

	io_uring_prep_nop(sqe);
	sqe->user_data = 0x1234;

	ret = io_uring_submit(ring);
	if (ret < 0) {
		printf("FAIL (submit: %s)\n", strerror(-ret));
		return ret;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		printf("FAIL (wait: %s)\n", strerror(-ret));
		return ret;
	}

	if (should_succeed) {
		if (cqe->res >= 0) {
			ret = 0;
		} else {
			printf("FAIL (expected success, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		}
	} else {
		if (cqe->res == -EACCES) {
			ret = 0;
		} else {
			printf("FAIL (expected -EACCES, got %d)\n", cqe->res);
			ret = -1;
		}
	}

	if (ret)
		fprintf(stderr, "%s: %s: failed\n", __FUNCTION__, desc);
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

/* Test socket operation */
static int test_socket(struct io_uring *ring, int family, int type,
		       const char *desc, int should_succeed)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_socket(sqe, family, type, 0, 0);
	sqe->user_data = 0x5678;

	ret = io_uring_submit(ring);
	if (ret < 0) {
		printf("FAIL (submit: %s)\n", strerror(-ret));
		return ret;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		printf("FAIL (wait: %s)\n", strerror(-ret));
		return ret;
	}

	if (should_succeed) {
		if (cqe->res >= 0) {
			close(cqe->res);
			ret = 0;
		} else {
			printf("FAIL (expected success, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		}
	} else {
		if (cqe->res == -EACCES) {
			ret = 0;
		} else if (cqe->res < 0) {
			printf("FAIL (expected -EACCES, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		} else {
			printf("FAIL (expected denial, got fd=%d)\n", cqe->res);
			close(cqe->res);
			ret = -1;
		}
	}

	if (ret)
		fprintf(stderr, "%s: %s: failed\n", __FUNCTION__, desc);
	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int test_deny_nop(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	/* Fork to get fresh task restrictions */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* Child process */
		ret = register_bpf_filter(deny_all_filter,
					  sizeof(deny_all_filter) / sizeof(deny_all_filter[0]),
					  IORING_OP_NOP, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: register failed\n");
			exit(ret == -EINVAL ? 0 : 1);
		}

		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init failed\n");
			exit(1);
		}

		if (test_nop(&ring, "NOP should be denied", 0) != 0)
			failed++;

		io_uring_queue_exit(&ring);
		exit(failed);
	}

	/* Parent waits for child */
	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

static int test_allow_inet_only(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	/* Fork to get fresh task restrictions */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* Child process */
		ret = register_bpf_filter(allow_inet_only_filter,
					   sizeof(allow_inet_only_filter) / sizeof(allow_inet_only_filter[0]),
					   IORING_OP_SOCKET, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: register failed\n");
			exit(ret == -EINVAL ? 0 : 1);
		}

		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init failed\n");
			exit(1);
		}

		if (test_socket(&ring, AF_INET, SOCK_STREAM,
				"AF_INET TCP should succeed", 1) != 0)
			failed++;

		if (test_socket(&ring, AF_INET6, SOCK_STREAM,
				"AF_INET6 TCP should be denied", 0) != 0)
			failed++;

		if (test_socket(&ring, AF_UNIX, SOCK_STREAM,
				"AF_UNIX should be denied", 0) != 0)
			failed++;

		io_uring_queue_exit(&ring);
		exit(failed);
	}

	/* Parent waits for child */
	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

static int test_allow_tcp_only(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		ret = register_bpf_filter(allow_tcp_only_filter,
					   sizeof(allow_tcp_only_filter) / sizeof(allow_tcp_only_filter[0]),
					   IORING_OP_SOCKET, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: register failed\n");
			exit(ret == -EINVAL ? 0 : 1);
		}

		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init failed\n");
			exit(1);
		}

		if (test_socket(&ring, AF_INET, SOCK_STREAM,
				"TCP should succeed", 1) != 0)
			failed++;

		if (test_socket(&ring, AF_INET, SOCK_DGRAM,
				"UDP should be denied", 0) != 0)
			failed++;

		if (test_socket(&ring, AF_INET6, SOCK_STREAM,
				"IPv6 TCP should succeed", 1) != 0)
			failed++;

		io_uring_queue_exit(&ring);
		exit(failed);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

static int test_deny_rest(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* Register allow filter for NOP with DENY_REST flag */
		ret = register_bpf_filter(allow_all_filter,
					   sizeof(allow_all_filter) / sizeof(allow_all_filter[0]),
					   IORING_OP_NOP,
					   1);  /* deny_rest = true */
		if (ret < 0) {
			fprintf(stderr, "Child: register failed\n");
			exit(ret == -EINVAL ? 0 : 1);
		}

		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init failed\n");
			exit(1);
		}

		if (test_nop(&ring, "NOP should succeed", 1) != 0)
			failed++;

		if (test_socket(&ring, AF_INET, SOCK_STREAM,
				"Socket should be denied (DENY_REST)", 0) != 0)
			failed++;

		io_uring_queue_exit(&ring);
		exit(failed);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

/*
 * Test that child processes inherit parent's restrictions.
 * Parent registers a filter, forks, child verifies the restriction applies.
 */
static int test_inherit_restrictions(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* First child: register deny filter for NOP, then fork */
		ret = register_bpf_filter(deny_all_filter,
					  sizeof(deny_all_filter) / sizeof(deny_all_filter[0]),
					  IORING_OP_NOP, 0);
		if (ret < 0) {
			fprintf(stderr, "Child1: register failed: %s\n",
				strerror(-ret));
			exit(1);
		}

		/* Fork grandchild to test inheritance */
		pid_t grandchild = fork();
		if (grandchild < 0) {
			perror("fork grandchild");
			exit(1);
		}

		if (grandchild == 0) {
			/* Grandchild: should inherit parent's NOP denial */
			ret = io_uring_queue_init(8, &ring, 0);
			if (ret < 0) {
				fprintf(stderr, "Grandchild: queue_init failed\n");
				exit(1);
			}

			/* NOP should be denied due to inherited restriction */
			if (test_nop(&ring, "inherited NOP denial", 0) != 0)
				failed++;

			io_uring_queue_exit(&ring);
			exit(failed);
		}

		waitpid(grandchild, &status, 0);
		exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

/*
 * Test that child can add new restrictions on top of inherited ones.
 * Parent allows only AF_INET, child adds TCP-only filter.
 * Result: only AF_INET + TCP should be allowed.
 */
static int test_stack_restrictions(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* First child: register AF_INET only filter */
		ret = register_bpf_filter(allow_inet_only_filter,
					  sizeof(allow_inet_only_filter) / sizeof(allow_inet_only_filter[0]),
					  IORING_OP_SOCKET, 0);
		if (ret < 0) {
			fprintf(stderr, "Child1: register failed: %s\n",
				strerror(-ret));
			exit(1);
		}

		/* Fork grandchild to add more restrictions */
		pid_t grandchild = fork();
		if (grandchild < 0) {
			perror("fork grandchild");
			exit(1);
		}

		if (grandchild == 0) {
			/* Grandchild: add TCP-only filter on top */
			ret = register_bpf_filter(allow_tcp_only_filter,
						  sizeof(allow_tcp_only_filter) / sizeof(allow_tcp_only_filter[0]),
						  IORING_OP_SOCKET, 0);
			if (ret < 0) {
				fprintf(stderr, "Grandchild: register failed: %s\n",
					strerror(-ret));
				exit(1);
			}

			ret = io_uring_queue_init(8, &ring, 0);
			if (ret < 0) {
				fprintf(stderr, "Grandchild: queue_init failed\n");
				exit(1);
			}

			/* AF_INET + TCP: allowed by both filters */
			if (test_socket(&ring, AF_INET, SOCK_STREAM,
					"AF_INET TCP (both filters allow)", 1) != 0)
				failed++;

			/* AF_INET + UDP: allowed by parent, denied by child */
			if (test_socket(&ring, AF_INET, SOCK_DGRAM,
					"AF_INET UDP (child denies)", 0) != 0)
				failed++;

			/* AF_INET6 + TCP: denied by parent, allowed by child */
			if (test_socket(&ring, AF_INET6, SOCK_STREAM,
					"AF_INET6 TCP (parent denies)", 0) != 0)
				failed++;

			io_uring_queue_exit(&ring);
			exit(failed);
		}

		waitpid(grandchild, &status, 0);
		exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

/*
 * Test that child cannot loosen parent's restrictions.
 * Parent denies NOP, child tries to allow it - should still be denied.
 */
static int test_cannot_loosen_restrictions(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* First child: deny NOP */
		ret = register_bpf_filter(deny_all_filter,
					  sizeof(deny_all_filter) / sizeof(deny_all_filter[0]),
					  IORING_OP_NOP, 0);
		if (ret < 0) {
			fprintf(stderr, "Child1: register failed: %s\n",
				strerror(-ret));
			exit(1);
		}

		/* Fork grandchild that tries to allow NOP */
		pid_t grandchild = fork();
		if (grandchild < 0) {
			perror("fork grandchild");
			exit(1);
		}

		if (grandchild == 0) {
			/* Grandchild: try to allow NOP (should not work) */
			ret = register_bpf_filter(allow_all_filter,
						  sizeof(allow_all_filter) / sizeof(allow_all_filter[0]),
						  IORING_OP_NOP, 0);
			if (ret < 0) {
				fprintf(stderr, "Grandchild: register failed: %s\n",
					strerror(-ret));
				exit(1);
			}

			ret = io_uring_queue_init(8, &ring, 0);
			if (ret < 0) {
				fprintf(stderr, "Grandchild: queue_init failed\n");
				exit(1);
			}

			/*
			 * NOP should still be denied - child's allow filter
			 * runs first (returns 1), but parent's deny filter
			 * is stacked and runs second (returns 0).
			 */
			if (test_nop(&ring, "NOP still denied (can't loosen)", 0) != 0)
				failed++;

			io_uring_queue_exit(&ring);
			exit(failed);
		}

		waitpid(grandchild, &status, 0);
		exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

/*
 * Test multi-level inheritance (parent -> child -> grandchild -> great-grandchild).
 * Each level adds more restrictions.
 */
static int test_multi_level_inherit(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* Level 1: allow only AF_INET for sockets */
		ret = register_bpf_filter(allow_inet_only_filter,
					  sizeof(allow_inet_only_filter) / sizeof(allow_inet_only_filter[0]),
					  IORING_OP_SOCKET, 0);
		if (ret < 0) {
			fprintf(stderr, "Level1: register failed\n");
			exit(1);
		}

		pid_t level2 = fork();
		if (level2 < 0)
			exit(1);

		if (level2 == 0) {
			/* Level 2: add TCP-only restriction */
			ret = register_bpf_filter(allow_tcp_only_filter,
						  sizeof(allow_tcp_only_filter) / sizeof(allow_tcp_only_filter[0]),
						  IORING_OP_SOCKET, 0);
			if (ret < 0) {
				fprintf(stderr, "Level2: register failed\n");
				exit(1);
			}

			pid_t level3 = fork();
			if (level3 < 0)
				exit(1);

			if (level3 == 0) {
				/* Level 3: allow NOP with DENY_REST */
				ret = register_bpf_filter(allow_all_filter,
							  sizeof(allow_all_filter) / sizeof(allow_all_filter[0]),
							  IORING_OP_NOP, 1);
				if (ret < 0) {
					fprintf(stderr, "Level3: register failed\n");
					exit(1);
				}

				ret = io_uring_queue_init(8, &ring, 0);
				if (ret < 0) {
					fprintf(stderr, "Level3: queue_init failed\n");
					exit(1);
				}

				/* NOP: allowed (explicit filter) */
				if (test_nop(&ring, "NOP allowed", 1) != 0)
					failed++;

				/*
				 * Socket still governed by inherited filters.
				 * DENY_REST only denies opcodes with no filter
				 * in the entire chain - ancestors have socket
				 * filters so those still apply.
				 *
				 * AF_INET + TCP: allowed by both ancestors
				 */
				if (test_socket(&ring, AF_INET, SOCK_STREAM,
						"AF_INET TCP (inherited filters)", 1) != 0)
					failed++;

				/* AF_INET + UDP: denied by Level 2's TCP filter */
				if (test_socket(&ring, AF_INET, SOCK_DGRAM,
						"AF_INET UDP (denied by L2)", 0) != 0)
					failed++;

				/* AF_INET6 + TCP: denied by Level 1's AF_INET filter */
				if (test_socket(&ring, AF_INET6, SOCK_STREAM,
						"AF_INET6 TCP (denied by L1)", 0) != 0)
					failed++;

				io_uring_queue_exit(&ring);
				exit(failed);
			}

			waitpid(level3, &status, 0);
			exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
		}

		waitpid(level2, &status, 0);
		exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

static int probe_bpf_filter_support(void)
{
	struct io_uring_bpf io_bpf = {
		.cmd_type = IO_URING_BPF_CMD_FILTER,
		.filter = {
			.opcode = IORING_OP_NOP,
			.flags = 0,
			.filter_len = sizeof(allow_all_filter) / sizeof(allow_all_filter[0]),
			.filter_ptr = (unsigned long)allow_all_filter,
		},
	};
	pid_t pid;
	int status;

	/* Fork so we don't pollute the main process */
	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		int ret = io_uring_register(-1, IORING_REGISTER_BPF_FILTER,
					    &io_bpf, 1);
		exit(ret < 0 ? -ret : 0);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		if (code == EINVAL || code == ENOSYS)
			return -1;  /* Not supported */
		return 0;  /* Supported (or other error we'll catch later) */
	}
	return -1;
}

int main(int argc, char *argv[])
{
	int total_failed = 0;

	if (argc > 1)
		return T_EXIT_SKIP;

	if (probe_bpf_filter_support() < 0)
		return T_EXIT_SKIP;

	total_failed += test_deny_nop();
	total_failed += test_allow_inet_only();
	total_failed += test_allow_tcp_only();
	total_failed += test_deny_rest();

	/* Per-task inheritance tests */
	total_failed += test_inherit_restrictions();
	total_failed += test_stack_restrictions();
	total_failed += test_cannot_loosen_restrictions();
	total_failed += test_multi_level_inherit();

	return total_failed;
}
