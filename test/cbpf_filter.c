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
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/openat2.h>

#include "liburing.h"
#include "liburing/io_uring/bpf_filter.h"
#include "helpers.h"

/*
 * cBPF filter context layout (struct io_uring_bpf_ctx):
 *   offset 0:  user_data (u64)
 *   offset 8:  opcode (u8)
 *   offset 9:  sqe_flags (u8)
 *   offset 10: pdu_size (u8)
 *   offset 11: pad[5]
 *   offset 16: union (socket: family/type/protocol at 16/20/24)
 *                    (open: flags/mode/resolve at 16/24/32 - all u64)
 */
#define CTX_OFF_USER_DATA	0
#define CTX_OFF_OPCODE		8
#define CTX_OFF_SQE_FLAGS	9
#define CTX_OFF_SOCKET_FAMILY	16
#define CTX_OFF_SOCKET_TYPE	20
#define CTX_OFF_SOCKET_PROTO	24
#define CTX_OFF_OPEN_FLAGS	16	/* u64, use low 32 bits */
#define CTX_OFF_OPEN_MODE	24	/* u64 */
#define CTX_OFF_OPEN_RESOLVE	32	/* u64, use low 32 bits */

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

/*
 * cBPF filter that denies O_CREAT flag for openat operations.
 * Checks the flags field in the open context.
 */
static struct sock_filter deny_o_creat_filter[] = {
	/* Load open flags (low 32 bits at offset 16) */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, CTX_OFF_OPEN_FLAGS),
	/* Check if O_CREAT bit is set */
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_CREAT),
	/* If result is non-zero (O_CREAT set), deny */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
	/* Deny: return 0 */
	BPF_STMT(BPF_RET | BPF_K, 0),
	/* Allow: return 1 */
	BPF_STMT(BPF_RET | BPF_K, 1),
};

/*
 * cBPF filter that denies RESOLVE_IN_ROOT flag for openat2 operations.
 * Checks the resolve field in the open context.
 */
static struct sock_filter deny_resolve_in_root_filter[] = {
	/* Load resolve flags (low 32 bits at offset 32) */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, CTX_OFF_OPEN_RESOLVE),
	/* Check if RESOLVE_IN_ROOT bit is set */
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, RESOLVE_IN_ROOT),
	/* If result is non-zero (RESOLVE_IN_ROOT set), deny */
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
	/* Deny: return 0 */
	BPF_STMT(BPF_RET | BPF_K, 0),
	/* Allow: return 1 */
	BPF_STMT(BPF_RET | BPF_K, 1),
};

/* Register a BPF filter on a task */
static int register_bpf_filter(struct sock_filter *filter, unsigned int len,
			       __u32 opcode, __u8 pdu_size, int deny_rest)
{
	struct io_uring_bpf bpf = {
		.cmd_type = IO_URING_BPF_CMD_FILTER,
		.filter = {
			.opcode = opcode,
			.flags = deny_rest ? IO_URING_BPF_FILTER_DENY_REST : 0,
			.filter_len = len,
			.filter_ptr = (unsigned long) (uintptr_t) filter,
			.pdu_size = pdu_size,
		},
	};

	return io_uring_register_bpf_filter_task(&bpf);
}

/* Register a BPF filter on a ring */
static int register_bpf_filter_ring(struct io_uring *ring,
				    struct sock_filter *filter, unsigned int len,
				    __u32 opcode, __u8 pdu_size, int deny_rest)
{
	struct io_uring_bpf bpf = {
		.cmd_type = IO_URING_BPF_CMD_FILTER,
		.filter = {
			.opcode = opcode,
			.flags = deny_rest ? IO_URING_BPF_FILTER_DENY_REST : 0,
			.filter_len = len,
			.filter_ptr = (unsigned long) (uintptr_t) filter,
			.pdu_size = pdu_size,
		},
	};

	return io_uring_register_bpf_filter(ring, &bpf);
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

/* Test openat operation */
static int test_openat(struct io_uring *ring, const char *path, int flags,
		       mode_t mode, const char *desc, int should_succeed)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_openat(sqe, AT_FDCWD, path, flags, mode);
	sqe->user_data = 0xabcd;

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

/* Test openat2 operation */
static int test_openat2(struct io_uring *ring, const char *path,
			struct open_how *how, const char *desc,
			int should_succeed)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_openat2(sqe, AT_FDCWD, path, how);
	sqe->user_data = 0xef01;

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
					  IORING_OP_NOP, 0, 0);
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
					   IORING_OP_SOCKET, 12, 0);
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
					   IORING_OP_SOCKET, 12, 0);
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
					   IORING_OP_NOP, 0,
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
 * Test denying O_CREAT flag for IORING_OP_OPENAT.
 * Verifies the operation works before filter installation,
 * then fails with -EACCES after.
 */
static int test_deny_openat_creat(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;
	char tmpfile[] = "/tmp/cbpf_test_XXXXXX";
	int tmpfd;

	/* Create a temp file path we can use for testing */
	tmpfd = mkstemp(tmpfile);
	if (tmpfd < 0) {
		perror("mkstemp");
		return 1;
	}
	close(tmpfd);
	unlink(tmpfile);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* Test that O_CREAT works BEFORE installing filter */
		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init failed\n");
			exit(1);
		}

		if (test_openat(&ring, tmpfile, O_CREAT | O_RDWR, 0644,
				"O_CREAT should succeed before filter", 1) != 0)
			failed++;

		/* Clean up created file */
		unlink(tmpfile);

		/* Test that regular open (no O_CREAT) works */
		if (test_openat(&ring, "/dev/null", O_RDONLY, 0,
				"regular open should succeed before filter", 1) != 0)
			failed++;

		io_uring_queue_exit(&ring);

		/* Now install the O_CREAT deny filter */
		ret = register_bpf_filter(deny_o_creat_filter,
					  sizeof(deny_o_creat_filter) / sizeof(deny_o_creat_filter[0]),
					  IORING_OP_OPENAT, 24, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: register failed: %s\n",
				strerror(-ret));
			exit(ret == -EINVAL ? 0 : 1);
		}

		/* Create new ring after filter is installed */
		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init 2 failed\n");
			exit(1);
		}

		/* Test that O_CREAT is now denied */
		if (test_openat(&ring, tmpfile, O_CREAT | O_RDWR, 0644,
				"O_CREAT should be denied after filter", 0) != 0)
			failed++;

		/* Test that regular open still works */
		if (test_openat(&ring, "/dev/null", O_RDONLY, 0,
				"regular open should still succeed", 1) != 0)
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
 * Test denying RESOLVE_IN_ROOT flag for IORING_OP_OPENAT2.
 * Verifies the operation works before filter installation,
 * then fails with -EACCES after.
 *
 * Note: RESOLVE_IN_ROOT requires a relative path since it treats dfd as root.
 * We use "." with O_DIRECTORY to test this.
 */
static int test_deny_openat2_resolve_in_root(void)
{
	struct io_uring ring;
	int ret, failed = 0;
	pid_t pid;
	int status;
	struct open_how how_with_resolve = {
		.flags = O_RDONLY | O_DIRECTORY,
		.mode = 0,
		.resolve = RESOLVE_IN_ROOT,
	};
	struct open_how how_normal = {
		.flags = O_RDONLY | O_DIRECTORY,
		.mode = 0,
		.resolve = 0,
	};

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		/* Test that RESOLVE_IN_ROOT works BEFORE installing filter */
		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init failed\n");
			exit(1);
		}

		if (test_openat2(&ring, ".", &how_with_resolve,
				 "RESOLVE_IN_ROOT should succeed before filter", 1) != 0)
			failed++;

		/* Test that normal openat2 works */
		if (test_openat2(&ring, ".", &how_normal,
				 "normal openat2 should succeed before filter", 1) != 0)
			failed++;

		io_uring_queue_exit(&ring);

		/* Now install the RESOLVE_IN_ROOT deny filter */
		ret = register_bpf_filter(deny_resolve_in_root_filter,
					  sizeof(deny_resolve_in_root_filter) / sizeof(deny_resolve_in_root_filter[0]),
					  IORING_OP_OPENAT2, 24, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: register failed: %s\n",
				strerror(-ret));
			exit(ret == -EINVAL ? 0 : 1);
		}

		/* Create new ring after filter is installed */
		ret = io_uring_queue_init(8, &ring, 0);
		if (ret < 0) {
			fprintf(stderr, "Child: queue_init 2 failed\n");
			exit(1);
		}

		/* Test that RESOLVE_IN_ROOT is now denied */
		if (test_openat2(&ring, ".", &how_with_resolve,
				 "RESOLVE_IN_ROOT should be denied after filter", 0) != 0)
			failed++;

		/* Test that normal openat2 still works */
		if (test_openat2(&ring, ".", &how_normal,
				 "normal openat2 should still succeed", 1) != 0)
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
 * Ring-level filter tests - these test filters registered on a specific ring
 * rather than on the task. Ring filters don't require forking.
 */

static int test_deny_nop_ring(void)
{
	struct io_uring ring;
	int ret, failed = 0;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init failed: %s\n", strerror(-ret));
		return 1;
	}

	ret = register_bpf_filter_ring(&ring, deny_all_filter,
				       ARRAY_SIZE(deny_all_filter),
				       IORING_OP_NOP, 0, 0);
	if (ret < 0) {
		fprintf(stderr, "register failed: %s\n", strerror(-ret));
		io_uring_queue_exit(&ring);
		return ret == -EINVAL ? 0 : 1;
	}

	if (test_nop(&ring, "NOP should be denied (ring)", 0) != 0)
		failed++;

	io_uring_queue_exit(&ring);
	return failed;
}

static int test_allow_inet_only_ring(void)
{
	struct io_uring ring;
	int ret, failed = 0;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init failed: %s\n", strerror(-ret));
		return 1;
	}

	ret = register_bpf_filter_ring(&ring, allow_inet_only_filter,
				       ARRAY_SIZE(allow_inet_only_filter),
				       IORING_OP_SOCKET, 12, 0);
	if (ret < 0) {
		fprintf(stderr, "register failed: %s\n", strerror(-ret));
		io_uring_queue_exit(&ring);
		return ret == -EINVAL ? 0 : 1;
	}

	if (test_socket(&ring, AF_INET, SOCK_STREAM,
			"AF_INET TCP should succeed (ring)", 1) != 0)
		failed++;

	if (test_socket(&ring, AF_INET6, SOCK_STREAM,
			"AF_INET6 TCP should be denied (ring)", 0) != 0)
		failed++;

	if (test_socket(&ring, AF_UNIX, SOCK_STREAM,
			"AF_UNIX should be denied (ring)", 0) != 0)
		failed++;

	io_uring_queue_exit(&ring);
	return failed;
}

static int test_allow_tcp_only_ring(void)
{
	struct io_uring ring;
	int ret, failed = 0;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init failed: %s\n", strerror(-ret));
		return 1;
	}

	ret = register_bpf_filter_ring(&ring, allow_tcp_only_filter,
				       ARRAY_SIZE(allow_tcp_only_filter),
				       IORING_OP_SOCKET, 12, 0);
	if (ret < 0) {
		fprintf(stderr, "register failed: %s\n", strerror(-ret));
		io_uring_queue_exit(&ring);
		return ret == -EINVAL ? 0 : 1;
	}

	if (test_socket(&ring, AF_INET, SOCK_STREAM,
			"TCP should succeed (ring)", 1) != 0)
		failed++;

	if (test_socket(&ring, AF_INET, SOCK_DGRAM,
			"UDP should be denied (ring)", 0) != 0)
		failed++;

	if (test_socket(&ring, AF_INET6, SOCK_STREAM,
			"IPv6 TCP should succeed (ring)", 1) != 0)
		failed++;

	io_uring_queue_exit(&ring);
	return failed;
}

static int test_deny_rest_ring(void)
{
	struct io_uring ring;
	int ret, failed = 0;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init failed: %s\n", strerror(-ret));
		return 1;
	}

	/* Register allow filter for NOP with DENY_REST flag */
	ret = register_bpf_filter_ring(&ring, allow_all_filter,
				       ARRAY_SIZE(allow_all_filter),
				       IORING_OP_NOP, 0, 1);
	if (ret < 0) {
		fprintf(stderr, "register failed: %s\n", strerror(-ret));
		io_uring_queue_exit(&ring);
		return ret == -EINVAL ? 0 : 1;
	}

	if (test_nop(&ring, "NOP should succeed (ring)", 1) != 0)
		failed++;

	if (test_socket(&ring, AF_INET, SOCK_STREAM,
			"Socket should be denied DENY_REST (ring)", 0) != 0)
		failed++;

	io_uring_queue_exit(&ring);
	return failed;
}

/*
 * Test pdu_size validation for filter registration.
 *
 * IORING_OP_SOCKET has a kernel pdu_size of 12 (3x __u32). Test:
 * 1) pdu_size too big (24) - should fail with -EMSGSIZE
 * 2) pdu_size too small (8) without strict - should succeed, kernel
 *    writes back actual pdu_size (12)
 * 3) pdu_size too small (8) with IO_URING_BPF_FILTER_SZ_STRICT -
 *    should fail with -EMSGSIZE, kernel writes back actual pdu_size (12)
 */
static int test_pdu_size_ring(void)
{
	struct io_uring ring;
	struct io_uring_bpf bpf;
	int ret, failed = 0;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init failed: %s\n", strerror(-ret));
		return 1;
	}

	/* Test 1: pdu_size too big, should fail with -EMSGSIZE */
	memset(&bpf, 0, sizeof(bpf));
	bpf.cmd_type = IO_URING_BPF_CMD_FILTER;
	bpf.filter.opcode = IORING_OP_SOCKET;
	bpf.filter.filter_len = ARRAY_SIZE(allow_all_filter);
	bpf.filter.filter_ptr = (unsigned long) (uintptr_t) allow_all_filter;
	bpf.filter.pdu_size = 24;

	ret = io_uring_register_bpf_filter(&ring, &bpf);
	if (ret != -EMSGSIZE) {
		fprintf(stderr, "pdu too big: expected -EMSGSIZE, got %d\n",
			ret);
		failed++;
	} else if (bpf.filter.pdu_size != 12) {
		fprintf(stderr, "pdu too big: expected writeback 12, got %u\n",
			bpf.filter.pdu_size);
		failed++;
	}

	/* Test 2: pdu_size smaller without strict, should succeed */
	memset(&bpf, 0, sizeof(bpf));
	bpf.cmd_type = IO_URING_BPF_CMD_FILTER;
	bpf.filter.opcode = IORING_OP_SOCKET;
	bpf.filter.filter_len = ARRAY_SIZE(allow_all_filter);
	bpf.filter.filter_ptr = (unsigned long) (uintptr_t) allow_all_filter;
	bpf.filter.pdu_size = 8;

	ret = io_uring_register_bpf_filter(&ring, &bpf);
	if (ret) {
		fprintf(stderr, "pdu smaller no strict: expected success, "
			"got %d\n", ret);
		failed++;
	} else if (bpf.filter.pdu_size != 12) {
		fprintf(stderr, "pdu smaller no strict: expected writeback "
			"12, got %u\n", bpf.filter.pdu_size);
		failed++;
	}

	io_uring_queue_exit(&ring);

	/*
	 * Test 3: pdu_size smaller with strict, should fail.
	 * Use a fresh ring since test 2 registered a filter.
	 */
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init 2 failed: %s\n", strerror(-ret));
		return 1;
	}

	memset(&bpf, 0, sizeof(bpf));
	bpf.cmd_type = IO_URING_BPF_CMD_FILTER;
	bpf.filter.opcode = IORING_OP_SOCKET;
	bpf.filter.flags = IO_URING_BPF_FILTER_SZ_STRICT;
	bpf.filter.filter_len = ARRAY_SIZE(allow_all_filter);
	bpf.filter.filter_ptr = (unsigned long) (uintptr_t) allow_all_filter;
	bpf.filter.pdu_size = 8;

	ret = io_uring_register_bpf_filter(&ring, &bpf);
	if (ret != -EMSGSIZE) {
		fprintf(stderr, "pdu smaller strict: expected -EMSGSIZE, "
			"got %d\n", ret);
		failed++;
	} else if (bpf.filter.pdu_size != 12) {
		fprintf(stderr, "pdu smaller strict: expected writeback 12, "
			"got %u\n", bpf.filter.pdu_size);
		failed++;
	}

	io_uring_queue_exit(&ring);
	return failed;
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
					  IORING_OP_NOP, 0, 0);
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
					  IORING_OP_SOCKET, 12, 0);
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
						  IORING_OP_SOCKET, 12, 0);
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
					  IORING_OP_NOP, 0, 0);
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
			/* Grandchild: try to allow NOP (inherits no_new_privs) */
			ret = register_bpf_filter(allow_all_filter,
						  sizeof(allow_all_filter) / sizeof(allow_all_filter[0]),
						  IORING_OP_NOP, 0, 0);
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
					  IORING_OP_SOCKET, 12, 0);
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
						  IORING_OP_SOCKET, 12, 0);
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
							  IORING_OP_NOP, 0, 1);
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

/*
 * Test that registering a filter without no_new_privs returns -EACCES.
 * This must be called before prctl(PR_SET_NO_NEW_PRIVS) in main().
 */
static int test_no_new_privs_required(void)
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

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}

	if (pid == 0) {
		int ret;

		/* Try to register without no_new_privs - should fail with EACCES */
		ret = io_uring_register(-1, IORING_REGISTER_BPF_FILTER,
					&io_bpf, 1);
		if (ret == -EACCES) {
			if (!geteuid())
				exit(1);
			exit(0);  /* Expected */
		} else if (!ret) {
			if (!geteuid())
				exit(0);
			exit(1);
		}
		if (ret == -EINVAL || ret == -ENOSYS)
			exit(2);  /* Not supported */
		fprintf(stderr, "Expected -EACCES, got %d\n", ret);
		exit(1);
	}

	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		if (code == 0)
			return 0;  /* Test passed */
		if (code == 2)
			return -1;  /* Not supported, skip */
	}
	fprintf(stderr, "test_no_new_privs_required failed\n");
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
		int ret;

		ret = io_uring_register(-1, IORING_REGISTER_BPF_FILTER,
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
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	if (probe_bpf_filter_support() < 0)
		return T_EXIT_SKIP;

	/*
	 * Test that filter registration fails without no_new_privs.
	 * Must run before we call prctl() below.
	 */
	ret = test_no_new_privs_required();
	if (ret < 0)
		return T_EXIT_SKIP;
	if (ret > 0)
		total_failed++;

	/*
	 * Must set no_new_privs to register BPF filters without CAP_SYS_ADMIN.
	 * This is inherited by all child processes.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("prctl");
		return T_EXIT_SKIP;
	}

	/* Task-level filter tests */
	total_failed += test_deny_nop();
	total_failed += test_allow_inet_only();
	total_failed += test_allow_tcp_only();
	total_failed += test_deny_rest();

	/* Task-level openat/openat2 filter tests */
	total_failed += test_deny_openat_creat();
	total_failed += test_deny_openat2_resolve_in_root();

	/* Ring-level filter tests */
	total_failed += test_deny_nop_ring();
	total_failed += test_allow_inet_only_ring();
	total_failed += test_allow_tcp_only_ring();
	total_failed += test_deny_rest_ring();
	total_failed += test_pdu_size_ring();

	/* Per-task inheritance tests */
	total_failed += test_inherit_restrictions();
	total_failed += test_stack_restrictions();
	total_failed += test_cannot_loosen_restrictions();
	total_failed += test_multi_level_inherit();

	return total_failed;
}
