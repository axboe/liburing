#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "liburing.h"
#include "liburing/io_uring/bpf_filter.h"

#ifndef BPF_PROG_TYPE_IO_URING
#define BPF_PROG_TYPE_IO_URING 33
#endif

/* Load BPF object file and return program fd */
static int load_bpf_filter(const char *filename, const char *filter)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prog_fd;
	int err;

	/* Open and load the BPF object file */
	obj = bpf_object__open(filename);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "Failed to open BPF object: %s\n",
			strerror(errno));
		return -1;
	}

	/* Set program type before loading */
	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_IO_URING);
	}

	/* Load the program into the kernel */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %s\n",
			strerror(-err));
		bpf_object__close(obj);
		return -1;
	}

	/* Find the program by section name */
	prog = bpf_object__find_program_by_name(obj, filter);
	if (!prog) {
		fprintf(stderr, "Failed to find BPF program %s\n", filter);
		bpf_object__close(obj);
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to get BPF program fd\n");
		bpf_object__close(obj);
		return -1;
	}

	printf("BPF program loaded successfully from %s, fd=%d\n", filename,
	       prog_fd);

	/* Note: We don't close the object because we need the fd to remain valid */
	/* In production code, you'd keep track of the object for cleanup */

	return prog_fd;
}

/* Register BPF filter with io_uring */
static int register_bpf_filter(int prog_fd, __u32 opcode, int disable_rest)
{
	struct io_uring_bpf io_bpf = {
		.cmd_type = IO_URING_BPF_CMD_FILTER,
		.filter = {
			.opcode = opcode,
			.prog_fd = prog_fd,
			.flags = disable_rest ? 1 : 0,
		},
	};
	int ret;

	ret = io_uring_register(-1, IORING_REGISTER_BPF_FILTER, &io_bpf, 1);
	if (ret < 0) {
		fprintf(stderr, "Failed to register BPF filter: %s\n",
			strerror(-ret));
		return ret;
	}

	printf("BPF filter registered for opcode %u\n", opcode);
	return 0;
}

/* Test socket creation through io_uring */
static int test_nop(struct io_uring *ring, const char *desc, int should_succeed)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	printf("Testing %s: ", desc);
	fflush(stdout);

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 0x4321;

	ret = io_uring_submit(ring);
	if (ret < 0) {
		printf("FAILED (submit: %s)\n", strerror(-ret));
		return ret;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		printf("FAILED (wait_cqe: %s)\n", strerror(-ret));
		return ret;
	}

	if (should_succeed) {
		if (cqe->res >= 0) {
			printf("PASSED (fd=%d)\n", cqe->res);
			close(cqe->res);
			ret = 0;
		} else {
			printf("FAILED (expected success, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		}
	} else {
		if (cqe->res == -EACCES) {
			printf("PASSED (correctly rejected)\n");
			ret = 0;
		} else if (cqe->res < 0) {
			printf("FAILED (expected -EACCES, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		} else {
			printf("FAILED (expected rejection, got fd=%d)\n",
			       cqe->res);
			close(cqe->res);
			ret = -1;
		}
	}

	io_uring_cqe_seen(ring, cqe);
	return ret;
}

/* Test socket creation through io_uring */
static int test_socket_op(struct io_uring *ring, int family, int type,
			  int protocol, const char *desc, int should_succeed)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	printf("Testing %s: ", desc);
	fflush(stdout);

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		printf("FAILED (get_sqe)\n");
		return -1;
	}

	io_uring_prep_socket(sqe, family, type, protocol, 0);
	sqe->user_data = 0x1234;

	ret = io_uring_submit(ring);
	if (ret < 0) {
		printf("FAILED (submit: %s)\n", strerror(-ret));
		return ret;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		printf("FAILED (wait_cqe: %s)\n", strerror(-ret));
		return ret;
	}

	if (should_succeed) {
		if (cqe->res >= 0) {
			printf("PASSED (fd=%d)\n", cqe->res);
			close(cqe->res);
			ret = 0;
		} else {
			printf("FAILED (expected success, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		}
	} else {
		if (cqe->res == -EACCES) {
			printf("PASSED (correctly rejected)\n");
			ret = 0;
		} else if (cqe->res < 0) {
			printf("FAILED (expected -EACCES, got %s)\n",
			       strerror(-cqe->res));
			ret = -1;
		} else {
			printf("FAILED (expected rejection, got fd=%d)\n",
			       cqe->res);
			close(cqe->res);
			ret = -1;
		}
	}

	io_uring_cqe_seen(ring, cqe);
	return ret;
}

static int run_test(const char *msg, int disable_inet6, int disable_nop)
{
	int passed = 0, failed = 0;
	int ret;
	struct io_uring ring;

	/* Initialize io_uring */
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init failed: %s\n",
			strerror(-ret));
		return 1;
	}

	printf("\nRunning tests for %s...\n\n", msg);

/* Test cases */
#define TEST(family, type, proto, desc, should_pass)                 \
	do {                                                         \
		if (test_socket_op(&ring, family, type, proto, desc, \
				   should_pass) == 0)                \
			passed++;                                    \
		else                                                 \
			failed++;                                    \
	} while (0)

	/* Should succeed */
	TEST(AF_INET, SOCK_STREAM, IPPROTO_TCP, "AF_INET TCP (explicit)", 1);
	TEST(AF_INET, SOCK_STREAM, 0, "AF_INET TCP (default)", 1);
	if (disable_inet6) {
		TEST(AF_INET6, SOCK_STREAM, IPPROTO_TCP,
		     "AF_INET6 TCP (explicit)", 0);
		TEST(AF_INET6, SOCK_STREAM, 0, "AF_INET6 TCP (default)", 0);
	} else {
		TEST(AF_INET6, SOCK_STREAM, IPPROTO_TCP,
		     "AF_INET6 TCP (explicit)", 1);
		TEST(AF_INET6, SOCK_STREAM, 0, "AF_INET6 TCP (default)", 1);
	}

	test_nop(&ring, "nop", !disable_nop);

	/* Should fail */
	TEST(AF_INET, SOCK_DGRAM, IPPROTO_UDP, "AF_INET UDP", 0);
	TEST(AF_INET, SOCK_RAW, IPPROTO_RAW, "AF_INET RAW", 0);
	TEST(AF_UNIX, SOCK_STREAM, 0, "AF_UNIX", 0);
	TEST(AF_INET, SOCK_STREAM, IPPROTO_UDP,
	     "AF_INET TCP socket with UDP proto", 0);

#undef TEST

	printf("\n==========================================\n");
	printf("Test Results: %d passed, %d failed\n", passed, failed);

	/* Cleanup */
	io_uring_queue_exit(&ring);

	return failed > 0 ? 1 : 0;
}

int main(int argc, char *argv[])
{
	int bpf_fd, bpf_fd2, wstatus;
	int ret = 0;
	pid_t pid;
	const char *bpf_obj = "bpf_filters/socket_mix.bpf.o";
	const char *bpf_obj6 = "bpf_filters/socket_ipv6_deny.bpf.o";

	if (argc > 1) {
		bpf_obj = argv[1];
		if (argc > 2)
			bpf_obj6 = argv[2];
	}

	/* Load BPF filter from compiled object file */
	bpf_fd = load_bpf_filter(bpf_obj, "socket_mix_filter");
	if (bpf_fd < 0) {
		fprintf(stderr, "Failed to load BPF filter\n");
		return 1;
	}

	/* Register filter for IORING_OP_SOCKET */
	ret = register_bpf_filter(bpf_fd, IORING_OP_SOCKET, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to register filter\n");
		close(bpf_fd);
		return 1;
	}

	ret = run_test("parent", 0, 0);
	if (ret)
		return ret;

	bpf_fd2 = load_bpf_filter(bpf_obj6, "socket_ipv6_deny_filter");
	if (bpf_fd2 < 0) {
		fprintf(stderr, "Failed to load BPF filter\n");
		return 1;
	}

	/* Register filter for IORING_OP_SOCKET */
	ret = register_bpf_filter(bpf_fd2, IORING_OP_SOCKET, 1);
	if (ret < 0) {
		fprintf(stderr, "Failed to register filter\n");
		close(bpf_fd2);
		return 1;
	}

	pid = fork();
	if (!pid) {
		ret = run_test("child", 1, 1);
		if (ret)
			printf("child test failed\n");
		exit(0);
	}

	waitpid(pid, &wstatus, 0);

	close(bpf_fd);
	if (bpf_fd2 != -1)
		close(bpf_fd2);
	return 0;
}
