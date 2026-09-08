/* SPDX-License-Identifier: MIT */
/*
 * File registration may raise the soft limit, but must respect the hard limit.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "helpers.h"
#include "liburing.h"

static int test_register(int mode)
{
	struct rlimit limit;
	struct io_uring ring;
	int files[80], fd, i, ret;

	if (getrlimit(RLIMIT_NOFILE, &limit)) {
		perror("getrlimit");
		return T_EXIT_FAIL;
	}
	if (limit.rlim_max < 96)
		return T_EXIT_SKIP;
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup: %d\n", ret);
		return T_EXIT_FAIL;
	}
	fd = open("/dev/null", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return T_EXIT_FAIL;
	}
	limit.rlim_cur = 64;
	limit.rlim_max = 96;
	if (setrlimit(RLIMIT_NOFILE, &limit)) {
		perror("setrlimit");
		return T_EXIT_FAIL;
	}
	for (i = 0; i < 80; i++)
		files[i] = fd;
	if (!mode)
		ret = io_uring_register_files(&ring, files, 80);
	else if (mode == 1)
		ret = io_uring_register_files_tags(&ring, files, NULL, 80);
	else
		ret = io_uring_register_files_sparse(&ring, 80);
	if (mode && ret == -EINVAL)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "register mode %d: %d\n", mode, ret);
		return T_EXIT_FAIL;
	}
	if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur < 80 ||
	    limit.rlim_cur > 96 || limit.rlim_max != 96) {
		fprintf(stderr, "unexpected file limits\n");
		return T_EXIT_FAIL;
	}
	io_uring_unregister_files(&ring);
	io_uring_queue_exit(&ring);
	close(fd);
	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	int mode, status, failed = 0, skipped = 0;
	pid_t pid;

	if (argc > 1)
		return T_EXIT_SKIP;
	for (mode = 0; mode < 3; mode++) {
		/* Keep the reduced hard limit confined to this child. */
		pid = fork();
		if (pid < 0) {
			perror("fork");
			return T_EXIT_FAIL;
		}
		if (!pid)
			_exit(test_register(mode));
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
			return T_EXIT_FAIL;
		if (WEXITSTATUS(status) == T_EXIT_SKIP)
			skipped++;
		else if (WEXITSTATUS(status) != T_EXIT_PASS)
			failed = 1;
	}
	if (failed)
		return T_EXIT_FAIL;
	return skipped == 3 ? T_EXIT_SKIP : T_EXIT_PASS;
}
