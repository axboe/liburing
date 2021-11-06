/* SPDX-License-Identifier: MIT */

/*
 * kworker-hang
 *
 * Link: https://github.com/axboe/liburing/issues/448
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "helpers.h"
#include "liburing.h"

#define NR_RINGS			2

/*
 * WAIT_FOR_KWORKER_SECS can be any longer, but to make
 * the test short, 10 seconds should be enough.
 */
#define WAIT_FOR_KWORKER_SECS		10
#define WAIT_FOR_KWORKER_SECS_STR	"10"

static bool is_all_numeric(const char *pid)
{
	size_t i, l;
	char c;

	l = strnlen(pid, 32);
	if (l == 0)
		return false;

	for (i = 0; i < l; i++) {
		c = pid[i];
		if (!('0' <= c && c <= '9'))
			return false;
	}

	return true;
}

static bool is_kworker_event_unbound(const char *pid)
{
	int fd;
	bool ret = false;
	char fpath[256];
	char read_buf[256] = { };
	ssize_t read_size;

	snprintf(fpath, sizeof(fpath), "/proc/%s/comm", pid);

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return false;

	read_size = read(fd, read_buf, sizeof(read_buf) - 1);
	if (read_size < 0)
		goto out;

	if (!strncmp(read_buf, "kworker", 7) && strstr(read_buf, "events_unbound"))
		ret = true;
out:
	close(fd);
	return ret;
}

static bool is_on_io_ring_exit_work(const char *pid)
{
	int fd;
	bool ret = false;
	char fpath[256];
	char read_buf[4096] = { };
	ssize_t read_size;

	snprintf(fpath, sizeof(fpath), "/proc/%s/stack", pid);

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return false;

	read_size = read(fd, read_buf, sizeof(read_buf) - 1);
	if (read_size < 0)
		goto out;

	if (strstr(read_buf, "io_ring_exit_work"))
		ret = true;
out:
	close(fd);
	return ret;
}

static bool is_in_d_state(const char *pid)
{
	int fd;
	bool ret = false;
	char fpath[256];
	char read_buf[4096] = { };
	ssize_t read_size;
	const char *p = read_buf;

	snprintf(fpath, sizeof(fpath), "/proc/%s/stat", pid);

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return false;

	read_size = read(fd, read_buf, sizeof(read_buf) - 1);
	if (read_size < 0)
		goto out;

	/*
	 * It looks like this:
	 * 9384 (kworker/u8:8+events_unbound) D 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 20 0 1 0
	 *
	 * Catch the 'D'!
	 */
	while (*p != ')') {
		p++;
		if (&p[2] >= &read_buf[sizeof(read_buf) - 1])
			/*
			 * /proc/$pid/stack shows the wrong output?
			 */
			goto out;
	}

	ret = (p[2] == 'D');
out:
	close(fd);
	return ret;
}

/*
 * Return 1 if we have kworkers hang or fail to open `/proc`.
 */
static int scan_kworker_hang(void)
{
	DIR *dr;
	int ret = 0;
	struct dirent *de;

	dr = opendir("/proc");
	if (dr == NULL) {
		perror("opendir");
		return 1;
	}

	while (1) {
		const char *pid;

		de = readdir(dr);
		if (!de)
			break;

		pid = de->d_name;
		if (!is_all_numeric(pid))
			continue;

		if (!is_kworker_event_unbound(pid))
			continue;

		if (!is_on_io_ring_exit_work(pid))
			continue;

		if (is_in_d_state(pid)) {
			/* kworker hang */
			fprintf(stderr, "Bug: found hang kworker on "
				"io_ring_exit_work /proc/%s\n", pid);
			ret = 1;
		}
	}

	closedir(dr);
	return ret;
}

static void set_hung_entries(void)
{
	const char *cmds[] = {
		/* Backup current values. */
		"cat /proc/sys/kernel/hung_task_all_cpu_backtrace > hung_task_all_cpu_backtrace.bak",
		"cat /proc/sys/kernel/hung_task_check_count > hung_task_check_count.bak",
		"cat /proc/sys/kernel/hung_task_panic > hung_task_panic.bak",
		"cat /proc/sys/kernel/hung_task_check_interval_secs > hung_task_check_interval_secs.bak",
		"cat /proc/sys/kernel/hung_task_timeout_secs > hung_task_timeout_secs.bak",
		"cat /proc/sys/kernel/hung_task_warnings > hung_task_warnings.bak",

		/* Set to do the test. */
		"echo 1 > /proc/sys/kernel/hung_task_all_cpu_backtrace",
		"echo 99999999 > /proc/sys/kernel/hung_task_check_count",
		"echo 0 > /proc/sys/kernel/hung_task_panic",
		"echo 1 > /proc/sys/kernel/hung_task_check_interval_secs",
		"echo " WAIT_FOR_KWORKER_SECS_STR " > /proc/sys/kernel/hung_task_timeout_secs",
		"echo -1 > /proc/sys/kernel/hung_task_warnings",
	};
	int p;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++)
		p = system(cmds[i]);

	(void)p;
}

static void restore_hung_entries(void)
{
	const char *cmds[] = {
		/* Restore old values. */
		"cat hung_task_all_cpu_backtrace.bak > /proc/sys/kernel/hung_task_all_cpu_backtrace",
		"cat hung_task_check_count.bak > /proc/sys/kernel/hung_task_check_count",
		"cat hung_task_panic.bak > /proc/sys/kernel/hung_task_panic",
		"cat hung_task_check_interval_secs.bak > /proc/sys/kernel/hung_task_check_interval_secs",
		"cat hung_task_timeout_secs.bak > /proc/sys/kernel/hung_task_timeout_secs",
		"cat hung_task_warnings.bak > /proc/sys/kernel/hung_task_warnings",

		/* Clean up! */
		"rm -f " \
			"hung_task_all_cpu_backtrace.bak " \
			"hung_task_check_count.bak " \
			"hung_task_panic.bak " \
			"hung_task_check_interval_secs.bak " \
			"hung_task_timeout_secs.bak " \
			"hung_task_warnings.bak"
	};
	int p;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++)
		p = system(cmds[i]);

	(void)p;
}


static int run_child(void)
{
	int ret, i;
	struct io_uring rings[NR_RINGS];

	for (i = 0; i < NR_RINGS; i++) {
		struct io_uring_params p = { };

		ret = io_uring_queue_init_params(64, &rings[i], &p);
		if (ret) {
			fprintf(stderr, "io_uring_queue_init_params(): (%d) %s\n",
			        ret, strerror(-ret));
			return 1;
		}
	}

	for (i = 0; i < NR_RINGS; i++)
		io_uring_queue_exit(&rings[i]);

	kill(getpid(), SIGSTOP);
	/*
	 * kworkers hang right after this task sends SIGSTOP to itself.
	 * The parent process will check it. We are suspended here!
	 */
	return 0;
}

int main(void)
{
	pid_t child_pid;
	int ret, wstatus = 0;

	/*
	 * We need root to check /proc/$pid/stack and set /proc/sys/kernel/hung*
	 */
	if (getuid() != 0 && geteuid() != 0) {
		fprintf(stderr, "Skipping kworker-hang: not root\n");
		return 0;
	}

	set_hung_entries();
	child_pid = fork();
	if (child_pid < 0) {
		ret = errno;
		fprintf(stderr, "fork(): (%d) %s\n", ret, strerror(ret));
		restore_hung_entries();
		return 1;
	}

	if (!child_pid)
		return run_child();

	atexit(restore_hung_entries);

	/*
	 * +2 just to add small extra time for
	 * fork(), io_uring_setup(), close(), etc.
	 */
	sleep(WAIT_FOR_KWORKER_SECS + 2);
	ret = scan_kworker_hang();

	/*
	 * Continue the suspended task.
	 */
	kill(child_pid, SIGCONT);

	if (waitpid(child_pid, &wstatus, 0) < 0) {
		ret = errno;
		fprintf(stderr, "waitpid(): (%d) %s\n", ret, strerror(ret));
		return 1;
	}

	if (!WIFEXITED(wstatus)) {
		fprintf(stderr, "Child process won't exit\n");
		return 1;
	}

	/* Make sure child process exited properly as well. */
	return ret | WEXITSTATUS(wstatus);
}
