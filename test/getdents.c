#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "helpers.h"
#include "liburing.h"

#define BUFFER_SIZE 512

#define LIST_INIT(name) { &(name), &(name) }

#define CONTAINER_OF(ptr, type, member) (					\
	{									\
		const typeof(((type *)0)->member) *__ptr = (ptr);		\
		(type *)((char *)__ptr - (intptr_t)(&((type *)0)->member)); 	\
	})

struct list {
	struct list	*next;
	struct list	*prev;
};

struct dir {
	struct list	list;
	int		ret;

	struct dir	*parent;
	int		fd;
	uint64_t	off;
	uint8_t		buf[BUFFER_SIZE];
	char		name[0];
};

struct linux_dirent64 {
	int64_t		d_ino;    /* 64-bit inode number */
	int64_t		d_off;    /* 64-bit offset to next structure */
	unsigned short	d_reclen; /* Size of this dirent */
	unsigned char	d_type;   /* File type */
	char		d_name[]; /* Filename (null-terminated) */
};

/* Define global variables. */
static struct io_uring ring;
static struct list active = LIST_INIT(active);
static int sqes_in_flight = 0;
static int num_dir_entries = 0;

/* Forward declarations. */
static void drain_cqes(void);
static void schedule_readdir(struct dir *dir);

/* List helper functions. */
static inline void list_add_tail(struct list *l, struct list *head)
{
	l->next = head;
	l->prev = head->prev;
	head->prev->next = l;
	head->prev = l;
}

static inline void list_del(struct list *l)
{
	l->prev->next = l->next;
	l->next->prev = l->prev;
	l->prev = NULL;
	l->next = NULL;
}

static inline int is_list_empty(const struct list *l)
{
	return l->next == l;
}

static struct io_uring_sqe *get_sqe(void)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&ring);
	while (sqe == NULL) {
		drain_cqes();

		int ret = io_uring_submit(&ring);
		if (ret < 0 && errno != EBUSY) {
			perror("io_uring_submit");
			exit(EXIT_FAILURE);
		}

		sqe = io_uring_get_sqe(&ring);
	}

	sqes_in_flight++;
	return sqe;
}

static void drain_cqes(void)
{
	struct io_uring_cqe *cqe;
	uint32_t head;
	int count;

	count = 0;
	io_uring_for_each_cqe (&ring, head, cqe) {
		struct dir *dir;

		dir = io_uring_cqe_get_data(cqe);

		list_add_tail(&dir->list, &active);
		dir->ret = cqe->res;

		count++;
	}

	sqes_in_flight -= count;
	io_uring_cq_advance(&ring, count);
}

static void schedule_opendir(struct dir *parent, const char *name)
{
	struct io_uring_sqe *sqe;
	int len = strlen(name);
	struct dir *dir;

	dir = malloc(sizeof(*dir) + len + 1);
	if (dir == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(EXIT_FAILURE);
	}

	dir->parent = parent;
	dir->fd = -1;
	memcpy(dir->name, name, len);
	dir->name[len] = 0;

	sqe = get_sqe();
	io_uring_prep_openat(sqe,
			     (parent != NULL) ? parent->fd : AT_FDCWD,
			     dir->name,
			     O_DIRECTORY,
			     0);
	io_uring_sqe_set_data(sqe, dir);
}

static void opendir_completion(struct dir *dir, int ret)
{
	if (ret < 0) {
		fprintf(stderr, "error opening ");
		fprintf(stderr, ": %s\n", strerror(-ret));
		return;
	}

	dir->fd = ret;
	dir->off = 0;
	schedule_readdir(dir);
}

static void schedule_readdir(struct dir *dir)
{
	struct io_uring_sqe *sqe;

	sqe = get_sqe();
	io_uring_prep_getdents(sqe, dir->fd, dir->buf, sizeof(dir->buf), dir->off);
	io_uring_sqe_set_data(sqe, dir);
}

static void readdir_completion(struct dir *dir, int ret)
{
	uint8_t *bufp;
	uint8_t *end;

	if (ret < 0) {
		fprintf(stderr, "error reading ");
		fprintf(stderr, ": %s (%d)\n", strerror(-ret), ret);
		return;
	}

	if (ret == 0) {
		free(dir);
		return;
	}

	bufp = dir->buf;
	end = bufp + ret;

	while (bufp < end) {
		struct linux_dirent64 *dent;

		dent = (struct linux_dirent64 *)bufp;

		if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
			if (dent->d_type == DT_DIR)
				schedule_opendir(dir, dent->d_name);
		}

		dir->off = dent->d_off;
		bufp += dent->d_reclen;
		++num_dir_entries;
	}

	schedule_readdir(dir);
}

int main(int argc, char *argv[])
{
	struct rlimit rlim;

	/* Increase number of files rlimit to 1M. */
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		perror("getrlimit");
		return 1;
	}

	if (geteuid() == 0 && rlim.rlim_max < 1048576)
		rlim.rlim_max = 1048576;

	if (rlim.rlim_cur < rlim.rlim_max) {
		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_NOFILE, &rlim);
	}

	if (io_uring_queue_init(256, &ring, 0) < 0) {
		perror("io_uring_queue_init");
		return 1;
	}

	/* Submit and handle requests. */
	schedule_opendir(NULL, ".");
	while (sqes_in_flight) {
		int ret = io_uring_submit_and_wait(&ring, 1);
		if (ret < 0 && errno != EBUSY) {
			perror("io_uring_submit_and_wait");
			return 1;
		}

		drain_cqes();

		while (!is_list_empty(&active)) {
			struct dir *dir;

			dir = CONTAINER_OF(active.next, struct dir, list);
			list_del(&dir->list);

			if (dir->fd == -1)
				opendir_completion(dir, dir->ret);
			else
				readdir_completion(dir, dir->ret);
		}
	}

	io_uring_queue_exit(&ring);
	return num_dir_entries < 50;
}
