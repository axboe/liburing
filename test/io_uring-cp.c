/*
 * gcc -Wall -O2 -D_GNU_SOURCE -o io_uring-cp io_uring-cp.c -luring
 */
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../src/liburing.h"

#define QD	64
#define BS	4096

static struct io_uring in_ring;
static struct io_uring out_ring;
static void *bufs[QD];

static int setup_context(unsigned entries, struct io_uring *ring, int offload)
{
	struct io_uring_params p;
	int ret;

	memset(&p, 0, sizeof(p));
	if (offload)
		p.flags = IORING_SETUP_SQWQ;

	ret = io_uring_queue_init(entries, &p, NULL, ring);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}

	return 0;
}

static int get_file_size(int fd, off_t *size)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -1;
	if (S_ISREG(st.st_mode)) {
		*size = st.st_size;
		return 0;
	}

	return -1;
}

static unsigned iocb_index(struct io_uring_iocb *iocb)
{
	return iocb - in_ring.sq.iocbs;
}

static int queue_read(int fd, off_t size, off_t offset)
{
	struct io_uring_iocb *iocb;

	iocb = io_uring_get_iocb(&in_ring);
	if (!iocb)
		return 1;

	iocb->opcode = IORING_OP_READ;
	iocb->flags = 0;
	iocb->ioprio = 0;
	iocb->fd = fd;
	iocb->off = offset;
	iocb->addr = bufs[iocb_index(iocb)];
	iocb->len = size;
	return 0;
}

static int complete_writes(unsigned *writes)
{
	int ret, nr;

	ret = io_uring_submit(&out_ring);
	if (ret < 0) {
		fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
		return 1;
	}

	nr = ret;
	while (nr) {
		struct io_uring_event *ev = NULL;

		ret = io_uring_wait_completion(&out_ring, &ev);
		if (ret < 0) {
			fprintf(stderr, "io_uring_wait_completion: %s\n",
						strerror(-ret));
			return 1;
		}
		if (ev->res < 0) {
			fprintf(stderr, "ev failed: %s\n", strerror(-ev->res));
			return 1;
		}
		(*writes)--;
		nr--;
	}

	return 0;
}

static void queue_write(int fd, off_t size, off_t offset, unsigned index)
{
	struct io_uring_iocb *iocb;

	iocb = io_uring_get_iocb(&out_ring);
	iocb->opcode = IORING_OP_WRITE;
	iocb->flags = 0;
	iocb->ioprio = 0;
	iocb->fd = fd;
	iocb->off = offset;
	iocb->addr = bufs[index];
	iocb->len = size;
}

int main(int argc, char *argv[])
{
	struct io_uring_event *ev;
	off_t read_left, write_left, offset;
	int i, infd, outfd, ret;
	unsigned reads, writes;

	if (argc < 3) {
		printf("%s: infile outfile\n", argv[0]);
		return 1;
	}

	infd = open(argv[1], O_RDONLY);
	if (infd < 0) {
		perror("open infile");
		return 1;
	}
	outfd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (outfd < 0) {
		perror("open outfile");
		return 1;
	}

	for (i = 0; i < QD; i++)
		if (posix_memalign(&bufs[i], BS, BS))
			return 1;

	if (setup_context(QD, &in_ring, 1))
		return 1;
	if (setup_context(QD, &out_ring, 0))
		return 1;
	if (get_file_size(infd, &read_left))
		return 1;

	offset = 0;
	writes = reads = 0;
	write_left = read_left;
	while (read_left || write_left) {
		off_t this_size = read_left;
		struct io_uring_iocb *iocb;

		if (this_size > BS)
			this_size = BS;
		else if (!this_size)
			goto skip_read;
	
		/*
		 * Queue up as many reads as we can
		 */
		while (read_left && !queue_read(infd, this_size, offset)) {
			read_left -= this_size;
			offset += this_size;
			reads++;
		}

skip_read:
		ret = io_uring_submit(&in_ring);
		if (ret < 0) {
			fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
			break;
		}

		/*
		 * read queue full, get at least one completion and queue up
		 * a write
		 */
		while (reads || write_left) {
			if (reads)
				ret = io_uring_wait_completion(&in_ring, &ev);
			else
				ret = io_uring_get_completion(&in_ring, &ev);
			if (ret < 0) {
				fprintf(stderr, "io_uring_get_completion: %s\n",
							strerror(-ret));
				return 1;
			}
			if (!ev)
				break;
			reads--;
			if (ev->res < 0) {
				fprintf(stderr, "ev failed: %s\n",
						strerror(-ev->res));
				return 1;
			}
			iocb = io_uring_iocb_from_ev(&in_ring, ev);
			queue_write(outfd, ev->res, iocb->off, ev->index);
			write_left -= ev->res;
			writes++;
		};
		if (complete_writes(&writes))
			break;
	};

	close(infd);
	close(outfd);
	io_uring_queue_exit(&in_ring);
	io_uring_queue_exit(&out_ring);
	return 0;
}
