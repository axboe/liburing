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
static struct iovec iovecs[QD];

struct io_data {
	off_t offset;
	struct iovec *iov;
};

static int setup_context(unsigned entries, struct io_uring *ring)
{
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
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

static unsigned sqe_index(struct io_uring_sqe *sqe)
{
	return sqe - in_ring.sq.sqes;
}

static int queue_read(int fd, off_t size, off_t offset)
{
	struct io_uring_sqe *sqe;
	struct io_data *data;

	sqe = io_uring_get_sqe(&in_ring);
	if (!sqe)
		return 1;

	data = malloc(sizeof(*data));
	data->offset = offset;
	data->iov = &iovecs[sqe_index(sqe)];

	sqe->opcode = IORING_OP_READV;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) data->iov;
	sqe->buf_index = 0;
	sqe->user_data = (unsigned long) data;
	iovecs[sqe_index(sqe)].iov_len = size;
	sqe->len = 1;
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
		struct io_uring_cqe *cqe;

		ret = io_uring_wait_completion(&out_ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "io_uring_wait_completion: %s\n",
						strerror(-ret));
			return 1;
		}
		if (cqe->res < 0) {
			fprintf(stderr, "cqe failed: %s\n", strerror(-cqe->res));
			return 1;
		}
		(*writes)--;
		nr--;
	}

	return 0;
}

static void queue_write(int fd, struct io_uring_cqe *cqe)
{
	struct io_data *data = (struct io_data *) cqe->user_data;
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&out_ring);
	sqe->opcode = IORING_OP_WRITEV;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = data->offset;
	sqe->addr = (unsigned long) data->iov;
	sqe->buf_index = 0;
	sqe->user_data = 0;
	data->iov->iov_len = cqe->res;
	sqe->len = 1;
	free(data);
}

int main(int argc, char *argv[])
{
	off_t read_left, write_left, offset;
	struct io_uring_cqe *cqe;
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

	for (i = 0; i < QD; i++) {
		void *buf;

		if (posix_memalign(&buf, BS, BS))
			return 1;
		iovecs[i].iov_base = buf;
		iovecs[i].iov_len = BS;
	}

	if (setup_context(QD, &in_ring))
		return 1;
	if (setup_context(QD, &out_ring))
		return 1;
	if (get_file_size(infd, &read_left))
		return 1;

	offset = 0;
	writes = reads = 0;
	write_left = read_left;
	while (read_left || write_left) {
	
		/*
		 * Queue up as many reads as we can
		 */
		while (read_left) {
			off_t this_size = read_left;

			if (this_size > BS)
				this_size = BS;
			else if (!this_size)
				break;

			if (queue_read(infd, this_size, offset))
				break;

			read_left -= this_size;
			offset += this_size;
			reads++;
		}

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
				ret = io_uring_wait_completion(&in_ring, &cqe);
			else
				ret = io_uring_get_completion(&in_ring, &cqe);
			if (ret < 0) {
				fprintf(stderr, "io_uring_get_completion: %s\n",
							strerror(-ret));
				return 1;
			}
			if (!cqe)
				break;
			reads--;
			if (cqe->res < 0) {
				fprintf(stderr, "cqe failed: %s\n",
						strerror(-cqe->res));
				return 1;
			}
			queue_write(outfd, cqe);
			write_left -= cqe->res;
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
