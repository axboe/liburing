#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "compat.h"
#include "io_uring.h"
#include "liburing.h"

int io_uring_register_buffers(struct io_uring *ring, const struct iovec *iovecs,
			      unsigned nr_iovecs)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_BUFFERS,
				iovecs, nr_iovecs);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_unregister_buffers(struct io_uring *ring)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_UNREGISTER_BUFFERS, NULL,
				0);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_files(struct io_uring *ring, const int *files,
			      unsigned nr_files)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_FILES, files,
				nr_files);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_unregister_files(struct io_uring *ring)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_UNREGISTER_FILES, NULL,
				0);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_register_eventfd(struct io_uring *ring, int event_fd)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_EVENTFD,
				&event_fd, 1);
	if (ret < 0)
		return -errno;

	return 0;
}

int io_uring_unregister_eventfd(struct io_uring *ring)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_UNREGISTER_EVENTFD, NULL,
				0);
	if (ret < 0)
		return -errno;

	return 0;
}
