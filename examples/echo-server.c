/* SPDX-License-Identifier: MIT */
/*
 * Simple TCP echo server demonstrating modern io_uring networking best
 * practices:
 *
 *   - Multishot accept (arm once, get a CQE per new connection)
 *   - Multishot receive (arm once per connection, get a CQE per data chunk)
 *   - Provided buffer rings (kernel picks buffers from a shared pool)
 *   - Proper buffer lifecycle management (recycle after send completes)
 *
 * Requires kernel >= 6.0 for buffer rings and multishot recv.
 * DEFER_TASKRUN (kernel >= 6.1) is used when available, with automatic
 * fallback to COOP_TASKRUN on older kernels.
 *
 * Usage: ./echo-server [port]
 *        Default port: 8000
 *
 * Test with: nc localhost 8000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include "liburing.h"
#include "helpers.h"

#define QD		64
#define BUF_SIZE	4096
#define BUFFERS		256		/* must be power of 2 */
#define BGID		0
#define MAX_CONNS	1024
#define DEFAULT_PORT	8000

enum event_type {
	EVENT_ACCEPT = 1,
	EVENT_RECV   = 2,
	EVENT_SEND   = 3,
};

struct conn {
	int fd;
	bool need_recv_rearm;
};

static struct io_uring ring;
static struct io_uring_buf_ring *buf_ring;
static unsigned char *bufs;
static struct conn conns[MAX_CONNS];
static int listen_fd;

/*
 * Encode event type, buffer ID, and file descriptor into a single 64-bit
 * user_data value:
 *
 *   bits 63-56: event type (ACCEPT, RECV, SEND)
 *   bits 31-16: buffer ID (used by SEND to identify which buffer to recycle)
 *   bits 15-0:  file descriptor
 */
static __u64 encode_userdata(enum event_type type, int bid, int fd)
{
	return ((__u64)type << 56) | ((__u64)(bid & 0xffff) << 16) |
		(__u64)(fd & 0xffff);
}

static enum event_type decode_type(__u64 user_data)
{
	return (enum event_type)(user_data >> 56);
}

static int decode_bid(__u64 user_data)
{
	return (int)((user_data >> 16) & 0xffff);
}

static int decode_fd(__u64 user_data)
{
	return (int)(user_data & 0xffff);
}

/*
 * Wrapper around io_uring_get_sqe() that handles a full SQ ring by
 * flushing pending submissions before retrying. This can happen when
 * processing a large batch of CQEs that each generate new SQEs.
 */
static struct io_uring_sqe *get_sqe(void)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&ring);
	if (!sqe) {
		io_uring_submit(&ring);
		sqe = io_uring_get_sqe(&ring);
	}
	if (!sqe) {
		fprintf(stderr, "cannot get sqe\n");
		exit(1);
	}
	return sqe;
}

/*
 * Set up the provided buffer ring. The kernel will pick buffers from this
 * ring when a multishot recv needs a buffer, eliminating per-recv buffer
 * management from userspace.
 *
 * We allocate the data buffers separately from the ring structure. The
 * io_uring_setup_buf_ring() helper handles the ring allocation and
 * registration with the kernel.
 */
static int setup_buffer_ring(void)
{
	int ret, i;

	bufs = malloc(BUF_SIZE * BUFFERS);
	if (!bufs) {
		fprintf(stderr, "buffer allocation failed\n");
		return 1;
	}

	buf_ring = io_uring_setup_buf_ring(&ring, BUFFERS, BGID, 0, &ret);
	if (!buf_ring) {
		fprintf(stderr, "buffer ring setup failed: %s\n",
				strerror(-ret));
		free(bufs);
		return 1;
	}

	for (i = 0; i < BUFFERS; i++) {
		io_uring_buf_ring_add(buf_ring, bufs + i * BUF_SIZE, BUF_SIZE,
				      i, io_uring_buf_ring_mask(BUFFERS), i);
	}
	io_uring_buf_ring_advance(buf_ring, BUFFERS);

	return 0;
}

static void cleanup_buffer_ring(void)
{
	io_uring_free_buf_ring(&ring, buf_ring, BUFFERS, BGID);
	free(bufs);
}

/*
 * Return a buffer to the provided buffer ring after a send completes.
 * This is the critical step in the buffer lifecycle: the buffer was
 * consumed by a multishot recv, used by a send, and is now free to be
 * reused by a future recv.
 */
static void recycle_buffer(int bid)
{
	io_uring_buf_ring_add(buf_ring, bufs + bid * BUF_SIZE, BUF_SIZE,
			      bid, io_uring_buf_ring_mask(BUFFERS), 0);
	io_uring_buf_ring_advance(buf_ring, 1);
}

/*
 * Submit a multishot accept request on the listening socket. A single
 * multishot accept arms once and generates a CQE for each new incoming
 * connection. It stays active until an error occurs (signaled by the
 * absence of IORING_CQE_F_MORE in cqe->flags).
 */
static void add_multishot_accept(void)
{
	struct io_uring_sqe *sqe;

	sqe = get_sqe();
	io_uring_prep_multishot_accept(sqe, listen_fd, NULL, NULL, 0);
	io_uring_sqe_set_data64(sqe, encode_userdata(EVENT_ACCEPT, 0,
						     listen_fd));
}

/*
 * Submit a multishot recv on a connected client socket. The
 * IOSQE_BUFFER_SELECT flag tells the kernel to pick a buffer from our
 * provided buffer ring (identified by buf_group = BGID). Each incoming
 * data chunk generates a CQE with the buffer ID in cqe->flags.
 */
static void add_recv(int fd)
{
	struct io_uring_sqe *sqe;

	sqe = get_sqe();
	io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = BGID;
	io_uring_sqe_set_data64(sqe, encode_userdata(EVENT_RECV, 0, fd));
}

/*
 * Submit a send echoing data back to the client. The buffer ID is encoded
 * in user_data so we can recycle the buffer when the send completes.
 */
static void add_send(int fd, int bid, int len)
{
	struct io_uring_sqe *sqe;

	sqe = get_sqe();
	io_uring_prep_send(sqe, fd, bufs + bid * BUF_SIZE, len, 0);
	io_uring_sqe_set_data64(sqe, encode_userdata(EVENT_SEND, bid, fd));
}

static void close_conn(int fd)
{
	if (fd >= 0 && fd < MAX_CONNS) {
		conns[fd].fd = -1;
		conns[fd].need_recv_rearm = false;
	}
	close(fd);
}

/*
 * Handle a CQE from the multishot accept. On success, cqe->res is the
 * new client fd. We immediately arm a multishot recv for it.
 *
 * If the multishot terminates (IORING_CQE_F_MORE not set), we re-arm it.
 * This happens when an error occurs on the accept itself.
 */
static void handle_accept(struct io_uring_cqe *cqe)
{
	int fd;

	if (cqe->res < 0) {
		fprintf(stderr, "accept error: %s\n", strerror(-cqe->res));
		if (!(cqe->flags & IORING_CQE_F_MORE))
			add_multishot_accept();
		return;
	}

	/* Defensive: re-arm if multishot terminates on a success CQE */
	if (!(cqe->flags & IORING_CQE_F_MORE))
		add_multishot_accept();

	fd = cqe->res;
	if (fd >= MAX_CONNS) {
		fprintf(stderr, "fd %d exceeds MAX_CONNS\n", fd);
		close(fd);
		return;
	}

	conns[fd].fd = fd;
	conns[fd].need_recv_rearm = false;
	add_recv(fd);
}

/*
 * Handle a CQE from a multishot recv. On success, cqe->res is the number
 * of bytes received, and the buffer ID is in the upper 16 bits of
 * cqe->flags.
 *
 * The buffer lifecycle:
 *   1. Kernel picks a buffer from the ring (buffer leaves the ring)
 *   2. We receive data in that buffer via this CQE
 *   3. We submit a send using the same buffer
 *   4. When the send completes, we recycle the buffer back to the ring
 *
 * If ENOBUFS is returned, all buffers are in-flight (consumed by recv
 * but not yet recycled after send). The multishot terminates and will be
 * re-armed when the send handler recycles a buffer.
 */
static void handle_recv(struct io_uring_cqe *cqe)
{
	int fd = decode_fd(cqe->user_data);
	int bid;

	/* EOF: client disconnected */
	if (cqe->res == 0) {
		close_conn(fd);
		return;
	}

	if (cqe->res < 0) {
		if (cqe->res == -ENOBUFS) {
			/*
			 * All provided buffers are in use. The multishot
			 * recv is terminated. We'll re-arm it from the
			 * send handler once a buffer is recycled.
			 */
			conns[fd].need_recv_rearm = true;
			return;
		}
		/* Connection error */
		close_conn(fd);
		return;
	}

	/*
	 * Successful receive. The IORING_CQE_F_BUFFER flag indicates that
	 * a buffer was consumed from the ring. Extract the buffer ID.
	 */
	if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
		fprintf(stderr, "recv cqe without buffer\n");
		close_conn(fd);
		return;
	}

	bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;

	/* Echo the data back to the client */
	/* TODO: handle short sends for production use */
	add_send(fd, bid, cqe->res);

	/*
	 * If IORING_CQE_F_MORE is not set, the multishot recv has
	 * terminated for a reason other than ENOBUFS (which we handled
	 * above). Mark for re-arm.
	 */
	if (!(cqe->flags & IORING_CQE_F_MORE))
		conns[fd].need_recv_rearm = true;
}

/*
 * Handle a CQE from a send. Recycle the buffer unconditionally (even on
 * error), and check if the connection's multishot recv needs re-arming.
 */
static void handle_send(struct io_uring_cqe *cqe)
{
	int bid = decode_bid(cqe->user_data);
	int fd = decode_fd(cqe->user_data);

	/* Always recycle the buffer, regardless of send success */
	recycle_buffer(bid);

	if (cqe->res < 0) {
		close_conn(fd);
		return;
	}

	/*
	 * Re-arm multishot recv if it was terminated due to ENOBUFS
	 * or another non-fatal reason. Check that the connection is
	 * still alive first -- it may have been closed by an earlier
	 * CQE in this batch.
	 */
	if (fd < MAX_CONNS && conns[fd].fd != -1 &&
	    conns[fd].need_recv_rearm) {
		conns[fd].need_recv_rearm = false;
		add_recv(fd);
	}
}

static int event_loop(void)
{
	struct io_uring_cqe *cqe;
	unsigned int head;
	int ret, count;

	add_multishot_accept();

	while (1) {
		ret = io_uring_submit_and_wait(&ring, 1);
		if (ret == -EINTR)
			continue;
		if (ret < 0) {
			fprintf(stderr, "submit_and_wait: %s\n",
					strerror(-ret));
			break;
		}

		count = 0;
		io_uring_for_each_cqe(&ring, head, cqe) {
			switch (decode_type(cqe->user_data)) {
			case EVENT_ACCEPT:
				handle_accept(cqe);
				break;
			case EVENT_RECV:
				handle_recv(cqe);
				break;
			case EVENT_SEND:
				handle_send(cqe);
				break;
			default:
				fprintf(stderr, "unexpected event type %d\n",
					decode_type(cqe->user_data));
				exit(1);
			}
			count++;
		}
		io_uring_cq_advance(&ring, count);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring_params params;
	int port = DEFAULT_PORT;
	int ret, i;

	if (argc > 1)
		port = atoi(argv[1]);

	for (i = 0; i < MAX_CONNS; i++)
		conns[i].fd = -1;

	listen_fd = setup_listening_socket(port, 0);
	if (listen_fd < 0)
		return 1;

	/*
	 * DEFER_TASKRUN: completions are only processed when the
	 * application explicitly waits for them, reducing overhead.
	 * Requires SINGLE_ISSUER (only one thread submits to the ring).
	 *
	 * SUBMIT_ALL: continue submitting remaining SQEs even if one
	 * fails, preventing one bad SQE from blocking a batch.
	 *
	 * CQSIZE: multishot operations can produce CQEs faster than
	 * single-shot, so we oversize the CQ ring to prevent overflow.
	 */
	memset(&params, 0, sizeof(params));
	params.cq_entries = QD * 8;
	params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE |
		       IORING_SETUP_SINGLE_ISSUER |
		       IORING_SETUP_DEFER_TASKRUN;

	ret = io_uring_queue_init_params(QD, &ring, &params);
	if (ret == -EINVAL) {
		/* Kernel < 6.1, fall back to COOP_TASKRUN */
		params.flags = IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE |
			       IORING_SETUP_COOP_TASKRUN;
		ret = io_uring_queue_init_params(QD, &ring, &params);
	}
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		close(listen_fd);
		return 1;
	}

	if (setup_buffer_ring()) {
		io_uring_queue_exit(&ring);
		close(listen_fd);
		return 1;
	}

	printf("echo server listening on port %d\n", port);

	event_loop();

	cleanup_buffer_ring();
	close(listen_fd);
	io_uring_queue_exit(&ring);
	return 0;
}
