/* SPDX-License-Identifier: MIT */
/*
 * Sample program that can act either as a packet sink, where it just receives
 * packets and doesn't do anything with them, or it can act as a proxy where it
 * receives packets and then sends them to a new destination.
 * 
 * Examples:
 *
 * Act as a proxy, listening on port 4444, and send data to 192.168.2.6 on port
 * 4445. Use multishot receive, DEFER_TASKRUN, and fixed files
 *
 * 	./proxy -m1 -d1 -f1 -r4444 -H 192.168.2.6 -p4445
 *
 * Act as a bi-directional proxy, listening on port 8888, and send data back
 * and forth between host and 192.168.2.6 on port 22. Use multishot receive,
 * DEFER_TASKRUN, fixed files, and buffers of size 1500.
 *
 * 	./proxy -m1 -d1 -f1 -B1 -b1500 -r8888 -H 192.168.2.6 -p22
 *
 * Act a sink, listening on port 4445, using multishot receive, DEFER_TASKRUN,
 * and fixed files:
 *
 * 	./proxy -m1 -d1 -s1 -f1 -r4445
 *
 * Run with -h to see a list of options, and their defaults.
 *
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 *
 */
#include <fcntl.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <liburing.h>

#include "proxy.h"
#include "list.h"
#include "helpers.h"

/*
 * Flag the kernel can use to tell us it supports sends with provided buffers.
 * We can use this to eliminate the need to serialize our sends, as each send
 * will pick a buffer in FIFO order if we can use provided buffers.
 */
#ifndef IORING_FEAT_SEND_BUFS
#define IORING_FEAT_SEND_BUFS	(1U << 14)
#endif

static int cur_bgid = 1;
static int nr_conns;
static int open_conns;
static long page_size;

static unsigned long event_loops;
static unsigned long events;

static int mshot = 1;
static int sqpoll;
static int defer_tw = 1;
static int is_sink;
static int fixed_files = 1;
static char *host = "192.168.2.6";
static int send_port = 4445;
static int receive_port = 4444;
static int buf_size = 32;
static int bidi;
static int ipv6;
static int napi;
static int napi_timeout;
static int wait_batch = 1;
static int wait_usec = 1000000;
static int use_msg;
static int send_ring = -1;
static int verbose;

static int nr_bufs = 256;
static int br_mask;

struct pending_send {
	struct list_head list;

	int fd, bid, len;
	void *data;
};

/*
 * Per socket stats per connection. For bi-directional, we'll have both
 * sends and receives on each socket, this helps track them seperately.
 * For sink or one directional, each of the two stats will be only sends
 * or receives, not both.
 */
struct conn_dir {
	int pending_shutdown;
	int pending_sends;
	struct list_head send_list;

	int rcv, rcv_shrt, enobufs;
	int snd, snd_shrt, snd_busy;

	int rearm_recv;
	int mshot_submit;

	unsigned long in_bytes, out_bytes;
};

enum {
	CONN_F_DISCONNECTING	= 1,
	CONN_F_DISCONNECTED	= 2,
	CONN_F_PENDING_SHUTDOWN	= 4,
	CONN_F_STATS_SHOWN	= 8,
	CONN_F_END_TIME		= 16,
};

/*
 * buffer ring belonging to a connection
 */
struct conn_buf_ring {
	struct io_uring_buf_ring *br;
	void *buf;
	int bgid;
};

struct conn {
	struct conn_buf_ring in_br;
	struct conn_buf_ring out_br;

	int tid;
	int in_fd, out_fd;
	int pending_cancels;
	int flags;

	struct conn_dir cd[2];

	struct timeval start_time, end_time;

	union {
		struct sockaddr_in addr;
		struct sockaddr_in6 addr6;
	};
};

#define MAX_CONNS	1024
static struct conn conns[MAX_CONNS];

#define vlog(str, ...) do {							\
	if (verbose)							\
		printf(str, ##__VA_ARGS__);				\
} while (0)

static struct conn *cqe_to_conn(struct io_uring_cqe *cqe)
{
	struct userdata ud = { .val = cqe->user_data };

	return &conns[ud.op_tid & TID_MASK];
}

static struct conn_dir *fd_to_conn_dir(struct conn *c, int fd)
{
	return &c->cd[fd != c->in_fd];
}

/*
 * Goes from accept new connection -> create socket, connect to end
 * point, prepare recv, on receive do send (unless sink). If either ends
 * disconnects, we transition to shutdown and then close.
 */
enum {
	__ACCEPT	= 1,
	__SOCK		= 2,
	__CONNECT	= 3,
	__RECV		= 4,
	__SEND		= 5,
	__SHUTDOWN	= 6,
	__CANCEL	= 7,
	__CLOSE		= 8,
};

struct error_handler {
	const char *name;
	int (*error_fn)(struct error_handler *, struct io_uring *, struct io_uring_cqe *);
};

static int recv_error(struct error_handler *err, struct io_uring *ring,
		      struct io_uring_cqe *cqe);

static int default_error(struct error_handler *err,
			 struct io_uring __attribute__((__unused__)) *ring,
			 struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);

	fprintf(stderr, "%d: %s error %s\n", c->tid, err->name, strerror(-cqe->res));
	fprintf(stderr, "fd=%d, bid=%d\n", cqe_to_fd(cqe), cqe_to_bid(cqe));
	return 1;
}

/*
 * Move error handling out of the normal handling path, cleanly seperating
 * them. If an opcode doesn't need any error handling, set it to NULL. If
 * it wants to stop the connection at that point and not do anything else,
 * then the default handler can be used. Only receive has proper error
 * handling, as we can get -ENOBUFS which is not a fatal condition. It just
 * means we need to wait on buffer replenishing before re-arming the receive.
 */
static struct error_handler error_handlers[] = {
	{ .name = "NULL",	.error_fn = NULL, },
	{ .name = "ACCEPT",	.error_fn = default_error, },
	{ .name = "SOCK",	.error_fn = default_error, },
	{ .name = "CONNECT",	.error_fn = default_error, },
	{ .name = "RECV",	.error_fn = recv_error, },
	{ .name = "SEND",	.error_fn = default_error, },
	{ .name = "SHUTDOWN",	.error_fn = NULL, },
	{ .name = "CANCEL",	.error_fn = NULL, },
	{ .name = "CLOSE",	.error_fn = NULL, },
};

static void free_buffer_ring(struct io_uring *ring, struct conn_buf_ring *cbr)
{
	if (!cbr->br)
		return;

	io_uring_free_buf_ring(ring, cbr->br, nr_bufs, cbr->bgid);
	cbr->br = NULL;
	free(cbr->buf);
}

static void free_buffer_rings(struct io_uring *ring, struct conn *c)
{
	free_buffer_ring(ring, &c->in_br);
	free_buffer_ring(ring, &c->out_br);
}

/*
 * Setup a ring provided buffer ring for each connection. If we get -ENOBUFS
 * on receive, for multishot receive we'll wait for half the provided buffers
 * to be returned by pending sends, then re-arm the multishot receive. If
 * this happens too frequently (see enobufs= stat), then the ring size is
 * likely too small. Use -nXX to make it bigger. See handle_enobufs().
 *
 * The alternative here would be to use the older style provided buffers,
 * where you simply setup a buffer group and use SQEs with
 * io_urign_prep_provide_buffers() to add to the pool. But that approach is
 * slower and has been deprecated by using the faster ring provided buffers.
 */
static int setup_recv_ring(struct io_uring *ring, struct conn *c)
{
	struct conn_buf_ring *cbr = &c->in_br;
	int ret, i;
	void *ptr;

	cbr->buf = NULL;

	if (posix_memalign(&cbr->buf, page_size, buf_size * nr_bufs)) {
		perror("posix memalign");
		return 1;
	}

	cbr->br = io_uring_setup_buf_ring(ring, nr_bufs, cbr->bgid, 0, &ret);
	if (!cbr->br) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	ptr = cbr->buf;
	for (i = 0; i < nr_bufs; i++) {
		vlog("%d: add bid %d, data %p\n", c->tid, i, ptr);
		io_uring_buf_ring_add(cbr->br, ptr, buf_size, i, br_mask, i);
		ptr += buf_size;
	}
	io_uring_buf_ring_advance(cbr->br, nr_bufs);
	printf("%d: recv buffer ring bgid %d, bufs %d\n", c->tid, cbr->bgid, nr_bufs);
	return 0;
}

/*
 * If 'send_ring' is used and the kernel supports it, we can skip serializing
 * sends as the data will be ordered regardless. This reduces the send handling
 * complexity, as buffers can always be added to the outgoing ring and will be
 * processed in the order in which they were added.
 */
static int setup_send_ring(struct io_uring *ring, struct conn *c)
{
	struct conn_buf_ring *cbr = &c->out_br;
	int ret;

	cbr->br = io_uring_setup_buf_ring(ring, nr_bufs, cbr->bgid, 0, &ret);
	if (!cbr->br) {
		fprintf(stderr, "Buffer ring register failed %d\n", ret);
		return 1;
	}

	printf("%d: send buffer ring bgid %d, bufs %d\n", c->tid, cbr->bgid, nr_bufs);
	return 0;
}

/*
 * Setup an input and output buffer ring
 */
static int setup_buffer_rings(struct io_uring *ring, struct conn *c)
{
	int ret;

	c->in_br.bgid = cur_bgid++;
	c->out_br.bgid = cur_bgid++;
	c->out_br.br = NULL;

	ret = setup_recv_ring(ring, c);
	if (ret)
		return ret;
	if (is_sink || !send_ring)
		return 0;

	ret = setup_send_ring(ring, c);
	if (ret) {
		free_buffer_ring(ring, &c->in_br);
		return ret;
	}

	return 0;
}

static void __show_stats(struct conn *c)
{
	unsigned long msec, qps;
	struct conn_dir *cd;
	int i;

	if (c->flags & CONN_F_STATS_SHOWN)
		return;

	if (!(c->flags & CONN_F_END_TIME))
		gettimeofday(&c->end_time, NULL);

	msec = (c->end_time.tv_sec - c->start_time.tv_sec) * 1000;
	msec += (c->end_time.tv_usec - c->start_time.tv_usec) / 1000;

	qps = 0;
	for (i = 0; i < 2; i++)
		qps += c->cd[i].rcv + c->cd[i].snd;

	if (!qps)
		return;

	if (msec)
		qps = (qps * 1000) / msec;

	printf("Conn %d/(in_fd=%d, out_fd=%d): qps=%lu, msec=%lu\n", c->tid,
					c->in_fd, c->out_fd, qps, msec);

	for (i = 0; i < 2; i++) {
		cd = &c->cd[i];

		if (!cd->in_bytes && !cd->out_bytes)
			continue;

		printf("\t%3d: rcv=%u (short=%u), snd=%u (short=%u, busy=%u)\n",
			i, cd->rcv, cd->rcv_shrt, cd->snd, cd->snd_shrt,
			cd->snd_busy);
		printf("\t   : in_bytes=%lu (Kb %lu), out_bytes=%lu (Kb %lu)\n",
			cd->in_bytes, cd->in_bytes >> 10,
			cd->out_bytes, cd->out_bytes >> 10);
		printf("\t   : mshot_submit=%d, enobufs=%d\n",
			cd->mshot_submit, cd->enobufs);

	}

	c->flags |= CONN_F_STATS_SHOWN;
}

static void show_stats(void)
{
	float events_per_loop = 0.0;
	static int stats_shown;
	int i;

	if (stats_shown)
		return;

	if (events)
		events_per_loop = (float) events / (float) event_loops;

	printf("Event loops: %lu, events %lu, events per loop %.2f\n", event_loops,
							events, events_per_loop);

	for (i = 0; i < MAX_CONNS; i++) {
		struct conn *c = &conns[i];

		__show_stats(c);
	}
	stats_shown = 1;
}

static void sig_int(int __attribute__((__unused__)) sig)
{
	printf("\n");
	show_stats();
	exit(1);
}

/*
 * Special cased for SQPOLL only, as we don't control when SQEs are consumed if
 * that is used. Hence we may need to wait for the SQPOLL thread to keep up
 * until we can get a new SQE. All other cases will break immediately, with a
 * fresh SQE.
 *
 * If we grossly undersized our SQ ring, getting a NULL sqe can happen even
 * for the !SQPOLL case if we're handling a lot of CQEs in our event loop
 * and multishot isn't used. We can do io_uring_submit() to flush what we
 * have here. Only caveat here is that if linked requests are used, SQEs
 * would need to be allocated upfront as a link chain is only valid within
 * a single submission cycle.
 */
static struct io_uring_sqe *get_sqe(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;

	do {
		sqe = io_uring_get_sqe(ring);
		if (sqe)
			break;
		if (!sqpoll)
			io_uring_submit(ring);
		else
			io_uring_sqring_wait(ring);
	} while (1);

	return sqe;
}

static void encode_userdata(struct io_uring_sqe *sqe, struct conn *c, int op,
			    int bid, int fd)
{
	__encode_userdata(sqe, c->tid, op, bid, fd);
}

/*
 * Given a bgid/bid, return the buffer associated with it.
 */
static void *get_buf(struct conn *c, int bid)
{
	struct conn_buf_ring *cbr = &c->in_br;

	return cbr->buf + bid * buf_size;
}

static void __submit_receive(struct io_uring *ring, struct conn *c, int fd)
{
	struct conn_buf_ring *cbr = &c->in_br;
	struct io_uring_sqe *sqe;
	struct msghdr msg;
	struct iovec iov;

	vlog("%d: submit receive fd=%d\n", c->tid, fd);

	if (use_msg) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = NULL;
		iov.iov_len = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
	}

	/*
	 * For both recv and multishot receive, we use the ring provided
	 * buffers. These are handed to the application ahead of time, and
	 * are consumed when a receive triggers. Note that the address and
	 * length of the receive are set to NULL/0, and we assign the
	 * sqe->buf_group to tell the kernel which buffer group ID to pick
	 * a buffer from. Finally, IOSQE_BUFFER_SELECT is set to tell the
	 * kernel that we want a buffer picked for this request, we are not
	 * passing one in with the request.
	 */
	sqe = get_sqe(ring);
	if (mshot) {
		fd_to_conn_dir(c, fd)->mshot_submit++;
		if (use_msg)
			io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
		else
			io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
	} else {
		if (use_msg)
			io_uring_prep_recvmsg(sqe, fd, &msg, 0);
		else
			io_uring_prep_recv(sqe, fd, NULL, 0, 0);
	}

	encode_userdata(sqe, c, __RECV, 0, fd);
	sqe->buf_group = cbr->bgid;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	if (fixed_files)
		sqe->flags |= IOSQE_FIXED_FILE;

	/* must submit to avoid msg/iov going out-of-scope */
	if (use_msg)
		io_uring_submit(ring);
}

/*
 * One directional just arms receive on our in_fd
 */
static void submit_receive(struct io_uring *ring, struct conn *c)
{
	__submit_receive(ring, c, c->in_fd);
}

/*
 * Bi-directional arms receive on both in and out fd
 */
static void submit_bidi_receive(struct io_uring *ring, struct conn *c)
{
	__submit_receive(ring, c, c->in_fd);
	__submit_receive(ring, c, c->out_fd);
}

/*
 * We hit -ENOBUFS, which means that we ran out of buffers in our current
 * provided buffer group. This can happen if there's an imbalance between the
 * receives coming in and the sends being processed, particularly with multishot
 * receive as they can trigger very quickly. If this happens, defer arming a
 * new receive until we've replenished half of the buffer pool by processing
 * pending sends.
 */
static void handle_enobufs(struct io_uring *ring, struct conn *c,
			   struct conn_dir *cd, int fd)
{
	int send_waits;

	vlog("%d: enobufs hit\n", c->tid);

	cd->enobufs++;

	send_waits = nr_bufs / 2;
	if (send_ring)
		send_waits = c->cd[0].pending_sends + c->cd[1].pending_sends;

	/* sink has no sends to wait for, no choice but to re-arm */
	if (is_sink || !send_waits) {
		__submit_receive(ring, c, fd);
		return;
	}

	cd->rearm_recv = send_waits;

	/* really shouldn't use 1 buffer ring... */
	if (!cd->rearm_recv)
		cd->rearm_recv = 1;
}

/*
 * Kill this socket - submit a shutdown and link a close to it. We don't
 * care about shutdown status, so mark it as not needing to post a CQE unless
 * it fails.
 */
static void queue_shutdown_close(struct io_uring *ring, struct conn *c, int fd)
{
	struct io_uring_sqe *sqe1, *sqe2;

	/*
	 * On the off chance that we run out of SQEs after the first one,
	 * grab two upfront. This it to prevent our link not working if
	 * get_sqe() ends up doing submissions to free up an SQE, as links
	 * are not valid across separate submissions.
	 */
	sqe1 = get_sqe(ring);
	sqe2 = get_sqe(ring);

	io_uring_prep_shutdown(sqe1, fd, SHUT_RDWR);
	if (fixed_files)
		sqe1->flags |= IOSQE_FIXED_FILE;
	sqe1->flags |= IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS;
	encode_userdata(sqe1, c, __SHUTDOWN, 0, fd);

	if (fixed_files)
		io_uring_prep_close_direct(sqe2, fd);
	else
		io_uring_prep_close(sqe2, fd);
	encode_userdata(sqe2, c, __CLOSE, 0, fd);
}

static void queue_cancel(struct io_uring *ring, struct conn *c)
{
	struct io_uring_sqe *sqe;
	int flags = 0;

	if (fixed_files)
		flags |= IORING_ASYNC_CANCEL_FD_FIXED;

	sqe = get_sqe(ring);
	io_uring_prep_cancel_fd(sqe, c->in_fd, flags);
	encode_userdata(sqe, c, __CANCEL, 0, c->in_fd);
	c->pending_cancels++;

	if (c->out_fd != -1) {
		sqe = get_sqe(ring);
		io_uring_prep_cancel_fd(sqe, c->in_fd, flags);
		encode_userdata(sqe, c, __CANCEL, 0, c->in_fd);
		c->pending_cancels++;
	}

	io_uring_submit(ring);
}

static int pending_shutdown(struct conn *c)
{
	return c->cd[0].pending_shutdown + c->cd[1].pending_shutdown;
}

static bool should_shutdown(struct conn *c)
{
	int i;

	if (!pending_shutdown(c))
		return false;
	if (is_sink)
		return true;
	if (!bidi)
		return c->cd[0].rcv == c->cd[1].snd;

	for (i = 0; i < 2; i++) {
		if (c->cd[0].rcv != c->cd[1].snd)
			return false;
		if (c->cd[1].rcv != c->cd[0].snd)
			return false;
	}

	return true;
}

static void __close_conn(struct io_uring *ring, struct conn *c)
{
	printf("Client %d: queueing shutdown\n", c->tid);

	queue_cancel(ring, c);
	io_uring_submit(ring);
}

static void close_cd(struct conn *c, struct conn_dir *cd)
{
	if (cd->pending_sends)
		return;

	cd->pending_shutdown = 1;
	if (!(c->flags & CONN_F_PENDING_SHUTDOWN)) {
		gettimeofday(&c->end_time, NULL);
		c->flags |= CONN_F_PENDING_SHUTDOWN | CONN_F_END_TIME;
	}
}

/*
 * We're done with this buffer, add it back to our pool so the kernel is
 * free to use it again.
 */
static void replenish_buffer(struct conn *c, int bid)
{
	struct conn_buf_ring *cbr = &c->in_br;
	void *this_buf;

	this_buf = cbr->buf + bid * buf_size;

	io_uring_buf_ring_add(cbr->br, this_buf, buf_size, bid, br_mask, 0);
	io_uring_buf_ring_advance(cbr->br, 1);
}

static void __queue_send(struct io_uring *ring, struct conn *c, int fd,
			 void *data, int bid, int len)
{
	struct conn_dir *cd = fd_to_conn_dir(c, fd);
	struct io_uring_sqe *sqe;
	struct iovec iov;
	struct msghdr msg;
	int bgid = 0;

	vlog("%d: send %d to fd %d (%p, bid %d)\n", c->tid, len, fd, data, bid);

	/* if using provided buffers for send, add it upfront */
	if (send_ring) {
		struct conn_buf_ring *cbr = &c->out_br;

		io_uring_buf_ring_add(cbr->br, data, len, bid, br_mask, 0);
		io_uring_buf_ring_advance(cbr->br, 1);
		bgid = cbr->bgid;
	}

	sqe = get_sqe(ring);
	if (use_msg) {
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = data;
		iov.iov_len = len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		io_uring_prep_sendmsg(sqe, fd, &msg, MSG_WAITALL | MSG_NOSIGNAL);
	} else {
		if (send_ring)
			data = NULL;
		io_uring_prep_send(sqe, fd, data, len, MSG_WAITALL | MSG_NOSIGNAL);
	}
	encode_userdata(sqe, c, __SEND, bid, fd);
	if (fixed_files)
		sqe->flags |= IOSQE_FIXED_FILE;
	if (send_ring) {
		sqe->flags |= IOSQE_BUFFER_SELECT;
		sqe->buf_group = bgid;
	}
	cd->pending_sends++;

	/* must submit to avoid msg/iov going out-of-scope */
	if (use_msg)
		io_uring_submit(ring);
}

/*
 * Submit any deferred sends (see comment for defer_send()).
 */
static void submit_deferred_send(struct io_uring *ring, struct conn *c,
				 struct conn_dir *cd)
{
	struct pending_send *ps;

	if (list_empty(&cd->send_list)) {
		vlog("%d: defer send %p empty\n", c->tid, cd);
		return;
	}

	vlog("%d: queueing deferred send %p\n", c->tid, cd);

	ps = list_first_entry(&cd->send_list, struct pending_send, list);
	list_del(&ps->list);
	__queue_send(ring, c, ps->fd, ps->data, ps->bid, ps->len);
	free(ps);
}

/*
 * We have pending sends on this socket. Normally this is not an issue, but
 * if we don't serialize sends, then we can get into a situation where the
 * following can happen:
 *
 * 1) Submit sendA for socket1
 * 2) socket1 buffer is full, poll is armed for sendA
 * 3) socket1 space frees up
 * 4) Poll triggers retry for sendA
 * 5) Submit sendB for socket1
 * 6) sendB completes
 * 7) sendA is retried
 *
 * Regardless of the outcome of what happens with sendA in step 7 (it completes
 * or it gets deferred because the socket1 buffer is now full again after sendB
 * has been filled), we've now reordered the received data.
 *
 * This isn't a common occurence, but more likely with big buffers. If we never
 * run into out-of-space in the socket, we could easily support having more than
 * one send in-flight at the same time.
 *
 * Something to think about on the kernel side...
 */
static void defer_send(struct conn *c, struct conn_dir *cd, int bid, int len,
		       int out_fd)
{
	void *data = get_buf(c, bid);
	struct pending_send *ps;

	vlog("%d: defer send %d to fd %d (%p, bid %d)\n", c->tid, len, out_fd,
					data, bid);
	vlog("%d: pending %d, %p\n", c->tid, cd->pending_sends, cd);

	cd->snd_busy++;
	ps = malloc(sizeof(*ps));
	ps->fd = out_fd;
	ps->bid = bid;
	ps->len = len;
	ps->data = data;
	list_add_tail(&ps->list, &cd->send_list);
}

/*
 * Queue a send based on the data received in this cqe, which came from
 * a completed receive operation.
 */
static void queue_send(struct io_uring *ring, struct conn *c, int bid, int len,
		       int out_fd)
{
	struct conn_dir *cd = fd_to_conn_dir(c, out_fd);

	/* no need to serialize sends if we use an outgoing buffer ring */
	if (!send_ring && cd->pending_sends) {
		defer_send(c, cd, bid, len, out_fd);
	} else {
		void *data = get_buf(c, bid);

		__queue_send(ring, c, out_fd, data, bid, len);
	}
}

static int handle_accept(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct io_uring_sqe *sqe;
	struct conn *c;
	int domain;

	if (nr_conns == MAX_CONNS) {
		fprintf(stderr, "max clients reached %d\n", nr_conns);
		return 1;
	}

	c = &conns[nr_conns];
	c->tid = nr_conns++;
	c->in_fd = cqe->res;
	c->out_fd = -1;
	gettimeofday(&c->start_time, NULL);

	open_conns++;

	printf("New client: id=%d, in=%d\n", c->tid, c->in_fd);

	if (setup_buffer_rings(ring, c))
		return 1;

	init_list_head(&c->cd[0].send_list);
	init_list_head(&c->cd[1].send_list);

	if (is_sink) {
		submit_receive(ring, c);
		return 0;
	}

	if (ipv6)
		domain = AF_INET6;
	else
		domain = AF_INET;

	/*
	 * If fixed_files is set, proxy will use fixed files for any
	 * new file descriptors it instantiates. Fixd files, or fixed
	 * descriptors, are io_uring private file descriptors. They
	 * cannot be accessed outside of io_uring. io_uring holds a
	 * fixed reference to them, which means that we do not need to
	 * grab per-request references to them. Particularly for
	 * threaded applications, grabbing and dropping file references
	 * for each operation can be costly as the file table is shared.
	 * This generally shows up as fget/fput related overhead in
	 * any workload profiles.
	 *
	 * Fixed descriptors are passed in via the 'fd' field just
	 * like regular descriptors, and then marked as such by
	 * setting the IOSQE_FIXED_FILE flag in the sqe->flags field.
	 * Some helpers do that automatically, like the below, others
	 * will need it set manually if they don't have a *direct*()
	 * helper.
	 *
	 * For operations that instantiate them, like the opening of
	 * a direct socket, the application may either ask the kernel
	 * to find a free one (as is done below), or the application
	 * may manage the space itself and pass in an index for a
	 * currently free slot in the table. If the kernel is asked
	 * to allocate a free direct descriptor, note that io_uring
	 * does not abide by the POSIX mandated "lowest free must be
	 * returned". It may return any free descriptor of its
	 * choosing.
	 */
	sqe = get_sqe(ring);
	if (fixed_files)
		io_uring_prep_socket_direct_alloc(sqe, domain, SOCK_STREAM, 0, 0);
	else
		io_uring_prep_socket(sqe, domain, SOCK_STREAM, 0, 0);
	encode_userdata(sqe, c, __SOCK, 0, 0);
	return 0;
}

static int handle_sock(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	struct io_uring_sqe *sqe;
	int ret;

	vlog("%d: sock: res=%d\n", c->tid, cqe->res);

	c->out_fd = cqe->res;

	if (ipv6) {
		memset(&c->addr6, 0, sizeof(c->addr6));
		c->addr6.sin6_family = AF_INET6;
		c->addr6.sin6_port = htons(send_port);
		ret = inet_pton(AF_INET6, host, &c->addr6.sin6_addr);
	} else {
		memset(&c->addr, 0, sizeof(c->addr));
		c->addr.sin_family = AF_INET;
		c->addr.sin_port = htons(send_port);
		ret = inet_pton(AF_INET, host, &c->addr.sin_addr);
	}
	if (ret <= 0) {
		if (!ret)
			fprintf(stderr, "host not in right format\n");
		else
			perror("inet_pton");
		return 1;
	}

	sqe = get_sqe(ring);
	if (ipv6) {
		io_uring_prep_connect(sqe, c->out_fd,
					(struct sockaddr *) &c->addr6,
					sizeof(c->addr6));
	} else {
		io_uring_prep_connect(sqe, c->out_fd,
					(struct sockaddr *) &c->addr,
					sizeof(c->addr));
	}
	encode_userdata(sqe, c, __CONNECT, 0, c->out_fd);
	if (fixed_files)
		sqe->flags |= IOSQE_FIXED_FILE;
	return 0;
}

static int handle_connect(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);

	if (bidi)
		submit_bidi_receive(ring, c);
	else
		submit_receive(ring, c);

	return 0;
}

static int __handle_recv(struct io_uring *ring, struct conn *c,
			 struct io_uring_cqe *cqe, int in_fd, int out_fd)
{
	struct conn_dir *cd = fd_to_conn_dir(c, in_fd);
	int bid, do_recv = !mshot;

	/*
	 * Not having a buffer attached should only happen if we get a zero
	 * sized receive, because the other end closed the connection. It
	 * cannot happen otherwise, as all our receives are using provided
	 * buffers and hence it's not possible to return a CQE with a non-zero
	 * result and not have a buffer attached.
	 */
	if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
		if (!cqe->res) {
			close_cd(c, cd);
			return 0;
		}
		fprintf(stderr, "no buffer assigned, res=%d\n", cqe->res);
		return 1;
	}

	cd->rcv++;

	if (cqe->res != buf_size)
		cd->rcv_shrt++;

	/*
	 * If multishot terminates, just submit a new one.
	 */
	if (mshot && !(cqe->flags & IORING_CQE_F_MORE))
		do_recv = 1;

	bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;

	vlog("%d: recv: bid=%d, res=%d\n", c->tid, bid, cqe->res);

	/*
	 * If we're a sink, we're done here. Just replenish the buffer back
	 * to the pool. For proxy mode, we will send the data to the other
	 * end and the buffer will be replenished once the send is done with
	 * it.
	 */
	if (is_sink)
		replenish_buffer(c, bid);
	else
		queue_send(ring, c, bid, cqe->res, out_fd);

	cd->in_bytes += cqe->res;

	/*
	 * If we're not doing multishot receive, or if multishot receive
	 * terminated, we need to submit a new receive request as this one
	 * has completed. Multishot will stay armed.
	 */
	if (do_recv)
		__submit_receive(ring, c, in_fd);

	return 0;
}

static int handle_recv(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	int fd = cqe_to_fd(cqe);

	if (fd == c->in_fd)
		return __handle_recv(ring, c, cqe, c->in_fd, c->out_fd);

	return __handle_recv(ring, c, cqe, c->out_fd, c->in_fd);
}

static int recv_error(struct error_handler *err, struct io_uring *ring,
		      struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	int in_fd, fd = cqe_to_fd(cqe);

	if (cqe->res != -ENOBUFS)
		return default_error(err, ring, cqe);

	if (fd == c->in_fd)
		in_fd = c->in_fd;
	else
		in_fd = c->out_fd;

	handle_enobufs(ring, c, fd_to_conn_dir(c, in_fd), in_fd);
	return 0;
}

/*
 * Check if we have a pending receive resubmit after buffer replenish. If
 * this is the case, ->rearm_recv will be set in the other data direction.
 * If set, decrement it. If we've now hit zero pending replenishes, then
 * resubmit the receive operation.
 */
static void check_recv_rearm(struct io_uring *ring, struct conn *c,
			     struct conn_dir *cd, int fd)
{
	struct conn_dir *ocd;

	if (cd == &c->cd[0])
		ocd = &c->cd[1];
	else
		ocd = &c->cd[0];

	if (!ocd->rearm_recv)
		return;

	vlog("%d: rearm_recv=%d\n", c->tid, ocd->rearm_recv);

	if (!--ocd->rearm_recv) {
		int in_fd;

		if (fd == c->in_fd)
			in_fd = c->out_fd;
		else
			in_fd = c->in_fd;

		vlog("%d: arm recv on replenish\n", c->tid);
		__submit_receive(ring, c, in_fd);
	}
}

static int handle_send(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	int fd = cqe_to_fd(cqe);
	struct conn_dir *cd = fd_to_conn_dir(c, fd);
	int bid;

	cd->snd++;
	cd->out_bytes += cqe->res;

	if (cqe->res != buf_size)
		cd->snd_shrt++;

	if (send_ring) {
		if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
			fprintf(stderr, "no buffer in send?!\n");
			return 1;
		}
		bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
	} else {
		bid = cqe_to_bid(cqe);
	}

	vlog("%d: send: bid=%d, res=%d\n", c->tid, bid, cqe->res);

	/*
	 * Find the provided buffer that the receive consumed, and
	 * which we then used for the send, and add it back to the
	 * pool so it can get picked by another receive. Once the send
	 * is done, we're done with it.
	 */
	replenish_buffer(c, bid);

	cd->pending_sends--;

	vlog("%d: pending sends %d\n", c->tid, cd->pending_sends);

	if (!cd->pending_sends) {
		if (!cqe->res)
			close_cd(c, cd);
		else
			submit_deferred_send(ring, c, cd);
	}

	/*
	 * Check if we need to re-arm receive after this send has added a
	 * buffer back into the pool.
	 */
	check_recv_rearm(ring, c, cd, fd);
	return 0;
}

/*
 * We don't expect to get here, as we marked it with skipping posting a
 * CQE if it was successful. If it does trigger, than means it fails and
 * that our close has not been done. Log the shutdown error and issue a new
 * separate close.
 */
static int handle_shutdown(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	struct io_uring_sqe *sqe;
	int fd = cqe_to_fd(cqe);

	fprintf(stderr, "Got shutdown notication on fd %d\n", fd);

	if (!cqe->res)
		fprintf(stderr, "Unexpected success shutdown CQE\n");
	else if (cqe->res < 0)
		fprintf(stderr, "Shutdown got %s\n", strerror(-cqe->res));

	sqe = get_sqe(ring);
	if (fixed_files)
		io_uring_prep_close_direct(sqe, fd);
	else
		io_uring_prep_close(sqe, fd);
	encode_userdata(sqe, c, __CLOSE, 0, fd);
	return 0;
}

/*
 * Final stage of a connection, the shutdown and close has finished. Mark
 * it as disconnected and let the main loop reap it.
 */
static int handle_close(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	int fd = cqe_to_fd(cqe);

	c->flags |= CONN_F_DISCONNECTED;

	printf("Closed client: id=%d, in_fd=%d, out_fd=%d\n", c->tid, c->in_fd, c->out_fd);
	if (fd == c->in_fd)
		c->in_fd = -1;
	else if (fd == c->out_fd)
		c->out_fd = -1;

	if (c->in_fd == -1 && c->out_fd == -1) {
		__show_stats(c);
		open_conns--;
		free_buffer_rings(ring, c);
	}

	return 0;
}

static int handle_cancel(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	struct conn *c = cqe_to_conn(cqe);
	int fd = cqe_to_fd(cqe);

	c->pending_cancels--;

	vlog("%d: got cancel fd %d, refs %d\n", c->tid, fd, c->pending_cancels);

	if (!c->pending_cancels) {
		queue_shutdown_close(ring, c, c->in_fd);
		if (c->out_fd != -1)
			queue_shutdown_close(ring, c, c->out_fd);
		io_uring_submit(ring);
	}

	return 0;
}

/*
 * Called for each CQE that we receive. Decode the request type that it
 * came from, and call the appropriate handler.
 */
static int handle_cqe(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	int ret;

	/*
	 * Unlikely, but there's an error in this CQE. If an error handler
	 * is defined, call it, and that will deal with it. If no error
	 * handler is defined, the opcode handler either doesn't care or will
	 * handle it on its own.
	 */
	if (cqe->res < 0) {
		struct error_handler *err = &error_handlers[cqe_to_op(cqe)];

		if (err->error_fn)
			return err->error_fn(err, ring, cqe);
	}

	switch (cqe_to_op(cqe)) {
	case __ACCEPT:
		ret = handle_accept(ring, cqe);
		break;
	case __SOCK:
		ret = handle_sock(ring, cqe);
		break;
	case __CONNECT:
		ret = handle_connect(ring, cqe);
		break;
	case __RECV:
		ret = handle_recv(ring, cqe);
		break;
	case __SEND:
		ret = handle_send(ring, cqe);
		break;
	case __CANCEL:
		ret = handle_cancel(ring, cqe);
		break;
	case __SHUTDOWN:
		ret = handle_shutdown(ring, cqe);
		break;
	case __CLOSE:
		ret = handle_close(ring, cqe);
		break;
	default:
		fprintf(stderr, "bad user data %lx\n", (long) cqe->user_data);
		return 1;
	}

	return ret;
}

static void usage(const char *name)
{
	printf("%s:\n", name);
	printf("\t-m:\t\tUse multishot receive (%d)\n", mshot);
	printf("\t-d:\t\tUse DEFER_TASKRUN (%d)\n", defer_tw);
	printf("\t-S:\t\tUse SQPOLL (%d)\n", sqpoll);
	printf("\t-b:\t\tSend/receive buf size (%d)\n", buf_size);
	printf("\t-u:\t\tUse provided buffers for send (%d)\n", send_ring);
	printf("\t-n:\t\tNumber of provided buffers (pow2) (%d)\n", nr_bufs);
	printf("\t-w:\t\tNumber of CQEs to wait for each loop (%d)\n", wait_batch);
	printf("\t-t:\t\tTimeout for waiting on CQEs (usec) (%d)\n", wait_usec);
	printf("\t-s:\t\tAct only as a sink (%d)\n", is_sink);
	printf("\t-f:\t\tUse only fixed files (%d)\n", fixed_files);
	printf("\t-B:\t\tUse bi-directional mode (%d)\n", bidi);
	printf("\t-H:\t\tHost to connect to (%s)\n", host);
	printf("\t-r:\t\tPort to receive on (%d)\n", receive_port);
	printf("\t-p:\t\tPort to connect to (%d)\n", send_port);
	printf("\t-6:\t\tUse IPv6 (%d)\n", ipv6);
	printf("\t-N:\t\tUse NAPI polling (%d)\n", napi);
	printf("\t-T:\t\tNAPI timeout (usec) (%d)\n", napi_timeout);
	printf("\t-M:\t\tUse send/recvmsg (%d)\n", use_msg);
	printf("\t-V:\t\tIncrease verbosity (%d)\n", verbose);
}

static void check_for_close(struct io_uring *ring)
{
	int i;

	for (i = 0; i < nr_conns; i++) {
		struct conn *c = &conns[i];

		if (c->flags & (CONN_F_DISCONNECTING | CONN_F_DISCONNECTED))
			continue;
		if (should_shutdown(c)) {
			__close_conn(ring, c);
			c->flags |= CONN_F_DISCONNECTING;
		}
	}
}

/*
 * Main event loop, Submit our multishot accept request, and then just loop
 * around handling incoming events.
 */
static int event_loop(struct io_uring *ring, int fd)
{
	struct __kernel_timespec active_ts, idle_ts = { .tv_sec = 1, };
	struct io_uring_sqe *sqe;
	int flags;

	/*
	 * proxy provides a way to use either multishot receive or not, but
	 * for accept, we always use multishot. A multishot accept request
	 * needs only be armed once, and then it'll trigger a completion and
	 * post a CQE whenever a new connection is accepted. No need to do
	 * anything else, unless the multishot accept terminates. This happens
	 * if it encounters an error. Applications should check for
	 * IORING_CQE_F_MORE in cqe->flags - this tells you if more completions
	 * are expected from this request or not. Non-multishot never have
	 * this set, where multishot will always have this set unless an error
	 * occurs.
	 */
	sqe = get_sqe(ring);
	if (fixed_files)
		io_uring_prep_multishot_accept_direct(sqe, fd, NULL, NULL, 0);
	else
		io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);
	__encode_userdata(sqe, 0, __ACCEPT, 0, fd);

	if (wait_usec > 1000000) {
		active_ts.tv_sec = wait_usec / 1000000;
		wait_usec -= active_ts.tv_sec * 1000000;
	}
	active_ts.tv_nsec = wait_usec * 1000;

	flags = 0;
	while (1) {
		struct __kernel_timespec *ts = &idle_ts;
		struct io_uring_cqe *cqe;
		unsigned int head;
		int i, to_wait;

		/*
		 * If wait_batch is set higher than 1, then we'll wait on
		 * that amount of CQEs to be posted each loop. If used with
		 * DEFER_TASKRUN, this can provide a substantial reduction
		 * in context switch rate as the task isn't woken until the
		 * requested number of events can be returned.
		 *
		 * Can be used with -t to set a wait_usec timeout as well.
		 * For example, if an application can deal with 250 usec
		 * of wait latencies, it can set -w8 -t250 which will cause
		 * io_uring to return when either 8 events have been received,
		 * or if 250 usec of waiting has passed.
		 *
		 * If we don't have any open connections, wait on just 1
		 * always.
		 */
		to_wait = 1;
		if (open_conns && !flags) {
			ts = &active_ts;
			to_wait = open_conns * wait_batch;
		}

		io_uring_submit_and_wait_timeout(ring, &cqe, to_wait, ts, NULL);

		i = flags = 0;
		io_uring_for_each_cqe(ring, head, cqe) {
			if (handle_cqe(ring, cqe))
				return 1;
			flags |= cqe_to_conn(cqe)->flags;
			++i;
		}

		/*
		 * Advance the CQ ring for seen events when we've processed
		 * all of them in this loop. This can also be done with
		 * io_uring_cqe_seen() in each handler above, which just marks
		 * that single CQE as seen. However, it's more efficient to
		 * mark a batch as seen when we're done with that batch.
		 */
		if (i)
			io_uring_cq_advance(ring, i);
		if (!i || (flags & (CONN_F_PENDING_SHUTDOWN)))
			check_for_close(ring);

		event_loops++;
		events += i;
	}

	return 0;
}

/*
 * Options parsing the ring / net setup
 */
int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_params params;
	struct sigaction sa = { };
	int opt, ret, fd;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	while ((opt = getopt(argc, argv, "m:d:S:s:b:f:H:r:p:n:B:N:T:w:t:M:u:6Vh?")) != -1) {
		switch (opt) {
		case 'm':
			mshot = !!atoi(optarg);
			break;
		case 'S':
			sqpoll = !!atoi(optarg);
			break;
		case 'd':
			defer_tw = !!atoi(optarg);
			break;
		case 'b':
			buf_size = atoi(optarg);
			break;
		case 'n':
			nr_bufs = atoi(optarg);
			break;
		case 'u':
			send_ring = !!atoi(optarg);
			break;
		case 'w':
			wait_batch = atoi(optarg);
			break;
		case 't':
			wait_usec = atoi(optarg);
			break;
		case 's':
			is_sink = !!atoi(optarg);
			break;
		case 'f':
			fixed_files = !!atoi(optarg);
			break;
		case 'H':
			host = strdup(optarg);
			break;
		case 'r':
			receive_port = atoi(optarg);
			break;
		case 'p':
			send_port = atoi(optarg);
			break;
		case 'B':
			bidi = !!atoi(optarg);
			break;
		case 'N':
			napi = !!atoi(optarg);
			break;
		case 'T':
			napi_timeout = atoi(optarg);
			break;
		case '6':
			ipv6 = true;
			break;
		case 'M':
			use_msg = !!atoi(optarg);
			break;
		case 'V':
			verbose++;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (bidi && is_sink) {
		fprintf(stderr, "Can't be both bidi proxy and sink\n");
		return 1;
	}
	if (use_msg && sqpoll) {
		fprintf(stderr, "SQPOLL with msg variants disabled\n");
		use_msg = 0;
	}

	br_mask = nr_bufs - 1;

	fd = setup_listening_socket(receive_port, ipv6);
	if (is_sink)
		send_port = -1;

	if (fd == -1)
		return 1;

	atexit(show_stats);
	sa.sa_handler = sig_int;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sa, NULL);

	/*
	 * By default, set us up with a big CQ ring. Not strictly needed
	 * here, but it's very important to never overflow the CQ ring.
	 * Events will not be dropped if this happens, but it does slow
	 * the application down in dealing with overflown events.
	 *
	 * Set SINGLE_ISSUER, which tells the kernel that only one thread
	 * is doing IO submissions. This enables certain optimizations in
	 * the kernel.
	 */
	memset(&params, 0, sizeof(params));
	params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_CLAMP;
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = 131072;

	/*
	 * DEFER_TASKRUN decouples async event reaping and retrying from
	 * regular system calls. If this isn't set, then io_uring uses
	 * normal task_work for this. task_work is always being run on any
	 * exit to userspace. Real applications do more than just call IO
	 * related system calls, and hence we can be running this work way
	 * too often. Using DEFER_TASKRUN defers any task_work running to
	 * when the application enters the kernel anyway to wait on new
	 * events. It's generally the preferred and recommended way to setup
	 * a ring.
	 */
	if (defer_tw) {
		params.flags |= IORING_SETUP_DEFER_TASKRUN;
		sqpoll = 0;
	}

	/*
	 * SQPOLL offloads any request submission and retry operations to a
	 * dedicated thread. This enables an application to do IO without
	 * ever having to enter the kernel itself. The SQPOLL thread will
	 * stay busy as long as there's work to do, and go to sleep if
	 * sq_thread_idle msecs have passed. If it's running, submitting new
	 * IO just needs to make them visible to the SQPOLL thread, it needs
	 * not enter the kernel. For submission, the application will only
	 * enter the kernel if the SQPOLL has been idle long enough that it
	 * has gone to sleep.
	 *
	 * Waiting on events still need to enter the kernel, if none are
	 * available. The application may also use io_uring_peek_cqe() to
	 * check for new events without entering the kernel, as completions
	 * will be continually produced to the CQ ring by the SQPOLL thread
	 * as they occur.
	 */
	if (sqpoll) {
		params.flags |= IORING_SETUP_SQPOLL;
		params.sq_thread_idle = 1000;
		defer_tw = 0;
	}

	/*
	 * If neither DEFER_TASKRUN or SQPOLL is used, set COOP_TASKRUN. This
	 * avoids heavy signal based notifications, which can force an
	 * application to enter the kernel and process it as soon as they
	 * occur.
	 */
	if (!sqpoll && !defer_tw)
		params.flags |= IORING_SETUP_COOP_TASKRUN;

	/*
	 * The SQ ring size need not be larger than any batch of requests
	 * that need to be prepared before submit. Normally in a loop we'd
	 * only need a few, if any, particularly if multishot is used.
	 */
	ret = io_uring_queue_init_params(128, &ring, &params);
	if (ret) {
		fprintf(stderr, "%s\n", strerror(-ret));
		return 1;
	}

	/*
	 * If send serialization is available and no option was given to use
	 * it or not, default it to on. If it was turned on and the kernel
	 * doesn't support it, turn it off.
	 */
	if (params.features & IORING_FEAT_SEND_BUFS) {
		if (send_ring == -1)
			send_ring = 1;
	} else {
		if (send_ring == 1) {
			fprintf(stderr, "Kernel doesn't support ring provided "
				"buffers for sends, disabled\n");
		}
		send_ring = 0;
	}

	if (fixed_files) {
		/*
		 * If fixed files are used, we need to allocate a fixed file
		 * table upfront where new direct descriptors can be managed.
		 */
		ret = io_uring_register_files_sparse(&ring, 4096);
		if (ret) {
			fprintf(stderr, "file register: %d\n", ret);
			return 1;
		}

		/*
		 * If fixed files are used, we also register the ring fd. See
		 * comment near io_uring_prep_socket_direct_alloc() further
		 * down. This avoids the fget/fput overhead associated with
		 * the io_uring_enter(2) system call itself, which is used to
		 * submit and wait on events.
		 */
		ret = io_uring_register_ring_fd(&ring);
		if (ret != 1) {
			fprintf(stderr, "ring register: %d\n", ret);
			return 1;
		}
	}

	if (napi) {
		struct io_uring_napi n = {
			.prefer_busy_poll = napi > 1 ? 1 : 0,
			.busy_poll_to = napi_timeout,
		};

		ret = io_uring_register_napi(&ring, &n);
		if (ret) {
			fprintf(stderr, "io_uring_register_napi: %d\n", ret);
			if (ret != -EINVAL)
				return 1;
			fprintf(stderr, "NAPI not available, turned off\n");
		}
	}

	printf("Backend: multishot=%d, sqpoll=%d, defer_tw=%d, fixed_files=%d "
		"is_sink=%d, buf_size=%d, nr_bufs=%d, host=%s, send_port=%d "
		"receive_port=%d, napi=%d, napi_timeout=%d, msg=%d, "
		"send_buf_ring=%d\n",
			mshot, sqpoll, defer_tw, fixed_files, is_sink,
			buf_size, nr_bufs, host, send_port, receive_port,
			napi, napi_timeout, use_msg, send_ring);

	return event_loop(&ring, fd);
}
