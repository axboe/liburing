/* SPDX-License-Identifier: MIT */
/*
 * Description: test IORING_SEND_QUIET, where a successful send posts a CQE
 *		that doesn't wake or count towards waiting for events
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "liburing.h"
#include "helpers.h"

#define UD_SEND		1
#define UD_RECV		2
#define BUF_SIZE	4096

static int no_quiet;
static int no_zc;
static char sbuf[BUF_SIZE];
static char rbuf[BUF_SIZE];

struct conn {
	/* quiet sends go out on snd[0] */
	int snd[2];
	/* recv on rcv[1], the helper thread writes to rcv[0] */
	int rcv[2];
	/* bytes the helper thread drains from snd[1] first */
	size_t drain;
	int drain_ms;
	int write_ms;
};

struct cqes {
	int nr_send, nr_recv, nr_notif;
	int send_res;
};

/* zerocopy needs TCP, otherwise use AF_UNIX to avoid TCP window timers */
static int conn_open(struct conn *c, bool zc)
{
	memset(c, 0, sizeof(*c));
	if (zc) {
		if (t_create_socket_pair(c->snd, true))
			return 1;
	} else if (socketpair(AF_UNIX, SOCK_STREAM, 0, c->snd)) {
		return 1;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, c->rcv)) {
		close(c->snd[0]);
		close(c->snd[1]);
		return 1;
	}
	return 0;
}

static void conn_close(struct conn *c)
{
	close(c->snd[0]);
	close(c->snd[1]);
	close(c->rcv[0]);
	close(c->rcv[1]);
}

/* fill the socket buffer of snd[0], so the next send has to wait */
static size_t conn_fill(struct conn *c)
{
	size_t total = 0;
	int val = BUF_SIZE;
	ssize_t ret;

	setsockopt(c->snd[0], SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
	setsockopt(c->snd[1], SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
	do {
		ret = send(c->snd[0], sbuf, BUF_SIZE, MSG_DONTWAIT);
		if (ret > 0)
			total += ret;
	} while (ret > 0);
	return total;
}

static void *helper(void *data)
{
	struct conn *c = data;
	size_t left = c->drain;
	char buf[BUF_SIZE];

	if (c->drain_ms)
		usleep(c->drain_ms * 1000);
	while (left) {
		ssize_t ret = read(c->snd[1], buf, sizeof(buf));

		if (ret <= 0)
			break;
		left -= ret;
	}
	usleep(c->write_ms * 1000);
	if (write(c->rcv[0], "x", 1) != 1)
		perror("write");
	return NULL;
}

static void queue_recv(struct io_uring *ring, struct conn *c)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_recv(sqe, c->rcv[1], rbuf, sizeof(rbuf), 0);
	sqe->user_data = UD_RECV;
}

/* MSG_WAITALL, as a short send isn't quiet */
static void queue_send(struct io_uring *ring, struct conn *c, bool zc,
		       unsigned sqe_flags)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	if (zc)
		io_uring_prep_send_zc(sqe, c->snd[0], sbuf, BUF_SIZE,
				      MSG_WAITALL, 0);
	else
		io_uring_prep_send(sqe, c->snd[0], sbuf, BUF_SIZE, MSG_WAITALL);
	sqe->ioprio |= IORING_SEND_QUIET;
	sqe->flags |= sqe_flags;
	sqe->user_data = UD_SEND;
}

static void reap(struct io_uring *ring, struct cqes *cs)
{
	struct io_uring_cqe *cqe;

	io_uring_get_events(ring);
	while (!io_uring_peek_cqe(ring, &cqe)) {
		if (cqe->user_data == UD_RECV) {
			cs->nr_recv++;
		} else if (cqe->flags & IORING_CQE_F_NOTIF) {
			cs->nr_notif++;
		} else {
			cs->nr_send++;
			cs->send_res = cqe->res;
		}
		io_uring_cqe_seen(ring, cqe);
	}
}

/*
 * Reap until the expected CQEs have arrived. Quiet ones don't wake a wait,
 * so poll, which also runs task_work for DEFER_TASKRUN.
 */
static void reap_until(struct io_uring *ring, struct cqes *cs, int nr_send,
		       int nr_notif, int nr_recv)
{
	int i;

	for (i = 0; i < 3000; i++) {
		reap(ring, cs);
		if (cs->nr_send >= nr_send && cs->nr_notif >= nr_notif &&
		    cs->nr_recv >= nr_recv)
			break;
		usleep(1000);
	}
}

/*
 * Submit nr quiet sends with a recv on another socket, and wait for one
 * event. That must be the recv, which the helper thread triggers once the
 * sends had time to complete.
 */
static int test_wait_recv(struct io_uring *ring, int nr, bool zc,
			  bool full, unsigned sqe_flags)
{
	struct cqes cs = { };
	struct conn c;
	pthread_t thread;
	void *tret;
	int i, ret;

	if (conn_open(&c, zc)) {
		fprintf(stderr, "socket pair failed\n");
		return T_EXIT_FAIL;
	}
	if (full) {
		c.drain = conn_fill(&c) + nr * BUF_SIZE;
		c.drain_ms = 50;
	}
	c.write_ms = 200;

	queue_recv(ring, &c);
	for (i = 0; i < nr; i++)
		queue_send(ring, &c, zc, sqe_flags);

	pthread_create(&thread, NULL, helper, &c);
	ret = io_uring_submit_and_wait(ring, 1);
	if (ret != nr + 1) {
		fprintf(stderr, "submit_and_wait: %d\n", ret);
		goto err;
	}
	reap(ring, &cs);
	if (!cs.nr_recv) {
		fprintf(stderr, "woken without recv, sends %d\n", cs.nr_send);
		goto err;
	}
	pthread_join(thread, &tret);

	if (!full && cs.nr_send != nr) {
		/* inline sends must all have been posted by now */
		fprintf(stderr, "got %d send CQEs, expected %d\n", cs.nr_send, nr);
		goto err_close;
	}
	reap_until(ring, &cs, nr, zc ? nr : 0, 1);
	if (cs.nr_send != nr || cs.send_res != BUF_SIZE) {
		fprintf(stderr, "sends %d res %d\n", cs.nr_send, cs.send_res);
		goto err_close;
	}
	if (zc && cs.nr_notif != nr) {
		fprintf(stderr, "notifs %d, expected %d\n", cs.nr_notif, nr);
		goto err_close;
	}
	conn_close(&c);
	return T_EXIT_PASS;
err:
	pthread_join(thread, &tret);
err_close:
	/* don't leave CQEs behind for the next test */
	reap(ring, &cs);
	conn_close(&c);
	return T_EXIT_FAIL;
}

/* a failed send must still wake the waiter */
static int test_fail(struct io_uring *ring)
{
	struct __kernel_timespec ts = { .tv_sec = 1, };
	struct io_uring_cqe *cqe;
	struct cqes cs = { };
	struct timeval tv;
	struct conn c;
	int ret;

	if (conn_open(&c, false)) {
		fprintf(stderr, "socket pair failed\n");
		return T_EXIT_FAIL;
	}
	shutdown(c.snd[0], SHUT_WR);

	queue_recv(ring, &c);
	queue_send(ring, &c, false, 0);

	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_timeout(ring, &cqe, 1, &ts, NULL);
	if (ret < 0) {
		fprintf(stderr, "failed send didn't wake: %d\n", ret);
		goto err;
	}
	if (mtime_since_now(&tv) >= 500) {
		fprintf(stderr, "failed send woke late\n");
		goto err;
	}
	if (cqe->user_data != UD_SEND || cqe->res != -EPIPE) {
		fprintf(stderr, "cqe ud %lu res %d\n",
			(unsigned long) cqe->user_data, cqe->res);
		goto err;
	}
	io_uring_cqe_seen(ring, cqe);

	/* complete the recv */
	if (write(c.rcv[0], "x", 1) != 1)
		goto err;
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret || cqe->user_data != UD_RECV) {
		fprintf(stderr, "recv wait %d\n", ret);
		goto err;
	}
	io_uring_cqe_seen(ring, cqe);
	conn_close(&c);
	return T_EXIT_PASS;
err:
	conn_close(&c);
	reap(ring, &cs);
	return T_EXIT_FAIL;
}

/*
 * More quiet CQEs than fit in the CQ ring must all get delivered, through
 * overflow if needed, and the wait must still end with the recv.
 */
static int test_fill(unsigned flags)
{
	struct __kernel_timespec ts = { .tv_sec = 5, };
	struct io_uring_params p = { };
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	struct cqes cs = { };
	pthread_t thread;
	struct timeval tv;
	struct conn c;
	void *tret;
	int i, ret;

	p.flags = flags | IORING_SETUP_CQSIZE;
	p.cq_entries = 8;
	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring setup %d\n", ret);
		return T_EXIT_FAIL;
	}
	if (conn_open(&c, false)) {
		fprintf(stderr, "socket pair failed\n");
		io_uring_queue_exit(&ring);
		return T_EXIT_FAIL;
	}

	/* io-wq sends that don't have to wait, completing as we sleep */
	c.drain = 12 * BUF_SIZE;
	c.write_ms = 200;

	queue_recv(&ring, &c);
	for (i = 0; i < 7; i++)
		queue_send(&ring, &c, false, IOSQE_ASYNC);
	ret = io_uring_submit(&ring);
	if (ret != 8) {
		fprintf(stderr, "submit %d\n", ret);
		goto err;
	}
	for (i = 0; i < 5; i++)
		queue_send(&ring, &c, false, IOSQE_ASYNC);

	pthread_create(&thread, NULL, helper, &c);
	gettimeofday(&tv, NULL);
	ret = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, &ts, NULL);
	if (ret < 0 || mtime_since_now(&tv) >= 4000) {
		fprintf(stderr, "wait with full CQ ring failed: %d\n", ret);
		goto err_join;
	}
	/* the remaining sends may need us to run task_work */
	reap_until(&ring, &cs, 12, 0, 1);
	pthread_join(thread, &tret);
	if (cs.nr_send != 12 || cs.nr_recv != 1) {
		fprintf(stderr, "sends %d recv %d\n", cs.nr_send, cs.nr_recv);
		goto err;
	}
	conn_close(&c);
	io_uring_queue_exit(&ring);
	return T_EXIT_PASS;
err_join:
	pthread_join(thread, &tret);
err:
	conn_close(&c);
	io_uring_queue_exit(&ring);
	return T_EXIT_FAIL;
}

static int test_ring(unsigned flags)
{
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(8, &ring, flags);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "ring setup %d\n", ret);
		return T_EXIT_FAIL;
	}

	ret = test_wait_recv(&ring, 1, false, false, 0);
	if (ret) {
		fprintf(stderr, "inline send failed\n");
		goto out;
	}
	ret = test_wait_recv(&ring, 4, false, false, 0);
	if (ret) {
		fprintf(stderr, "inline sends failed\n");
		goto out;
	}
	ret = test_wait_recv(&ring, 2, false, true, 0);
	if (ret) {
		fprintf(stderr, "polled sends failed\n");
		goto out;
	}
	ret = test_wait_recv(&ring, 2, false, false, IOSQE_ASYNC);
	if (ret) {
		fprintf(stderr, "io-wq sends failed\n");
		goto out;
	}
	ret = test_wait_recv(&ring, 2, false, true, IOSQE_ASYNC);
	if (ret) {
		fprintf(stderr, "polled io-wq sends failed\n");
		goto out;
	}
	if (!no_zc) {
		ret = test_wait_recv(&ring, 2, true, false, 0);
		if (ret) {
			fprintf(stderr, "zc sends failed\n");
			goto out;
		}
	}
	ret = test_fail(&ring);
	if (ret) {
		fprintf(stderr, "failed send failed\n");
		goto out;
	}
	io_uring_queue_exit(&ring);

	ret = test_fill(flags);
	if (ret)
		fprintf(stderr, "CQ ring fill failed\n");
	return ret;
out:
	io_uring_queue_exit(&ring);
	return ret;
}

/* check that the kernel supports IORING_SEND_QUIET, and for zerocopy */
static int probe(void)
{
	struct io_uring_cqe *cqe;
	struct cqes cs = { };
	struct io_uring ring;
	struct conn c;
	int ret;

	if (io_uring_queue_init(8, &ring, 0))
		return 1;
	if (conn_open(&c, true)) {
		io_uring_queue_exit(&ring);
		return 1;
	}
	queue_send(&ring, &c, false, 0);
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret)
		goto out;
	if (cqe->res == -EINVAL)
		no_quiet = 1;
	io_uring_cqe_seen(&ring, cqe);
	if (no_quiet)
		goto out;

	/* the main CQE completes inline, the notification is quiet */
	queue_send(&ring, &c, true, 0);
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret)
		goto out;
	if (cqe->res < 0)
		no_zc = 1;
	io_uring_cqe_seen(&ring, cqe);
	if (!no_zc)
		reap_until(&ring, &cs, 0, 1, 0);
out:
	conn_close(&c);
	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	static const unsigned ring_flags[] = {
		0,
		IORING_SETUP_COOP_TASKRUN,
		IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
	};
	int i, ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	memset(sbuf, 0x5a, sizeof(sbuf));
	if (probe()) {
		fprintf(stderr, "probe failed\n");
		return T_EXIT_FAIL;
	}
	if (no_quiet)
		return T_EXIT_SKIP;

	for (i = 0; i < ARRAY_SIZE(ring_flags); i++) {
		ret = test_ring(ring_flags[i]);
		if (ret == T_EXIT_SKIP)
			continue;
		if (ret) {
			fprintf(stderr, "ring flags %x failed\n", ring_flags[i]);
			return T_EXIT_FAIL;
		}
	}
	return T_EXIT_PASS;
}
