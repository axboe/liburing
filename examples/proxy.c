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
 * 	./proxy -m1 -d1 -f1 -H 192.168.2.6 -r4444 -p4445
 *
 * Act as a bi-directional proxy, listening on port 8884, and send data back
 * and forth between host and 192.168.2.6 on port 22. Use multishot receive,
 * DEFER_TASKRUN, fixed files, and buffers of size 1500.
 *
 * 	./proxy -m1 -d1 -f1 -B1 -b1500 -H 192.168.2.6 -r22 -p8888
 *
 * Act a sink, listening on port 4445, using multishot receive, DEFER_TASKRUN,
 * and fixed files:
 *
 * 	./proxy -m1 -d1 -s1 -f1 -p4445
 *
 * Run with -h to see a list of options, and their defaults.
 *
 * (C) Jens Axboe <axboe@kernel.dk> 2024
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
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <liburing.h>

/*
 * Upper 8 bits is the command type, next 16 bits is the bid, next 16 bits is
 * the bgid, bottom 8 bits is the connection id
 */
#define OP_SHIFT	(56ULL)
#define OP_MASK		((1ULL << OP_SHIFT) - 1)
#define BID_SHIFT	(40ULL)
#define BID_MASK	((1ULL << 16) - 1)
#define BGID_SHIFT	(24ULL)
#define BGID_MASK	((1ULL << 16) - 1)

#define __ACCEPT	1ULL
#define	__SOCK		2ULL
#define	__CONNECT	3ULL
#define	__RECV		4ULL
#define __RECV_IN	5ULL
#define __RECV_OUT	6ULL
#define	__SEND		7ULL

/*
 * Goes from accept new connection -> create socket, connect to end
 * point, prepare recv, on receive do send.
 */
#define ACCEPT_DATA	(__ACCEPT << OP_SHIFT)
#define	SOCK_DATA	(__SOCK << OP_SHIFT)
#define	CONNECT_DATA	(__CONNECT << OP_SHIFT)
#define	RECV_DATA	(__RECV << OP_SHIFT)
#define	RECV_IN_DATA	(__RECV_IN << OP_SHIFT)
#define	RECV_OUT_DATA	(__RECV_OUT << OP_SHIFT)
#define	SEND_DATA	(__SEND << OP_SHIFT)

static int start_bgid = 1;

#define MAX_CONNS	1024

static int nr_conns;
static int mshot = 1;
static int sqpoll;
static int defer_tw = 1;
static int is_sink;
static int stats_shown;
static int fixed_files;
static char *host = "192.168.2.6";
static int send_port = 4445;
static int receive_port = 4444;
static int buf_size = 32;
static int bidi;

static int nr_bufs = 256;
static int br_mask;

#define NR_BUF_RINGS	2

struct conn_buf_ring {
	struct io_uring_buf_ring *br;
	void *buf;
	int bgid;
};

struct conn {
	struct conn_buf_ring brs[NR_BUF_RINGS];

	int tid;
	int start_bgid;
	int cur_br_index;
	struct conn_buf_ring *cur_br;

	int in_fd, out_fd;

	struct sockaddr_in addr;

	int rcv, snd, shrt, bgid_switch, mshot_resubmit;

	unsigned long rps;
	unsigned long bytes;
};

static struct conn conns[MAX_CONNS];

static int setup_listening_socket(int port)
{
	struct sockaddr_in srv_addr;
	int fd, enable;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket()");
		return -1;
	}

	enable = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR)");
		return -1;
	}

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
		perror("bind()");
		return -1;
	}

	if (listen(fd, 1024) < 0) {
		perror("listen()");
		return -1;
	}

	return fd;
}

static int setup_buffer_ring(struct io_uring *ring, struct conn *c, int index)
{
	struct conn_buf_ring *cbr = &c->brs[index];
	int ret, i;
	void *ptr;

	cbr->bgid = c->start_bgid + index;

	if (posix_memalign(&cbr->buf, 4096, buf_size * nr_bufs)) {
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
		io_uring_buf_ring_add(cbr->br, ptr, buf_size, i, br_mask, i);
		ptr += buf_size;
	}
	io_uring_buf_ring_advance(cbr->br, nr_bufs);
	printf("%d: buffer ring bgid %d, bufs %d\n", c->tid, cbr->bgid, nr_bufs);
	return 0;
}

/*
 * Sets up two buffer rings per connection, and we alternate between them if we
 * hit -ENOBUFS on a receive. See handle_enobufs().
 */
static int setup_buffer_rings(struct io_uring *ring, struct conn *c)
{
	int i;

	c->start_bgid = start_bgid;

	for (i = 0; i < NR_BUF_RINGS; i++) {
		if (setup_buffer_ring(ring, c, i))
			return 1;
	}

	c->cur_br = &c->brs[0];
	c->cur_br_index = 0;
	start_bgid += 2;
	return 0;
}

static void show_stats(void)
{
	int i;

	if (stats_shown)
		return;

	stats_shown = 1;

	for (i = 0; i < MAX_CONNS; i++) {
		struct conn *c = &conns[i];

		if (!c->rps)
			continue;

		printf("Conn %d/(in_fd=%d, out_fd=%d): rps=%lu (rcv=%u, snd=%u, switch=%u, mshot_resubmit=%d, short=%d), kb=%lu\n", c->tid, c->in_fd, c->out_fd, c->rps, c->rcv, c->snd, c->bgid_switch, c->mshot_resubmit, c->shrt, c->bytes >> 10);
	}
}

static void sig_int(int __attribute__((__unused__)) sig)
{
	show_stats();
	exit(1);
}

/*
 * Special cased for SQPOLL only, as we don't control when SQEs are consumed if
 * that is used. Hence we may need to wait for the SQPOLL thread to keep up until
 * we can get a new SQE. All other cases will break immediately, with a fresh
 * SQE.
 */
static struct io_uring_sqe *get_sqe(struct io_uring *ring)
{
	struct io_uring_sqe *sqe;

	do {
		sqe = io_uring_get_sqe(ring);
		if (sqe)
			break;
		if (!sqpoll) {
			fprintf(stderr, "bug in sq handling\n");
			exit(1);
		}
		io_uring_sqring_wait(ring);
	} while (1);

	return sqe;
}

static void __submit_receive(struct io_uring *ring, struct conn *c, int fd,
			     uint64_t type)
{
	struct conn_buf_ring *cbr = c->cur_br;
	struct io_uring_sqe *sqe;
	uint64_t user_data;

	sqe = get_sqe(ring);
	if (mshot)
		io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
	else
		io_uring_prep_recv(sqe, fd, NULL, 0, 0);

	user_data = type | c->tid;
	user_data |= ((uint64_t) cbr->bgid << BGID_SHIFT);
	io_uring_sqe_set_data64(sqe, user_data);
	sqe->buf_group = cbr->bgid;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	if (fixed_files)
		sqe->flags |= IOSQE_FIXED_FILE;
}

static void submit_receive(struct io_uring *ring, struct conn *c)
{
	__submit_receive(ring, c, c->in_fd, RECV_DATA);
}

static void submit_bidi_receive(struct io_uring *ring, struct conn *c)
{
	__submit_receive(ring, c, c->in_fd, RECV_IN_DATA);
	__submit_receive(ring, c, c->out_fd, RECV_OUT_DATA);
}

/*
 * We hit -ENOBUFS, which means that we ran out of buffers in our current
 * provided buffer group. This can happen if there's an imbalance between the
 * receives coming in and the sends being processed. Switch to the other buffer
 * group and continue from there, previous sends should come in and replenish the
 * previous one by the time we potentially hit -ENOBUFS again.
 */
static void handle_enobufs(struct io_uring *ring, struct conn *c)
{
	c->bgid_switch++;
	c->cur_br_index ^= 1;
	c->cur_br = &c->brs[c->cur_br_index];

	submit_receive(ring, c);
}

static int handle_receive(struct io_uring *ring, struct conn *c,
			  struct io_uring_cqe *cqe, int *need_submit,
			  int in_fd, int out_fd, uint64_t type)
{
	uint64_t user_data = io_uring_cqe_get_data64(cqe);
	struct conn_buf_ring *cbr;
	struct io_uring_sqe *sqe;
	int bid, bgid, do_recv = !mshot;
	int res = cqe->res;
	void *ptr;

	if (res < 0) {
		if (res == -ENOBUFS) {
			handle_enobufs(ring, c);
			*need_submit = 1;
			return 0;
		} else {
			fprintf(stderr, "recv error %s\n", strerror(-res));
			return 1;
		}
	}

	c->rcv++;

	if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
		fprintf(stderr, "no buffer assigned\n");
		return 1;
	}

	/*
	 * If multishot terminates, just submit a new one.
	 */
	if (mshot && !(cqe->flags & IORING_CQE_F_MORE)) {
		c->mshot_resubmit++;
		do_recv = 1;
	}

	bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
	bgid = (user_data >> BGID_SHIFT) & BGID_MASK;
	assert(bid < nr_bufs);
	cbr = &c->brs[bgid - c->start_bgid];
	ptr = cbr->buf + bid * buf_size;

	/*
	 * If we're a sink, we're done here. Just replenish the buffer back
	 * to the pool. For proxy mode, we will send the data to the other
	 * end and the buffer will be replenished once the send is done with
	 * it.
	 */
	if (is_sink) {
		io_uring_buf_ring_add(cbr->br, ptr, buf_size, bid, br_mask, 0);
		io_uring_buf_ring_advance(cbr->br, 1);
		*need_submit = 0;
	} else {
		sqe = get_sqe(ring);
		io_uring_prep_send(sqe, out_fd, ptr, res, 0);
		user_data = SEND_DATA | ((uint64_t) bid << BID_SHIFT) | c->tid;
		user_data |= ((uint64_t) bgid) << BGID_SHIFT;
		io_uring_sqe_set_data64(sqe, user_data);
		if (fixed_files)
			sqe->flags |= IOSQE_FIXED_FILE;
	}

	c->rps++;
	c->bytes += res;

	/*
	 * If we're not doing multishot receive, or if multishot receive
	 * terminated, we need to submit a new receive request as this one
	 * has completed. Multishot will stay armed.
	 */
	if (do_recv) {
		__submit_receive(ring, c, in_fd, type);
		*need_submit = 1;
	}

	return 0;
}

static int handle_cqe(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	uint64_t user_data = io_uring_cqe_get_data64(cqe);
	int conn_id = cqe->user_data & 0xff;
	struct conn *c = &conns[conn_id];
	struct io_uring_sqe *sqe;
	int res = cqe->res;
	int ret, need_submit = 1;

	switch (user_data >> OP_SHIFT) {
	case __ACCEPT: {
		if (res < 0) {
			fprintf(stderr, "accept error %s\n", strerror(-res));
			return 1;
		}

		if (nr_conns == MAX_CONNS) {
			fprintf(stderr, "max clients reached %d\n", nr_conns);
			return 1;
		}

		c = &conns[nr_conns];
		c->tid = nr_conns;
		c->in_fd = res;

		printf("New client: %d/%d\n", nr_conns, c->in_fd);

		nr_conns++;
		setup_buffer_rings(ring, c);

		if (is_sink) {
			submit_receive(ring, c);
			break;
		}

		sqe = get_sqe(ring);
		if (fixed_files)
			io_uring_prep_socket_direct_alloc(sqe, AF_INET, SOCK_STREAM, 0, 0);
		else
			io_uring_prep_socket(sqe, AF_INET, SOCK_STREAM, 0, 0);
		io_uring_sqe_set_data64(sqe, SOCK_DATA | c->tid);
		break;
		}
	case __SOCK: {
		if (res < 0) {
			fprintf(stderr, "socket error %s\n", strerror(-res));
			return 1;
		}

		c->out_fd = res;
		memset(&c->addr, 0, sizeof(c->addr));
		c->addr.sin_family = AF_INET;
		c->addr.sin_port = htons(send_port);
		ret = inet_pton(AF_INET, host, (struct sockaddr *) &c->addr.sin_addr);
		if (ret <= 0) {
			if (!ret)
				fprintf(stderr, "host not in right format\n");
			else
				perror("inet_pton");
			return 1;
		}
		sqe = get_sqe(ring);
		io_uring_prep_connect(sqe, c->out_fd, (struct sockaddr *) &c->addr, sizeof(c->addr));
		io_uring_sqe_set_data64(sqe, CONNECT_DATA | c->tid);
		if (fixed_files)
			sqe->flags |= IOSQE_FIXED_FILE;
		break;
		}
	case __CONNECT: {
		if (res < 0) {
			fprintf(stderr, "connect error %s\n", strerror(-res));
			return 1;
		}

		if (bidi)
			submit_bidi_receive(ring, c);
		else
			submit_receive(ring, c);
		break;
		}
	case __RECV: {
		handle_receive(ring, c, cqe, &need_submit, c->in_fd, c->out_fd, RECV_DATA);
		break;
		}
	case __RECV_IN: {
		handle_receive(ring, c, cqe, &need_submit, c->in_fd, c->out_fd, RECV_IN_DATA);
		break;
		}
	case __RECV_OUT: {
		handle_receive(ring, c, cqe, &need_submit, c->out_fd, c->in_fd, RECV_OUT_DATA);
		break;
		}
	case __SEND: {
		struct conn_buf_ring *cbr;
		int bid, bgid;
		void *ptr;

		c->snd++;

		if (res < 0) {
			fprintf(stderr, "send error %s\n", strerror(-res));
			return 1;
		}

		if (cqe->res != buf_size)
			c->shrt++;

		bid = (user_data >> BID_SHIFT) & BID_MASK;
		bgid = (user_data >> BGID_SHIFT) & BGID_MASK;
		bgid -= c->start_bgid;
		cbr = &c->brs[bgid];
		ptr = cbr->buf + bid * buf_size;
		io_uring_buf_ring_add(cbr->br, ptr, buf_size, bid, br_mask, 0);
		io_uring_buf_ring_advance(cbr->br, 1);
		need_submit = 0;
		break;
		}
	default:
		fprintf(stderr, "bad user data %lx\n", (long) user_data);
		break;
	}

	if (need_submit)
		io_uring_submit(ring);

	return 0;
}

static void usage(const char *name)
{
	printf("%s:\n", name);
	printf("\t-m:\t\tUse multishot receive (%d)\n", mshot);
	printf("\t-d:\t\tUse DEFER_TASKRUN (%d)\n", defer_tw);
	printf("\t-S:\t\tUse SQPOLL (%d)\n", sqpoll);
	printf("\t-b:\t\tSend/receive buf size (%d)\n", buf_size);
	printf("\t-n:\t\tNumber of provided buffers (%d)\n", nr_bufs);
	printf("\t-s:\t\tAct only as a sink (%d)\n", is_sink);
	printf("\t-f:\t\tUse only fixed files (%d)\n", fixed_files);
	printf("\t-B:\t\tUse bi-directiona mode (%d)\n", bidi);
	printf("\t-h:\t\tHost to connect to (%s)\n", host);
	printf("\t-r:\t\tPort to receive on (%d)\n", receive_port);
	printf("\t-p:\t\tPort to connect to (%d)\n", send_port);
}

int main(int argc, char *argv[])
{
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	struct io_uring_params params;
	struct sigaction sa = { };
	int opt, ret, fd;

	while ((opt = getopt(argc, argv, "m:d:S:s:b:f:H:r:p:n:B:h?")) != -1) {
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
		case 'h':
		default:
			usage(argv[0]);
			return 1;
		}
	}

	br_mask = nr_bufs - 1;

	if (is_sink) {
		fd = setup_listening_socket(send_port);
		receive_port = -1;
	} else {
		fd = setup_listening_socket(receive_port);
	}

	if (fd == -1)
		return 1;

	atexit(show_stats);
	sa.sa_handler = sig_int;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sa, NULL);

	memset(&params, 0, sizeof(params));
	params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_CLAMP;
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = 131072;
	if (defer_tw) {
		params.flags |= IORING_SETUP_DEFER_TASKRUN;
		sqpoll = 0;
	}
	if (sqpoll) {
		params.flags |= IORING_SETUP_SQPOLL;
		params.sq_thread_idle = 1000;
		defer_tw = 0;
	}
	if (!sqpoll && !defer_tw)
		params.flags |= IORING_SETUP_COOP_TASKRUN;

	ret = io_uring_queue_init_params(MAX_CONNS * 2, &ring, &params);
	if (ret) {
		fprintf(stderr, "%s\n", strerror(-ret));
		return 1;
	}

	if (fixed_files) {
		ret = io_uring_register_files_sparse(&ring, 4096);
		if (ret) {
			fprintf(stderr, "file register: %d\n", ret);
			return 1;
		}

		ret = io_uring_register_ring_fd(&ring);
		if (ret != 1) {
			fprintf(stderr, "ring register: %d\n", ret);
			return 1;
		}
	}

	printf("Backend: multishot=%d, sqpoll=%d, defer_tw=%d, fixed_files=%d "
		"is_sink=%d, buf_size=%d, nr_bufs=%d, host=%s, send_port=%d "
		"receive_port=%d\n",
			mshot, sqpoll, defer_tw, fixed_files, is_sink,
			buf_size, nr_bufs, host, send_port, receive_port);

	sqe = get_sqe(&ring);
	if (fixed_files)
		io_uring_prep_multishot_accept_direct(sqe, fd, NULL, NULL, 0);
	else
		io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);
	io_uring_sqe_set_data64(sqe, ACCEPT_DATA);
	io_uring_submit(&ring);

	while (1) {
		struct io_uring_cqe *cqe;
		unsigned int head;
		unsigned int i = 0;
		int to_wait;

		to_wait = 1;
		if (nr_conns)
			to_wait = nr_conns;

		to_wait = 1;
		io_uring_wait_cqes(&ring, &cqe, to_wait, NULL, NULL);

		io_uring_for_each_cqe(&ring, head, cqe) {
			if (handle_cqe(&ring, cqe))
				return 1;
			++i;
		}

		if (i)
			io_uring_cq_advance(&ring, i);
	}

	return 0;
}
