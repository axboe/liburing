// SPDX-License-Identifier: MIT

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "liburing.h"
#include "helpers.h"

static int no_recv_mshot;

enum early_error_t {
	ERROR_NONE  = 0,
	ERROR_NOT_ENOUGH_BUFFERS,
	ERROR_EARLY_CLOSE_SENDER,
	ERROR_EARLY_CLOSE_RECEIVER,
	ERROR_EARLY_OVERFLOW,
	ERROR_EARLY_LAST
};

struct args {
	bool stream;
	bool wait_each;
	enum early_error_t early_error;
};

static int test(struct args *args)
{
	int const N = 8;
	int const N_BUFFS = N * 64;
	int const N_CQE_OVERFLOW = 4;
	int const min_cqes = 2;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int fds[2], ret, i, j, total_sent_bytes = 0, total_recv_bytes = 0;
	int send_buff[256];
	int *recv_buffs[N_BUFFS];
	int *at;
	struct io_uring_cqe recv_cqe[N_BUFFS];
	int recv_cqes = 0;
	bool early_error = false;
	bool early_error_started = false;
	struct __kernel_timespec timeout = {
		.tv_sec = 1,
	};


	memset(recv_buffs, 0, sizeof(recv_buffs));

	if (args->early_error == ERROR_EARLY_OVERFLOW) {
		struct io_uring_params params = {
			.flags = IORING_SETUP_CQSIZE,
			.cq_entries = N_CQE_OVERFLOW
		};

		ret = io_uring_queue_init_params(N_CQE_OVERFLOW, &ring, &params);
	} else {
		ret = io_uring_queue_init(32, &ring, 0);
	}
	if (ret) {
		fprintf(stderr, "queue init failed: %d\n", ret);
		return ret;
	}

	ret = t_create_socket_pair(fds, args->stream);
	if (ret) {
		fprintf(stderr, "t_create_socket_pair failed: %d\n", ret);
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(send_buff); i++)
		send_buff[i] = i;

	for (i = 0; i < ARRAY_SIZE(recv_buffs); i++) {
		/* prepare some different sized buffers */
		int buffer_size = (i % 2 == 0 && args->stream) ? 1 : N * sizeof(int);

		recv_buffs[i] = malloc(sizeof(*at) * buffer_size);

		if (i > 2 && args->early_error == ERROR_NOT_ENOUGH_BUFFERS)
			continue;

		sqe = io_uring_get_sqe(&ring);
		io_uring_prep_provide_buffers(sqe, recv_buffs[i],
					buffer_size * sizeof(*recv_buffs[i]), 1, 7, i);
		if (io_uring_submit_and_wait_timeout(&ring, &cqe, 1, &timeout, NULL) != 0) {
			fprintf(stderr, "provide buffers failed: %d\n", ret);
			ret = -1;
			goto cleanup;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_recv_multishot(sqe, fds[0], NULL, 0, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = 7;
	io_uring_sqe_set_data64(sqe, 1234);
	io_uring_submit(&ring);

	at = &send_buff[0];
	total_sent_bytes = 0;
	for (i = 0; i < N; i++) {
		int to_send = sizeof(*at) * (i+1);

		total_sent_bytes += to_send;
		if (send(fds[1], at, to_send, 0) != to_send) {
			if (early_error_started)
				break;
			fprintf(stderr, "send failed %d\n", errno);
			ret = -1;
			goto cleanup;
		}

		if (i == 2) {
			if (args->early_error == ERROR_EARLY_CLOSE_RECEIVER) {
				/* allow previous sends to complete */
				usleep(1000);

				sqe = io_uring_get_sqe(&ring);
				io_uring_prep_recv(sqe, fds[0], NULL, 0, 0);
				io_uring_prep_cancel64(sqe, 1234, 0);
				sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
				io_uring_submit(&ring);
				early_error_started = true;
			}
			if (args->early_error == ERROR_EARLY_CLOSE_SENDER) {
				early_error_started = true;
				shutdown(fds[1], SHUT_RDWR);
				close(fds[1]);
			}
		}
		at += (i+1);

		if (args->wait_each) {
			ret = io_uring_wait_cqes(&ring, &cqe, 1, &timeout, NULL);
			if (ret) {
				fprintf(stderr, "wait_each failed: %d\n", ret);
				ret = -1;
				goto cleanup;
			}
			while (io_uring_peek_cqe(&ring, &cqe) == 0) {
				recv_cqe[recv_cqes++] = *cqe;
				if (cqe->flags & IORING_CQE_F_MORE) {
					io_uring_cqe_seen(&ring, cqe);
				} else {
					early_error = true;
					io_uring_cqe_seen(&ring, cqe);
				}
			}
			if (early_error)
				break;
		}
	}

	close(fds[1]);

	/* allow sends to finish */
	usleep(1000);

	if ((args->stream && !early_error) || recv_cqes < min_cqes) {
		ret = io_uring_wait_cqes(&ring, &cqe, 1, &timeout, NULL);
		if (ret && ret != -ETIME) {
			fprintf(stderr, "wait final failed: %d\n", ret);
			ret = -1;
			goto cleanup;
		}
	}

	while (io_uring_peek_cqe(&ring, &cqe) == 0) {
		recv_cqe[recv_cqes++] = *cqe;
		io_uring_cqe_seen(&ring, cqe);
	}

	ret = -1;
	at = &send_buff[0];
	if (recv_cqes < min_cqes) {
		if (recv_cqes > 0 && recv_cqe[0].res == -EINVAL) {
			no_recv_mshot = 1;
			return 0;
		}
		/* some kernels apparently don't check ->ioprio, skip */
		ret = 0;
		no_recv_mshot = 1;
		goto cleanup;
	}
	for (i = 0; i < recv_cqes; i++) {
		cqe = &recv_cqe[i];

		bool const is_last = i == recv_cqes - 1;

		bool const should_be_last =
			(cqe->res <= 0) ||
			(args->stream && is_last) ||
			(args->early_error == ERROR_EARLY_OVERFLOW &&
			 !args->wait_each && i == N_CQE_OVERFLOW);
		int *this_recv;


		if (should_be_last) {
			if (!is_last) {
				fprintf(stderr, "not last cqe had error %d\n", i);
				goto cleanup;
			}

			switch (args->early_error) {
			case ERROR_NOT_ENOUGH_BUFFERS:
				if (cqe->res != -ENOBUFS) {
					fprintf(stderr,
						"ERROR_NOT_ENOUGH_BUFFERS: res %d\n", cqe->res);
					goto cleanup;
				}
				break;
			case ERROR_EARLY_OVERFLOW:
				if (cqe->res < 0) {
					fprintf(stderr,
						"ERROR_EARLY_OVERFLOW: res %d\n", cqe->res);
					goto cleanup;
				}
				break;
			case ERROR_EARLY_CLOSE_RECEIVER:
				if (cqe->res != -ECANCELED) {
					fprintf(stderr,
						"ERROR_EARLY_CLOSE_RECEIVER: res %d\n", cqe->res);
					goto cleanup;
				}
				break;
			case ERROR_NONE:
			case ERROR_EARLY_CLOSE_SENDER:
				if (cqe->res != 0) {
					fprintf(stderr, "early error: res %d\n", cqe->res);
					goto cleanup;
				}
				break;
			case ERROR_EARLY_LAST:
				fprintf(stderr, "bad error_early\n");
				goto cleanup;
			};

			if (cqe->res <= 0 && cqe->flags & IORING_CQE_F_BUFFER) {
				fprintf(stderr, "final BUFFER flag set\n");
				goto cleanup;
			}

			if (cqe->flags & IORING_CQE_F_MORE) {
				fprintf(stderr, "final MORE flag set\n");
				goto cleanup;
			}

			if (cqe->res <= 0)
				continue;
		} else {
			if (!(cqe->flags & IORING_CQE_F_MORE)) {
				fprintf(stderr, "MORE flag not set\n");
				goto cleanup;
			}
		}

		if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
			fprintf(stderr, "BUFFER flag not set\n");
			goto cleanup;
		}

		total_recv_bytes += cqe->res;
		if (cqe->res % 4 != 0) {
			/*
			 * doesn't seem to happen in practice, would need some
			 * work to remove this requirement
			 */
			fprintf(stderr, "unexpectedly aligned buffer cqe->res=%d\n", cqe->res);
			goto cleanup;
		}

		/* check buffer arrived in order (for tcp) */
		this_recv = recv_buffs[cqe->flags >> 16];
		for (j = 0; args->stream && j < cqe->res / 4; j++) {
			int sent = *at++;
			int recv = *this_recv++;

			if (sent != recv) {
				fprintf(stderr, "recv=%d sent=%d\n", recv, sent);
				goto cleanup;
			}
		}
	}

	if (args->early_error == ERROR_NONE && total_recv_bytes < total_sent_bytes) {
		fprintf(stderr,
			"missing recv: recv=%d sent=%d\n", total_recv_bytes, total_sent_bytes);
		goto cleanup;
	}

	/* check the final one */
	cqe = &recv_cqe[recv_cqes-1];

	ret = 0;
cleanup:
	for (i = 0; i < ARRAY_SIZE(recv_buffs); i++)
		free(recv_buffs[i]);
	close(fds[0]);
	close(fds[1]);
	io_uring_queue_exit(&ring);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	int loop;
	int early_error = 0;

	if (argc > 1)
		return T_EXIT_SKIP;

	for (loop = 0; loop < 4; loop++) {
		struct args a = {
			.stream = loop & 0x01,
			.wait_each = loop & 0x2,
		};
		for (early_error = 0; early_error < ERROR_EARLY_LAST; early_error++) {
			a.early_error = (enum early_error_t)early_error;
			ret = test(&a);
			if (ret) {
				fprintf(stderr,
					"test stream=%d wait_each=%d early_error=%d failed\n",
					a.stream, a.wait_each, a.early_error);
				return T_EXIT_FAIL;
			}
			if (no_recv_mshot)
				return T_EXIT_SKIP;
		}
	}

	return T_EXIT_PASS;
}
