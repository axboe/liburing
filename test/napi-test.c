#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>

#include <poll.h>
#include <sched.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <linux/mman.h>

#include "liburing.h"

#include <assert.h>

static const char receiver_address[] = "10.10.10.20";
static const int port = 9999;
#define BUF_SIZE 4096

static char buffer[BUF_SIZE];
static unsigned current_byte = 0;

static void do_setsockopt(int fd, int level, int optname, int val)
{
	int ret = setsockopt(fd, level, optname, &val, sizeof(val));

	assert(ret == 0);
}

static void sender(void)
{
	unsigned long long written = 0;
	struct sockaddr_in addr;
	int i, ret, fd;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	ret = inet_pton(AF_INET, receiver_address, &addr.sin_addr);
	assert(ret == 1);

	fd = socket(PF_INET, SOCK_STREAM, 0);
	assert(fd >= 0);

	printf("sender: connect\n");

	if (connect(fd, (void *)&addr, sizeof(addr))) {
		fprintf(stderr, "connect fail %i\n", errno);
		exit(1);
	}

	printf("sender: connected\n");

	while (written < 8 * 1024 * 1024) {
		for (i = 0; i < BUF_SIZE; i++)
			buffer[i] = current_byte + i;

		ret = write(fd, buffer, BUF_SIZE);
		if (ret <= 0) {
			if (!ret || errno == ECONNRESET)
				break;
			fprintf(stderr, "write failed %i %i\n", ret, errno);
			exit(1);
		}
		written += ret;
		current_byte += ret;
	}

	close(fd);
	printf("bytes sent %llu\n", written);
}

static void receiver(void)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring ring;
	unsigned long long received = 0;
	struct sockaddr_in addr;
	int fd, listen_fd;
	int i, ret;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(listen_fd >= 0);

	do_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, 1);
	ret = bind(listen_fd, (void *)&addr, sizeof(addr));
	if (ret) {
		fprintf(stderr, "bind failed %i %i\n", ret, errno);
		exit(1);
	}

	printf("receiver: listen()\n");

	ret = listen(listen_fd, 8);
	assert(ret == 0);

	printf("receiver: accept()\n");

	fd = accept(listen_fd, NULL, NULL);
	assert(fd >= 0);

	while (1) {
		sqe = io_uring_get_sqe(&ring);
		io_uring_prep_recv(sqe, fd, buffer, BUF_SIZE, 0);

		ret = io_uring_submit(&ring);
		if (ret != 1) {
			fprintf(stderr, "io_uring_submit: %i\n", ret);
			return;
		}

		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "io_uring_wait_cqe: %i\n", ret);
			return;
		}

		ret = cqe->res;
		if (ret <= 0) {
			if (!ret)
				break;
			fprintf(stderr, "recv failed %i %i\n", ret, errno);
			exit(1);
		}

		for (i = 0; i < ret; i++) {
			char expected = current_byte + i;

			if (buffer[i] != expected) {
				fprintf(stderr, "data mismatch: idx %i, %c vs %c\n",
					i, buffer[i], expected);
				exit(1);
			}
		}

		current_byte += ret;
		received += ret;
		io_uring_cqe_seen(&ring, cqe);
	}

	close(fd);
	io_uring_queue_exit(&ring);
	printf("bytes received %llu\n", received);
}

int main(int argc, char **argv)
{
	int is_rx;

	assert(argc == 2);
	is_rx = strtoul(argv[1], NULL, 0);

	printf("%s: start\n", is_rx ? "receiver" : "sender");

	if (is_rx)
		receiver();
	else
		sender();

	return 0;
}
