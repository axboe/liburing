/* SPDX-License-Identifier: MIT */
//
//  Test for receving HUP/ERR events for socket fd when
//  other side closes.

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>

#include "liburing.h"

#define WRITE_EVENTS 10

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static int server_thread_ready = 0;
static int server_thread_done = 0;
static int port = 0; // protected by the mutex, will be set before server signals ready

static void signal_var(int *var)
{
        pthread_mutex_lock(&mutex);
        *var = 1;
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&mutex);
}

static void wait_for_var(int *var)
{
        pthread_mutex_lock(&mutex);

        while (!*var)
                pthread_cond_wait(&cond, &mutex);

        pthread_mutex_unlock(&mutex);
}

static void prepare_sqe(struct io_uring *ring, int fd, uint64_t poll_mask)
{
    struct io_uring_sqe *sqe;
    uint64_t bitpattern;
    
    sqe = io_uring_get_sqe(ring);
    assert(sqe != NULL);

    bitpattern = (poll_mask << 32) + fd;
    io_uring_prep_poll_add(sqe, fd, poll_mask);
    io_uring_sqe_set_data(sqe, (void *) bitpattern);
    sqe->len |= IORING_POLL_ADD_MULTI;

    return;
}

void *server_thread(void *arg)
{
    struct io_uring ring;
    int i, ret, client_fd, s0;
    uint64_t user_data;
    int fd, done = 0;
    uint64_t poll_mask;
    struct sockaddr_in addr;
    unsigned int rand_seed = getpid();
    char readbuffer[1024];
    int bytes_read = 0;
    
    // set up uring
    ret = io_uring_queue_init(8, &ring, 0);
    assert(ret == 0);

    // set up listening
    s0 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(s0 != -1);

    int32_t val = 1;
    ret = setsockopt(s0, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    assert(ret != -1);
    ret = setsockopt(s0, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    assert(ret != -1);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0x0100007fU;

    i = 0;
    do {
        port = 1025 + (rand_r(&rand_seed) % 64510);
        addr.sin_port = port;

        if (bind(s0, (struct sockaddr*)&addr, sizeof(addr)) != -1)
            break;
    } while (++i < 100);

    if (i >= 100) {
        fprintf(stderr, "Can't find good port, bailing out\n");
        exit(1);
    }
    
    ret = listen(s0, 128);
    assert(ret != -1);

    signal_var(&server_thread_ready);

    client_fd = accept(s0, NULL, NULL);
    assert(client_fd != -1);

    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    prepare_sqe(&ring, client_fd, POLLIN | POLLHUP | POLLERR ); // POLLRDHUP

    ret = io_uring_submit(&ring);
    assert(ret == 1);

    while (!done) {
        struct io_uring_cqe *cqe;

        if (bytes_read >= WRITE_EVENTS)
        {
            fprintf(stderr, "We have received %d bytes and should be done now, but we have received no POLLHUP, test fail.\n",bytes_read);
            exit(1);
        }
        
        if (io_uring_wait_cqe(&ring, &cqe)) {
            fprintf(stderr, "server wait cqe failed\n");
            exit(1);
        }
        
        user_data = (uint64_t) io_uring_cqe_get_data(cqe);
        fd = user_data & 0x00000000FFFFFFFF; // mask out the fd
        poll_mask = user_data >> 32;         // and shift out the fd to get the poll_mask

        if (POLLIN & cqe->res) {
            while ((ret = read(fd, readbuffer, 1)) > 0)
            {
                readbuffer[1]=0;
                assert (ret == 1);
                bytes_read++;
            }
            
            if (ret == 0)
            {
                fprintf(stderr, "Read zero bytes, should have received HUP now too cqe->res [%d].\n", cqe->res);
            }
            
            if (ret < 0 && errno != EAGAIN)
            {
                fprintf(stderr, "Read failed with return code %d, errno %d\n", ret, errno);
                exit(1);
            }
        }

        if (POLLHUP & cqe->res) {
            fprintf(stderr, "Server POLLHUP on [%d] [%d] [%ld]\n", fd, cqe->res, poll_mask);
            done = 1;
        }
        
        if (POLLERR & cqe->res) {
            fprintf(stderr, "Server POLLERR fd [%d] [%d] [%ld]\n", fd, cqe->res, poll_mask);
            done = 1;
        }

        if (POLLRDHUP & cqe->res) {
            fprintf(stderr, "Server POLLRDHUP fd [%d] [%d] [%ld]\n", fd, cqe->res, poll_mask);
            done = 1;
        }

        io_uring_cqe_seen(&ring, cqe);
    }

    signal_var(&server_thread_done);
    close(s0);
    close(client_fd);
    io_uring_queue_exit(&ring);
    return NULL;
}

static void *client_thread(void *arg)
{
    int ret, i;

    wait_for_var(&server_thread_ready);

    // connect to server thread
    int s0 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(s0 != -1);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = port;
    addr.sin_addr.s_addr = 0x0100007fU;

    if (connect(s0, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        fprintf(stderr, "Failed to connect to 127.0.0.1:%d, aborting test.\n", port);
        exit(1);
    }

    int flags = fcntl(s0, F_GETFL, 0);
    fcntl(s0, F_SETFL, flags | O_NONBLOCK);

    for (i=0; i<WRITE_EVENTS; i++)
    {
      usleep(100000);
      ret = write(s0, "x", 1);
      assert (ret == 1);
    }
    
    close(s0); // should give server a HUP
    wait_for_var(&server_thread_done);

    return 0;
}

static int start_threads()
{
    pthread_t t1, t2;
    void *tret;
    int ret = 0;

    server_thread_ready = 0;
    server_thread_done = 0;
 
    pthread_create(&t1, NULL, server_thread, NULL);
    pthread_create(&t2, NULL, client_thread, NULL);

    pthread_join(t1, &tret);
    if (tret)
        ret++;

    pthread_join(t2, &tret);
    if (tret)
        ret++;

    return ret;
}

int main(int argc, char *argv[])
{
    if (argc > 1)
        return 0;
    
    return start_threads();
}
