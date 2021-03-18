/* SPDX-License-Identifier: MIT */
//
//  Test for multiple polls (ie. not oneshots).
//
//  Tests runs two threads and uses an eventfd to trigger uring.
//
//  t1 creates a ring and reaps events, t2 generates random wakeups with the eventfd.
//


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

#define CLIENT_WAKEUPS 100

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static int client_thread_ready = 0;
static int client_thread_done = 0;
static int event_fd = 0;

static void signal_var(int *var)
{
        pthread_mutex_lock(&mutex);
        *var = 1;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
}

static void wait_for_var(int *var)
{
        pthread_mutex_lock(&mutex);

        while (!*var)
                pthread_cond_wait(&cond, &mutex);

        pthread_mutex_unlock(&mutex);
}

static void *client_thread(void *arg)
{
    struct io_uring_sqe *sqe;
    struct io_uring ring;
    struct io_uring_cqe *cqe;
    int ret, done = 0;
    uint64_t u;

    ret = io_uring_queue_init(8, &ring, 0);
    assert(ret == 0);

    sqe = io_uring_get_sqe(&ring);
    assert(sqe != NULL);

    io_uring_prep_poll_add(sqe, event_fd, POLLIN);
    sqe->len |= IORING_POLL_ADD_MULTI;

    ret = io_uring_submit(&ring);
    assert(ret == 1);

    signal_var(&client_thread_ready);

    while (!done)
    {
        if (io_uring_wait_cqe(&ring, &cqe)) {
            fprintf(stderr, "wait cqe failed\n");
        }
        ret = read(event_fd, &u, sizeof(uint64_t));
        if (ret == sizeof(uint64_t))
        {
            if (u == CLIENT_WAKEUPS)
                done = 1;
        }
        else
        {
            assert (errno == EAGAIN);
        }
        io_uring_cqe_seen(&ring, cqe);
    }
    
    io_uring_queue_exit(&ring);
    signal_var(&client_thread_done);

    return 0;
}

static void *wakeup_thread(void *arg)
{
    int res;
    unsigned int rand_seed = getpid();
    uint64_t u;

    wait_for_var(&client_thread_ready);
    
    usleep((rand_r(&rand_seed) % 10000) * 100); // sleep up to 1s before starting
    
    for (u=1; u <= CLIENT_WAKEUPS; u++)
    {
        res = usleep((rand_r(&rand_seed) % 100) * 1000); // sleep up to 0.1s
        assert(res != -1);
        res = write(event_fd, &u, sizeof(uint64_t));
        assert(res == sizeof(uint64_t));
    }
    
    wait_for_var(&client_thread_done);

    return 0;
}

static int start_threads()
{
    pthread_t t1, t2;
    void *tret;
    int ret = 0;

    client_thread_ready = 0;
    client_thread_done = 0;
 
    pthread_create(&t1, NULL, client_thread, NULL);
    pthread_create(&t2, NULL, wakeup_thread, NULL);
    
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
    
    event_fd = eventfd(0, O_CLOEXEC | EFD_NONBLOCK);

    assert(event_fd != -1);

    return start_threads();
}
