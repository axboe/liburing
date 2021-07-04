/* SPDX-License-Identifier: MIT */
//
//  Test for multiple polls (ie. not oneshots) and updates
//  of polling masks to those.
//
//  t1 is the 'server' accepting and t2 is the 'client' connecting.
//
//  t1 will simply echo any data recieved, t2 will switch between POLLIN/POLLOUT.
//
//  This test explores failure conditions of modifications of pollmasks.
//
// First we run NUMBER_OF_EVENTS successfull modifications
// followed by as many referencing invalid user data
// followed by as many with a bad fd

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

#define NUMBER_OF_EVENTS 20 // number of events tested before next step

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static int server_thread_ready = 0;
static int server_thread_done = 0;
static int port = 0; // protected by the mutex, will be set before server signals ready

enum edge_states // error state we trigger
{
    NORMAL, // first run a handful successful modifications
    TRIGGER_ENOENT,
    TRIGGER_EINVAL
};

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

static void submit(struct io_uring *ring)
{
    int ret;
    
    while (io_uring_sq_ready(ring) > 0)
    {
        ret = io_uring_submit(ring);
        assert ( ret >= 0);
    }
    
    return;
}

static void add_poll_mask(struct io_uring *ring, int fd, uint64_t poll_mask)
{
    struct io_uring_sqe *sqe;
    uint64_t bitpattern;
    
    sqe = io_uring_get_sqe(ring);
    assert(sqe != NULL);
    
    bitpattern = (poll_mask << 32) + fd;
    io_uring_prep_poll_add(sqe, fd, poll_mask);
    io_uring_sqe_set_data(sqe, (void *) bitpattern);
    sqe->len |= IORING_POLL_ADD_MULTI;

    submit(ring);

    return;
}

static struct io_uring_sqe *switch_poll_mask(struct io_uring *ring, int fd, uint64_t old_poll_mask, uint64_t new_poll_mask)
{
    struct io_uring_sqe *sqe;
    int flags = IORING_POLL_UPDATE_USER_DATA | IORING_POLL_UPDATE_EVENTS | IORING_POLL_ADD_MULTI;
    uint64_t old_bitpattern, new_bitpattern;

    sqe = io_uring_get_sqe(ring);
    assert(sqe != NULL);
    
    old_bitpattern = (old_poll_mask << 32) + fd;
    new_bitpattern = (new_poll_mask << 32) + fd;
    
    io_uring_prep_poll_update(sqe, (void *) old_bitpattern, (void *) new_bitpattern, new_poll_mask, flags);
    io_uring_sqe_set_data(sqe, (void *) old_bitpattern);
    
    return sqe;
}

static void invalid_switch_poll_mask(struct io_uring *ring, int fd)
{
    struct io_uring_sqe *sqe;
    uint64_t pollmask = (POLLIN | POLLHUP | POLLERR);
    
    sqe = switch_poll_mask(ring, fd, pollmask, pollmask);
    
    // set some invalid stuff
    sqe->ioprio = 1;
    sqe->buf_index = 3;
    return;
}

void *server_thread(void *arg)
{
    struct io_uring ring;
    int i, ret, client_fd, s0, done = 0;
    struct sockaddr_in addr;
    unsigned int rand_seed = getpid();
    char readbuffer[1024];
    
        // set up uring
    ret = io_uring_queue_init(64, &ring, 0);
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
    
    add_poll_mask(&ring, client_fd, POLLIN | POLLHUP | POLLERR);
    
    while (!done) {
        struct io_uring_cqe *cqe;
        
        if (io_uring_wait_cqe(&ring, &cqe)) {
            fprintf(stderr, "server wait cqe failed\n");
            exit(1);
        }
        
        if (POLLIN & cqe->res) {
            while ((ret = read(client_fd, readbuffer, 1)) > 0)
            {
                readbuffer[1]=0;
                assert (ret == 1);
                ret = write(client_fd, "S", 1);
                assert(ret == 1);
            }
        }
        
        if ((POLLERR | POLLHUP) & cqe->res) {
            done = 1;
        }
                
        io_uring_cqe_seen(&ring, cqe);
    }
    
    close(s0);
    close(client_fd);
    signal_var(&server_thread_done);
    io_uring_queue_exit(&ring);
    return NULL;
}

static void *client_thread(void *arg)
{
    struct io_uring ring;
    struct io_uring_cqe *cqe;
    enum edge_states state = NORMAL;
    int fd, ret, done = 0, expecting_data = 0, successful_events = 0;
    uint64_t user_data, poll_mask;
    char readbuffer[1024];
    
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
    
        // set up uring
    ret = io_uring_queue_init(16, &ring, 0);
    assert(ret == 0);
    
    add_poll_mask(&ring, s0, POLLOUT | POLLHUP | POLLERR); // POLLRDHUP
    
    int flags = fcntl(s0, F_GETFL, 0);
    fcntl(s0, F_SETFL, flags | O_NONBLOCK);
    
    while (!done)
    {
        if (io_uring_wait_cqe(&ring, &cqe)) {
            fprintf(stderr, "wait cqe failed\n");
        }
        
        user_data = (uint64_t) io_uring_cqe_get_data(cqe);
        assert(user_data != 0);
        fd = user_data & 0x00000000FFFFFFFF; // mask out the fd
        poll_mask = user_data >> 32;         // and shift out the fd to get the poll_mask
        
        if (cqe->res > 0) { // handle normal poll events, running some ping-pong
            if (state == NORMAL)
            {
                if (POLLIN & cqe->res) {
                    while ((ret = read(fd, readbuffer, 1)) > 0)
                    {
                        readbuffer[1]=0;
                        assert (ret == 1);
                        if (!expecting_data) {
                            printf("Client recevied unexpected POLLIN with data available\n");
                            expecting_data++;
                        }
                    }
                    
                    if (!expecting_data)
                    {
                        printf("Client recevied unexpected POLLIN with no data available\n");
                        exit(1);
                    }
                    expecting_data = 0; // we emptied the incoming data, so should have no more coming
                    (void) switch_poll_mask(&ring, fd, poll_mask, (POLLOUT | POLLHUP | POLLERR));
                }
                
                if (POLLOUT & cqe->res) {
                    if (expecting_data)
                    {
                        printf("Client recevied unexpected POLLOUT while expecting data\n");
                        exit(1);
                    }
                    ret = write(fd, "X", 1);
                    assert(ret == 1);
                    expecting_data = 1; // we emptied the incoming data, so should have no more coming
                    (void) switch_poll_mask(&ring, fd, poll_mask, (POLLIN | POLLHUP | POLLERR));
                }
                
                if (POLLHUP & cqe->res) {
                    done = 1;
                }
                
                if (POLLERR & cqe->res) {
                    done = 1;
                }
            }
        } else { // handle failure modes (and success of modifications)
            switch (cqe->res) {
                case 0:
                    if (state == NORMAL) {
                        successful_events++;
                        if (successful_events >= NUMBER_OF_EVENTS)
                        {
                            (void) switch_poll_mask(&ring, fd, 0x123456, 0x8910);
                        }
                    }
                    break;
                case -ENOENT:
                    if (state == NORMAL) { // first
                        successful_events = 0;
                        state = TRIGGER_ENOENT;
                    } else if (state != TRIGGER_ENOENT) {
                        fprintf(stderr, "Unexpected state transition to ENOENT [%d], test failed.\n", state);
                        exit(1);
                    }
                    if (state == TRIGGER_ENOENT) {
                        successful_events++;
                        if (successful_events >= NUMBER_OF_EVENTS)
                        {
                            invalid_switch_poll_mask(&ring, s0);
                        } else {
                            (void) switch_poll_mask(&ring, fd, 0x123456, 0x8910);
                        }
                    } else {
                        fprintf(stderr, "Received -ENOENT unexpectedly, test failed.\n");
                        exit(1);
                    }
                    break;
                case -EINVAL:
                    if (state == TRIGGER_ENOENT) {
                        state = TRIGGER_EINVAL;
                        successful_events = 0;
                    } else if (state != TRIGGER_EINVAL) {
                        fprintf(stderr, "Unexpected state transition to EINVAL [%d], test failed.\n", state);
                        exit(1);
                    }
                    if (state == TRIGGER_EINVAL) {
                        successful_events++;
                        if (successful_events >= NUMBER_OF_EVENTS)
                        {
                            done = 1;
                        } else {
                            invalid_switch_poll_mask(&ring, s0);
                        }
                    } else {
                        fprintf(stderr, "Received -EINVAL unexpectedly, test failed.\n");
                        exit(1);
                    }
                    break;
                default:
                    printf("Received unexpected failure for modifying poll mask fd [%d] cqe->res [%d] poll_mask [%ld], test failed.\n", fd, cqe->res, poll_mask);
                    exit(1);
                    break;
            }
        }
        
        io_uring_cqe_seen(&ring, cqe);
        submit(&ring);
    }
    
    close(s0);
    io_uring_queue_exit(&ring);
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
