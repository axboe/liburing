CFLAGS ?= -g -O2 -Wall -D_GNU_SOURCE -L../src/

all_targets += io_uring-test io_uring-cp poll poll-cancel ring-leak fsync \
	io_uring_setup io_uring_register io_uring_enter

all: $(all_targets)

test_srcs := io_uring-test.c io_uring-cp.c poll.c poll-cancel.c ring-leak.c \
	fsync.c io_uring_setup.c io_uring_register.c io_uring_enter.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

io_uring-test: io_uring-test.c
	$(CC) $(CFLAGS) -o $@ io_uring-test.c -luring
io_uring-cp: io_uring-cp.c
	$(CC) $(CFLAGS) -o $@ io_uring-cp.c -luring
poll: poll.c
	$(CC) $(CFLAGS) -o $@ poll.c -luring
poll-cancel: poll-cancel.c
	$(CC) $(CFLAGS) -o $@ poll-cancel.c -luring
ring-leak: ring-leak.c
	$(CC) $(CFLAGS) -o $@ ring-leak.c -luring
fsync: fsync.c
	$(CC) $(CFLAGS) -o $@ fsync.c -luring
io_uring_setup: io_uring_setup.c
	$(CC) $(CFLAGS) -o $@ io_uring_setup.c -luring
io_uring_register: io_uring_register.c
	$(CC) $(CFLAGS) -o $@ io_uring_register.c -luring
io_uring_enter: io_uring_enter.c
	$(CC) $(CFLAGS) -o $@ io_uring_enter.c -luring
clean:
	rm -f $(all_targets) $(test_objs)
