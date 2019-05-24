CFLAGS ?= -g -O2 -Wall -D_GNU_SOURCE -L../src/

all_targets += poll poll-cancel ring-leak fsync io_uring_setup io_uring_register \
	       io_uring_enter nop sq-full cq-full 35fa71a030ca-test \
		917257daa0fe-test b19062a56726-test eeed8b54e0df-test link \
		send_recvmsg

all: $(all_targets)

test_srcs := poll.c poll-cancel.c ring-leak.c fsync.c io_uring_setup.c \
	io_uring_register.c io_uring_enter.c nop.c sq-full.c cq-full.c \
	35fa71a030ca-test.c 917257daa0fe-test.c b19062a56726-test.c \
	eeed8b54e0df-test.c link.c send_recvmsg.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

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
nop: nop.c
	$(CC) $(CFLAGS) -o $@ nop.c -luring
sq-full: sq-full.c
	$(CC) $(CFLAGS) -o $@ sq-full.c -luring
cq-full: cq-full.c
	$(CC) $(CFLAGS) -o $@ cq-full.c -luring
35fa71a030ca-test: 35fa71a030ca-test.c
	$(CC) $(CFLAGS) -o $@ 35fa71a030ca-test.c -lpthread
917257daa0fe-test: 917257daa0fe-test.c
	$(CC) $(CFLAGS) -o $@ 917257daa0fe-test.c
b19062a56726-test: b19062a56726-test.c
	$(CC) $(CFLAGS) -o $@ b19062a56726-test.c
eeed8b54e0df-test: eeed8b54e0df-test.c
	$(CC) $(CFLAGS) -o $@ eeed8b54e0df-test.c -luring
link: link.c
	$(CC) $(CFLAGS) -o $@ link.c -luring
send_recvmsg: send_recvmsg.c
	$(CC) $(CFLAGS) -o $@ send_recvmsg.c -luring

clean:
	rm -f $(all_targets) $(test_objs)

runtests:
	@./runtests.sh $(all_targets)
