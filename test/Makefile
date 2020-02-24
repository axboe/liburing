prefix ?= /usr
datadir ?= $(prefix)/share

INSTALL=install

CFLAGS ?= -g -O2
XCFLAGS =
override CFLAGS += -Wall -D_GNU_SOURCE -L../src/ -I../src/include/ -include ../config-host.h

all_targets += poll poll-cancel ring-leak fsync io_uring_setup io_uring_register \
	       io_uring_enter nop sq-full cq-full 35fa71a030ca-test \
		917257daa0fe-test b19062a56726-test eeed8b54e0df-test link \
		send_recvmsg a4c0b3decb33-test 500f9fbadef8-test timeout \
		sq-space_left stdout cq-ready cq-peek-batch file-register \
		cq-size 8a9973408177-test a0908ae19763-test 232c93d07b74-test \
		socket-rw accept timeout-overflow defer read-write io-cancel \
		link-timeout cq-overflow link_drain fc2a85cb02ef-test \
		poll-link accept-link fixed-link poll-cancel-ton teardowns \
		poll-many b5837bd5311d-test accept-test d77a67ed5f27-test \
		connect 7ad0e4b2f83c-test submit-reuse fallocate open-close \
		file-update statx accept-reuse poll-v-poll fadvise madvise \
		short-read openat2 probe shared-wq personality eventfd \
		send_recv eventfd-ring across-fork sq-poll-kthread splice

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all: $(all_targets)

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -luring $(XCFLAGS)

test_srcs := poll.c poll-cancel.c ring-leak.c fsync.c io_uring_setup.c \
	io_uring_register.c io_uring_enter.c nop.c sq-full.c cq-full.c \
	35fa71a030ca-test.c 917257daa0fe-test.c b19062a56726-test.c \
	eeed8b54e0df-test.c link.c send_recvmsg.c a4c0b3decb33-test.c \
	500f9fbadef8-test.c timeout.c sq-space_left.c stdout.c cq-ready.c\
	cq-peek-batch.c file-register.c cq-size.c 8a9973408177-test.c \
	a0908ae19763-test.c 232c93d07b74-test.c socket-rw.c accept.c \
	timeout-overflow.c defer.c read-write.c io-cancel.c link-timeout.c \
	cq-overflow.c link_drain.c fc2a85cb02ef-test.c poll-link.c \
	accept-link.c fixed-link.c poll-cancel-ton.c teardowns.c poll-many.c \
	b5837bd5311d-test.c accept-test.c d77a67ed5f27-test.c connect.c \
	7ad0e4b2f83c-test.c submit-reuse.c fallocate.c open-close.c \
	file-update.c statx.c accept-reuse.c poll-v-poll.c fadvise.c \
	madvise.c short-read.c openat2.c probe.c shared-wq.c \
	personality.c eventfd.c eventfd-ring.c across-fork.c sq-poll-kthread.c \
	splice.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

35fa71a030ca-test: XCFLAGS = -lpthread
232c93d07b74-test: XCFLAGS = -lpthread
send_recv: XCFLAGS = -lpthread
send_recvmsg: XCFLAGS = -lpthread
poll-link: XCFLAGS = -lpthread
accept-link: XCFLAGS = -lpthread
submit-reuse: XCFLAGS = -lpthread
poll-v-poll: XCFLAGS = -lpthread
across-fork: XCFLAGS = -lpthread

install: $(all_targets) runtests.sh runtests-loop.sh
	$(INSTALL) -D -d -m 755 $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 $(all_targets) $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests.sh  $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests-loop.sh  $(datadir)/liburing-test/
clean:
	@rm -f $(all_targets) $(test_objs)

runtests: all
	@./runtests.sh $(all_targets)
runtests-loop: all
	@./runtests-loop.sh $(all_targets)
