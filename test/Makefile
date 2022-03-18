prefix ?= /usr
datadir ?= $(prefix)/share

INSTALL=install

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

CPPFLAGS ?=

override CPPFLAGS += \
	-D_GNU_SOURCE \
	-D__SANE_USERSPACE_TYPES__ \
	-I../src/include/ \
	-include ../config-host.h

CFLAGS ?= -g -O2 -Wall -Wextra
XCFLAGS = -Wno-unused-parameter -Wno-sign-compare

ifdef CONFIG_HAVE_STRINGOP_OVERFLOW
	XCFLAGS += -Wstringop-overflow=0
endif

ifdef CONFIG_HAVE_ARRAY_BOUNDS
	XCFLAGS += -Warray-bounds=0
endif

CXXFLAGS ?= $(CFLAGS)
override CFLAGS += $(XCFLAGS) -DLIBURING_BUILD_TEST
override CXXFLAGS += $(XCFLAGS) -std=c++11 -DLIBURING_BUILD_TEST

LDFLAGS ?=
override LDFLAGS += -L../src/ -luring

test_srcs := \
	232c93d07b74-test.c \
	35fa71a030ca-test.c \
	500f9fbadef8-test.c \
	7ad0e4b2f83c-test.c \
	8a9973408177-test.c \
	917257daa0fe-test.c \
	a0908ae19763-test.c \
	a4c0b3decb33-test.c \
	accept.c \
	accept-link.c \
	accept-reuse.c \
	accept-test.c \
	across-fork.c \
	b19062a56726-test.c \
	b5837bd5311d-test.c \
	ce593a6c480a-test.c \
	close-opath.c \
	connect.c \
	cq-full.c \
	cq-overflow.c \
	cq-peek-batch.c \
	cq-ready.c \
	cq-size.c \
	d4ae271dfaae-test.c \
	d77a67ed5f27-test.c \
	defer.c \
	double-poll-crash.c \
	drop-submit.c \
	eeed8b54e0df-test.c \
	empty-eownerdead.c \
	eventfd.c \
	eventfd-disable.c \
	eventfd-reg.c \
	eventfd-ring.c \
	exec-target.c \
	exit-no-cleanup.c \
	fadvise.c \
	fallocate.c \
	fc2a85cb02ef-test.c \
	file-register.c \
	files-exit-hang-poll.c \
	files-exit-hang-timeout.c \
	file-update.c \
	file-verify.c \
	fixed-buf-iter.c \
	fixed-link.c \
	fpos.c \
	fsync.c \
	hardlink.c \
	io-cancel.c \
	iopoll.c \
	io_uring_enter.c \
	io_uring_register.c \
	io_uring_setup.c \
	lfs-openat.c \
	lfs-openat-write.c \
	link.c \
	link_drain.c \
	link-timeout.c \
	madvise.c \
	mkdir.c \
	msg-ring.c \
	multicqes_drain.c \
	nop-all-sizes.c \
	nop.c \
	openat2.c \
	open-close.c \
	personality.c \
	pipe-eof.c \
	pipe-reuse.c \
	poll.c \
	poll-cancel.c \
	poll-cancel-ton.c \
	poll-link.c \
	poll-many.c \
	poll-mshot-update.c \
	poll-ring.c \
	poll-v-poll.c \
	pollfree.c \
	probe.c \
	read-write.c \
	register-restrictions.c \
	rename.c \
	ring-leak2.c \
	ring-leak.c \
	rsrc_tags.c \
	rw_merge_test.c \
	self.c \
	sendmsg_fs_cve.c \
	send_recv.c \
	send_recvmsg.c \
	shared-wq.c \
	short-read.c \
	shutdown.c \
	sigfd-deadlock.c \
	socket-rw.c \
	socket-rw-eagain.c \
	socket-rw-offset.c \
	splice.c \
	sq-full.c \
	sq-full-cpp.cc \
	sqpoll-cancel-hang.c \
	sqpoll-disable-exit.c \
	sq-poll-dup.c \
	sqpoll-exit-hang.c \
	sq-poll-kthread.c \
	sq-poll-share.c \
	sqpoll-sleep.c \
	sq-space_left.c \
	stdout.c \
	submit-link-fail.c \
	submit-reuse.c \
	symlink.c \
	teardowns.c \
	thread-exit.c \
	timeout.c \
	timeout-new.c \
	timeout-overflow.c \
	unlink.c \
	wakeup-hang.c \
	skip-cqe.c \
	# EOL


all_targets :=
include ../Makefile.quiet


ifdef CONFIG_HAVE_STATX
	test_srcs += statx.c
endif

ifdef CONFIG_HAVE_GLIBC_STATX
	test_srcs += statx.c
endif
all_targets += statx


ifdef CONFIG_HAVE_CXX
	test_srcs += sq-full-cpp.cc
endif
all_targets += sq-full-cpp


test_targets := $(patsubst %.c,%,$(patsubst %.cc,%,$(test_srcs)))
all_targets += $(test_targets)

#
# Build ../src/syscall.c manually from test's Makefile to support
# liburing nolibc.
#
# Functions in ../src/syscall.c require libc to work with, if we
# build liburing without libc, we don't have those functions
# in liburing.a. So build it manually here.
#
helpers = helpers.o ../src/syscall.o

all: $(test_targets)

../src/syscall.o: ../src/syscall.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

helpers.o: helpers.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

%: %.c $(helpers) helpers.h ../src/liburing.a
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(helpers) $(LDFLAGS)

%: %.cc $(helpers) helpers.h ../src/liburing.a
	$(QUIET_CXX)$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< $(helpers) $(LDFLAGS)


35fa71a030ca-test: override LDFLAGS += -lpthread
232c93d07b74-test: override LDFLAGS += -lpthread
send_recv: override LDFLAGS += -lpthread
send_recvmsg: override LDFLAGS += -lpthread
poll-link: override LDFLAGS += -lpthread
accept-link: override LDFLAGS += -lpthread
submit-reuse: override LDFLAGS += -lpthread
poll-v-poll: override LDFLAGS += -lpthread
across-fork: override LDFLAGS += -lpthread
ce593a6c480a-test: override LDFLAGS += -lpthread
wakeup-hang: override LDFLAGS += -lpthread
pipe-eof: override LDFLAGS += -lpthread
timeout-new: override LDFLAGS += -lpthread
thread-exit: override LDFLAGS += -lpthread
ring-leak2: override LDFLAGS += -lpthread
poll-mshot-update: override LDFLAGS += -lpthread
exit-no-cleanup: override LDFLAGS += -lpthread
pollfree: override LDFLAGS += -lpthread
msg-ring: override LDFLAGS += -lpthread

install: $(test_targets) runtests.sh runtests-loop.sh
	$(INSTALL) -D -d -m 755 $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 $(test_targets) $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests.sh  $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests-loop.sh  $(datadir)/liburing-test/

clean:
	@rm -f $(all_targets) helpers.o output/*
	@rm -rf output/

runtests: all
	@./runtests.sh $(test_targets)

runtests-loop: all
	@./runtests-loop.sh $(test_targets)

.PHONY: all install clean runtests runtests-loop
