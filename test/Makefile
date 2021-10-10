prefix ?= /usr
datadir ?= $(prefix)/share

INSTALL=install

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

CPPFLAGS ?=
override CPPFLAGS += -D_GNU_SOURCE -D__SANE_USERSPACE_TYPES__ \
	-I../src/include/ -include ../config-host.h
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

test_targets += \
	232c93d07b74-test \
	35fa71a030ca-test \
	500f9fbadef8-test \
	7ad0e4b2f83c-test \
	8a9973408177-test \
	917257daa0fe-test \
	a0908ae19763-test \
	a4c0b3decb33-test \
	accept \
	accept-link \
	accept-reuse \
	accept-test \
	across-fork splice \
	b19062a56726-test \
	b5837bd5311d-test \
	ce593a6c480a-test \
	close-opath \
	connect \
	cq-full \
	cq-overflow \
	cq-peek-batch \
	cq-ready \
	cq-size \
	d4ae271dfaae-test \
	d77a67ed5f27-test \
	defer \
	double-poll-crash \
	eeed8b54e0df-test \
	empty-eownerdead \
	eventfd \
	eventfd-disable \
	eventfd-ring \
	fadvise \
	fallocate \
	fc2a85cb02ef-test \
	file-register \
	file-verify \
	file-update \
	files-exit-hang-poll \
	files-exit-hang-timeout \
	fixed-link \
	fsync \
	hardlink \
	io-cancel \
	io_uring_enter \
	io_uring_register \
	io_uring_setup \
	iopoll \
	lfs-openat \
	lfs-openat-write \
	link \
	link-timeout \
	link_drain \
	madvise \
	mkdir \
	multicqes_drain \
	nop \
	nop-all-sizes \
	open-close \
	openat2 \
	personality \
	pipe-eof \
	pipe-reuse \
	poll \
	poll-cancel \
	poll-cancel-ton \
	poll-link \
	poll-many \
	poll-mshot-update \
	poll-ring \
	poll-v-poll \
	probe \
	read-write \
	register-restrictions \
	rename \
	ring-leak \
	ring-leak2 \
	rw_merge_test \
	self \
	send_recv \
	send_recvmsg \
	shared-wq \
	short-read \
	shutdown \
	sigfd-deadlock \
	socket-rw \
	socket-rw-eagain \
	sq-full \
	sq-poll-dup \
	sq-poll-kthread \
	sq-poll-share \
	sqpoll-disable-exit \
	sqpoll-exit-hang \
	sqpoll-cancel-hang \
	sqpoll-sleep \
	sq-space_left \
	stdout \
	submit-reuse \
	submit-link-fail \
	symlink \
	teardowns \
	thread-exit \
	timeout \
	timeout-new \
	timeout-overflow \
	unlink \
	wakeup-hang \
	sendmsg_fs_cve \
	rsrc_tags \
	exec-target \
	# EOL

all_targets += $(test_targets)

include ../Makefile.quiet

ifdef CONFIG_HAVE_STATX
test_targets += statx
endif
all_targets += statx

ifdef CONFIG_HAVE_CXX
test_targets += sq-full-cpp
endif
all_targets += sq-full-cpp

#
# Build ../src/syscall.c manually from test's Makefile to support
# liburing nolibc.
#
# Functions in ../src/syscall.c require libc to work with, if we
# build liburing without libc, we don't have those functions
# in liburing.a. So build it manually here.
#
helpers = helpers.o ../src/syscall.o

all: ${helpers} $(test_targets)

../src/syscall.o: ../src/syscall.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

helpers.o: helpers.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

%: %.c ${helpers} helpers.h
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< ${helpers} $(LDFLAGS)

%: %.cc ${helpers} helpers.h
	$(QUIET_CXX)$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< ${helpers} $(LDFLAGS)

test_srcs := \
	helpers.c \
	232c93d07b74-test.c \
	35fa71a030ca-test.c \
	500f9fbadef8-test.c \
	7ad0e4b2f83c-test.c \
	8a9973408177-test.c \
	917257daa0fe-test.c \
	a0908ae19763-test.c \
	a4c0b3decb33-test.c \
	accept-link.c \
	accept-reuse.c \
	accept-test.c \
	accept.c \
	across-fork.c \
	b19062a56726-test.c \
	b5837bd5311d-test.c \
	ce593a6c480a-test.c \
	close-opath.c \
	connect.c \
	cq-full.c \
	cq-overflow.c \
	cq-peek-batch.c \
	cq-ready.c\
	cq-size.c \
	d4ae271dfaae-test.c \
	d77a67ed5f27-test.c \
	defer.c \
	double-poll-crash.c \
	eeed8b54e0df-test.c \
	empty-eownerdead.c \
	eventfd-disable.c \
	eventfd-ring.c \
	eventfd.c \
	fadvise.c \
	fallocate.c \
	fc2a85cb02ef-test.c \
	file-register.c \
	file-verify.c \
	file-update.c \
	files-exit-hang-poll.c \
	files-exit-hang-timeout.c \
	fixed-link.c \
	fsync.c \
	hardlink.c \
	io-cancel.c \
	io_uring_enter.c \
	io_uring_register.c \
	io_uring_setup.c \
	iopoll.c \
	lfs-openat-write.c \
	lfs-openat.c \
	link-timeout.c \
	link.c \
	link_drain.c \
	madvise.c \
	mkdir.c \
	multicqes_drain.c \
	nop-all-sizes.c \
	nop.c \
	open-close.c \
	openat2.c \
	personality.c \
	pipe-eof.c \
	pipe-reuse.c \
	poll-cancel-ton.c \
	poll-cancel.c \
	poll-link.c \
	poll-many.c \
	poll-mshot-update.c \
	poll-ring.c \
	poll-v-poll.c \
	poll.c \
	probe.c \
	read-write.c \
	register-restrictions.c \
	rename.c \
	ring-leak.c \
	ring-leak2.c \
	rw_merge_test.c \
	self.c \
	send_recvmsg.c \
	shared-wq.c \
	short-read.c \
	shutdown.c \
	sigfd-deadlock.c \
	socket-rw.c \
	socket-rw-eagain.c \
	splice.c \
	sq-full-cpp.cc \
	sq-full.c \
	sq-poll-dup.c \
	sq-poll-kthread.c \
	sq-poll-share.c \
	sqpoll-disable-exit.c \
	sqpoll-exit-hang.c \
	sqpoll-cancel-hang.c \
	sqpoll-sleep.c \
	sq-space_left.c \
	statx.c \
	stdout.c \
	submit-reuse.c \
	submit-link-fail.c \
	symlink.c \
	teardowns.c \
	thread-exit.c \
	timeout-new.c \
	timeout-overflow.c \
	timeout.c \
	unlink.c \
	wakeup-hang.c \
	sendmsg_fs_cve.c \
	rsrc_tags.c \
	exec-target.c \
	# EOL

test_objs := $(patsubst %.c,%.ol,$(patsubst %.cc,%.ol,$(test_srcs)))

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

install: $(test_targets) runtests.sh runtests-loop.sh
	$(INSTALL) -D -d -m 755 $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 $(test_targets) $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests.sh  $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests-loop.sh  $(datadir)/liburing-test/
clean:
	@rm -f $(all_targets) $(test_objs) helpers.o output/*
	@rm -rf output/

runtests: all
	@./runtests.sh $(test_targets)
runtests-loop: all
	@./runtests-loop.sh $(test_targets)
