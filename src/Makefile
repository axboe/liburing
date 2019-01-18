prefix=/usr
includedir=$(prefix)/include
libdir=$(prefix)/lib

CFLAGS ?= -g -fomit-frame-pointer -O2
CFLAGS += -Wall -I. -fPIC
SO_CFLAGS=-shared $(CFLAGS)
L_CFLAGS=$(CFLAGS)
LINK_FLAGS=
LINK_FLAGS+=$(LDFLAGS)
ENABLE_SHARED ?= 1

soname=liburing.so.1
minor=0
micro=1
libname=$(soname).$(minor).$(micro)
all_targets += liburing.a

ifeq ($(ENABLE_SHARED),1)
all_targets += $(libname)
endif

all: $(all_targets)

liburing_srcs := setup.c queue.c syscall.c

liburing_objs := $(patsubst %.c,%.ol,$(liburing_srcs))
liburing_sobjs := $(patsubst %.c,%.os,$(liburing_srcs))

$(liburing_objs) $(liburing_sobjs): io_uring.h

%.os: %.c
	$(CC) $(SO_CFLAGS) -c -o $@ $<

%.ol: %.c
	$(CC) $(L_CFLAGS) -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
liburing.a: $(liburing_objs)
	rm -f liburing.a
	$(AR) r liburing.a $^
	$(RANLIB) liburing.a

$(libname): $(liburing_sobjs) liburing.map
	$(CC) $(SO_CFLAGS) -Wl,--version-script=liburing.map -Wl,-soname=$(soname) -o $@ $(liburing_sobjs) $(LINK_FLAGS)

install: $(all_targets)
	install -D -m 644 io_uring.h $(includedir)/io_uring.h
	install -D -m 644 liburing.a $(libdir)/liburing.a
ifeq ($(ENABLE_SHARED),1)
	install -D -m 755 $(libname) $(libdir)/$(libname)
	ln -sf $(libname) $(libdir)/$(soname)
	ln -sf $(libname) $(libdir)/liburing.so
endif

$(liburing_objs): liburing.h

clean:
	rm -f $(all_targets) $(liburing_objs) $(liburing_sobjs) $(soname).new
	rm -f *.so* *.a *.o
