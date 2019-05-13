CFLAGS ?= -g -O2 -Wall -D_GNU_SOURCE -L../src/

all_targets += io_uring-test io_uring-cp link-cp

all: $(all_targets)

test_srcs := io_uring-test.c io_uring-cp.c link-cp.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

io_uring-test: io_uring-test.c
	$(CC) $(CFLAGS) -o $@ io_uring-test.c -luring
io_uring-cp: io_uring-cp.c
	$(CC) $(CFLAGS) -o $@ io_uring-cp.c -luring
link-cp: link-cp.c
	$(CC) $(CFLAGS) -o $@ link-cp.c -luring

clean:
	rm -f $(all_targets) $(test_objs)
