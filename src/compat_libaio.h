/* /usr/include/libaio.h
 *
 * Copyright 2000,2001,2002 Red Hat, Inc.
 *
 * Written by Benjamin LaHaise <bcrl@redhat.com>
 *
 * libaio Linux async I/O interface
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
#ifndef __LIBAIO_H
#define __LIBAIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <signal.h>

struct timespec;
struct sockaddr;
struct iovec;

typedef struct io_context *io_context_t;

typedef enum io_iocb_cmd {
	IO_CMD_PREAD = 0,
	IO_CMD_PWRITE = 1,

	IO_CMD_FSYNC = 2,
	IO_CMD_FDSYNC = 3,

	IO_CMD_POLL = 5,
	IO_CMD_NOOP = 6,
	IO_CMD_PREADV = 7,
	IO_CMD_PWRITEV = 8,
} io_iocb_cmd_t;

/* little endian, 32 bits */
#if defined(__i386__) || (defined(__arm__) && !defined(__ARMEB__)) || \
    defined(__sh__) || defined(__bfin__) || defined(__MIPSEL__) || \
    defined(__cris__) || (defined(__riscv) && __riscv_xlen == 32) || \
    (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
         __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && __SIZEOF_LONG__ == 4)
#define PADDED(x, y)	x; unsigned y
#define PADDEDptr(x, y)	x; unsigned y
#define PADDEDul(x, y)	unsigned long x; unsigned y

/* little endian, 64 bits */
#elif defined(__ia64__) || defined(__x86_64__) || defined(__alpha__) || \
      (defined(__aarch64__) && defined(__AARCH64EL__)) || \
      (defined(__riscv) && __riscv_xlen == 64) || \
      (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
          __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && __SIZEOF_LONG__ == 8)
#define PADDED(x, y)	x, y
#define PADDEDptr(x, y)	x
#define PADDEDul(x, y)	unsigned long x

/* big endian, 64 bits */
#elif defined(__powerpc64__) || defined(__s390x__) || \
      (defined(__sparc__) && defined(__arch64__)) || \
      (defined(__aarch64__) && defined(__AARCH64EB__)) || \
      (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
           __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && __SIZEOF_LONG__ == 8)
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x,y)	x
#define PADDEDul(x, y)	unsigned long x

/* big endian, 32 bits */
#elif defined(__PPC__) || defined(__s390__) || \
      (defined(__arm__) && defined(__ARMEB__)) || \
      defined(__sparc__) || defined(__MIPSEB__) || defined(__m68k__) || \
      defined(__hppa__) || defined(__frv__) || defined(__avr32__) || \
      (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
           __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && __SIZEOF_LONG__ == 4)
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x, y)	unsigned y; x
#define PADDEDul(x, y)	unsigned y; unsigned long x

#else
#error	endian?
#endif

struct io_iocb_poll {
	PADDED(int events, __pad1);
};	/* result code is the set of result flags or -'ve errno */

struct io_iocb_sockaddr {
	struct sockaddr *addr;
	int		len;
};	/* result code is the length of the sockaddr, or -'ve errno */

struct io_iocb_common {
	PADDEDptr(void	*buf, __pad1);
	PADDEDul(nbytes, __pad2);
	long long	offset;
	long long	__pad3;
	unsigned	flags;
	unsigned	resfd;
};	/* result code is the amount read or -'ve errno */

struct io_iocb_vector {
	const struct iovec	*vec;
	int			nr;
	long long		offset;
};	/* result code is the amount read or -'ve errno */

struct iocb {
	PADDEDptr(void *data, __pad1);	/* Return in the io completion event */
	/* key: For use in identifying io requests */
	/* aio_rw_flags: RWF_* flags (such as RWF_NOWAIT) */
	PADDED(unsigned key, aio_rw_flags);

	short		aio_lio_opcode;
	short		aio_reqprio;
	int		aio_fildes;

	union {
		struct io_iocb_common		c;
		struct io_iocb_vector		v;
		struct io_iocb_poll		poll;
		struct io_iocb_sockaddr	saddr;
	} u;
};

struct io_event {
	PADDEDptr(void *data, __pad1);
	PADDEDptr(struct iocb *obj,  __pad2);
	PADDEDul(res,  __pad3);
	PADDEDul(res2, __pad4);
};

#undef PADDED
#undef PADDEDptr
#undef PADDEDul

#ifdef __cplusplus
}
#endif

#endif /* __LIBAIO_H */
