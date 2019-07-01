#ifndef LIBURING_BARRIER_H
#define LIBURING_BARRIER_H

/*
From the kernel documentation file refcount-vs-atomic.rst:

A RELEASE memory ordering guarantees that all prior loads and
stores (all po-earlier instructions) on the same CPU are completed
before the operation. It also guarantees that all po-earlier
stores on the same CPU and all propagated stores from other CPUs
must propagate to all other CPUs before the release operation
(A-cumulative property). This is implemented using
:c:func:`smp_store_release`.

An ACQUIRE memory ordering guarantees that all post loads and
stores (all po-later instructions) on the same CPU are
completed after the acquire operation. It also guarantees that all
po-later stores on the same CPU must propagate to all other CPUs
after the acquire operation executes. This is implemented using
:c:func:`smp_acquire__after_ctrl_dep`.
*/

/* From tools/include/linux/compiler.h */
/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() __asm__ __volatile__("": : :"memory")

/* From tools/virtio/linux/compiler.h */
#define WRITE_ONCE(var, val) \
	(*((volatile typeof(val) *)(&(var))) = (val))
#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))


#if defined(__x86_64) || defined(__i386__)
/* From tools/arch/x86/include/asm/barrier.h */
#if defined(__i386__)
/*
 * Some non-Intel clones support out of order store. wmb() ceases to be a
 * nop for these.
 */
#define mb()	asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#define rmb()	asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#define wmb()	asm volatile("lock; addl $0,0(%%esp)" ::: "memory")
#elif defined(__x86_64__)
#define mb()	asm volatile("mfence" ::: "memory")
#define rmb()	asm volatile("lfence" ::: "memory")
#define wmb()	asm volatile("sfence" ::: "memory")
#define smp_rmb() barrier()
#define smp_wmb() barrier()
#define smp_mb()  asm volatile("lock; addl $0,-132(%%rsp)" ::: "memory", "cc")
#endif

#if defined(__x86_64__)
#define smp_store_release(p, v)			\
do {						\
	barrier();				\
	WRITE_ONCE(*(p), (v));			\
} while (0)

#define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p1 = READ_ONCE(*(p));	\
	barrier();				\
	___p1;					\
})
#endif /* defined(__x86_64__) */
#else
/*
 * Add arch appropriate definitions. Be safe and use full barriers for
 * archs we don't have support for.
 */
#define smp_rmb()	__sync_synchronize()
#define smp_wmb()	__sync_synchronize()
#endif

/* From tools/include/asm/barrier.h */

#ifndef smp_store_release
# define smp_store_release(p, v)		\
do {						\
	smp_mb();				\
	WRITE_ONCE(*p, v);			\
} while (0)
#endif

#ifndef smp_load_acquire
# define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p1 = READ_ONCE(*p);	\
	smp_mb();				\
	___p1;					\
})
#endif

#endif
