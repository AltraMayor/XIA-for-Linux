/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Code for ensuring compatibility with various platforms.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef _PLATFORM_H
#define _PLATFORM_H

#include <common_platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/kernel.h>
#include <linux/version.h>
#include <net/sock.h>
#define MALLOC(sz, prio) kmalloc(sz, prio)
#define ZALLOC(sz, prio) kzalloc(sz, prio)
#define FREE(m) kfree(m)

typedef uint32_t socklen_t;

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

#endif /* OS_LINUX_KERNEL */

#if defined(OS_USER)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#if HAVE_LIBIO
#include <libio.h>
#endif

#if defined(OS_BSD)
#include <serval/platform_tcpip.h>
#endif

#include <serval/checksum.h>

#if !defined(OS_ANDROID)
#define PAGE_SHIFT      12
#define PAGE_SIZE       (1 << PAGE_SHIFT) /* 4096 bytes */
#endif

int ilog2(unsigned long n);

#define LINUX_VERSION_CODE 132643 /* corresponds to 2.6.35 */
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

typedef unsigned char gfp_t;
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define MALLOC(sz, prio) malloc(sz)
#define kmalloc(sz, prio) malloc(sz)
#define ZALLOC(sz, prio) ({                     \
                        void *ptr = malloc(sz); \
                        memset(ptr, 0, sz);     \
                        ptr; })
#define FREE(m) free(m)
#define kfree(m) free(m)

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)

#define smp_wmb()

#define prefetch(x) x
#define __read_mostly
/*
 * Prevent the compiler from merging or refetching accesses.  The compiler
 * is also forbidden from reordering successive instances of ACCESS_ONCE(),
 * but only when the compiler is aware of some particular ordering.  One way
 * to make the compiler aware of ordering is to put the two invocations of
 * ACCESS_ONCE() in different C statements.
 *
 * This macro does absolutely -nothing- to prevent the CPU from reordering,
 * merging, or refetching absolutely anything at any time.  Its main intended
 * use is to mediate communication between process-level code and irq/NMI
 * handlers, all running on the same CPU.
 */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

/* From kernel.h */
#define __ALIGN_KERNEL(x, a)	__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(divisor) __divisor = divisor;		\
	(((x) + ((__divisor) / 2)) / (__divisor));	\
}							\
)

static inline void yield(void) {}

#define __init
#define __exit

#define panic(name) { int *foo = NULL; *foo = 1; } /* Cause a sefault */
#define WARN_ON(cond) ({                                                \
                        int ret = !!(cond);                             \
                        if (ret) fprintf(stderr, "WARN_ON: %s: %u\n", __FILE__, __LINE__); \
                        ret;                                            \
                })

/*
  Checksum functions (from Linux kernel, see platform.c) 
*/
__sum16 ip_fast_csum(const void *iph, unsigned int ihl);
__wsum csum_partial(const void *buff, int len, __wsum wsum);

int memcpy_toiovec(struct iovec *iov, unsigned char *kdata, int len);
int memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len);
int memcpy_fromiovecend(unsigned char *kdata, const struct iovec *iov,
			int offset, int len);

#define cpu_to_be16(n) htons(n)

struct __una_u16 { u16 x __attribute__((packed)); };
struct __una_u32 { u32 x __attribute__((packed)); };
struct __una_u64 { u64 x __attribute__((packed)); };

static inline u16 __get_unaligned_cpu16(const void *p)
{
	const struct __una_u16 *ptr = (const struct __una_u16 *)p;
	return ptr->x;
}

static inline u32 __get_unaligned_cpu32(const void *p)
{
	const struct __una_u32 *ptr = (const struct __una_u32 *)p;
	return ptr->x;
}

static inline u64 __get_unaligned_cpu64(const void *p)
{
	const struct __una_u64 *ptr = (const struct __una_u64 *)p;
	return ptr->x;
}

static inline void __put_unaligned_cpu16(u16 val, void *p)
{
	struct __una_u16 *ptr = (struct __una_u16 *)p;
	ptr->x = val;
}

static inline void __put_unaligned_cpu32(u32 val, void *p)
{
	struct __una_u32 *ptr = (struct __una_u32 *)p;
	ptr->x = val;
}

static inline void __put_unaligned_cpu64(u64 val, void *p)
{
	struct __una_u64 *ptr = (struct __una_u64 *)p;
	ptr->x = val;
}

static inline u16 get_unaligned_be16(const void *p)
{
	return __get_unaligned_cpu16((const u8 *)p);
}

static inline u32 get_unaligned_be32(const void *p)
{
	return __get_unaligned_cpu32((const u8 *)p);
}

static inline u64 get_unaligned_be64(const void *p)
{
	return __get_unaligned_cpu64((const u8 *)p);
}

static inline void put_unaligned_be16(u16 val, void *p)
{
	__put_unaligned_cpu16(val, p);
}

static inline void put_unaligned_be32(u32 val, void *p)
{
	__put_unaligned_cpu32(val, p);
}

static inline void put_unaligned_be64(u64 val, void *p)
{
	__put_unaligned_cpu64(val, p);
}

#include <sys/time.h>
#define get_seconds() ({                        \
                        struct timeval t;       \
                        gettimeofday(&t, NULL); \
                        t.tv_sec;               \
                })


/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

/*
 *	These inlines deal with timer wrapping correctly. You are 
 *	strongly encouraged to use them
 *	1. Because people otherwise forget
 *	2. Because if the timer wrap changes in future you won't have to
 *	   alter your driver code.
 *
 * time_after(a,b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 */
#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_before(a,b)	time_after(b,a)

#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_before_eq(a,b)	time_after_eq(b,a)


#if BITS_PER_LONG == 64

# define do_div(n,base) ({					\
                        uint32_t __base = (base);               \
                        uint32_t __rem;                         \
                        __rem = ((uint64_t)(n)) % __base;       \
                        (n) = ((uint64_t)(n)) / __base;         \
                        __rem;                                  \
                })

#elif BITS_PER_LONG == 32

static inline uint32_t __div64_32(uint64_t *n, uint32_t base)
{
	uint64_t rem = *n;
	uint64_t b = base;
	uint64_t res, d = 1;
	uint32_t high = rem >> 32;

	/* Reduce the thing a bit first */
	res = 0;
	if (high >= base) {
		high /= base;
		res = (uint64_t) high << 32;
		rem -= (uint64_t) (high*base) << 32;
	}

	while ((int64_t)b > 0 && b < rem) {
		b = b+b;
		d = d+d;
	}

	do {
		if (rem >= b) {
			rem -= b;
			res += d;
		}
		b >>= 1;
		d >>= 1;
	} while (d);

	*n = res;
	return rem;
}

/* The unnecessary pointer compare is there
 * to check for type safety (n must be 64bit)
 */
# define do_div(n,base) ({                                              \
                        uint32_t __base = (base);                       \
                        uint32_t __rem;                                 \
                        (void)(((typeof((n)) *)0) == ((uint64_t *)0));	\
                        if (likely(((n) >> 32) == 0)) {			\
                                __rem = (uint32_t)(n) % __base;		\
                                (n) = (uint32_t)(n) / __base;		\
                        } else 						\
                                __rem = __div64_32(&(n), __base);	\
                        __rem;						\
                })

#else /* BITS_PER_LONG == ?? */

# error do_div() does not yet support the C64

#endif /* BITS_PER_LONG */

/**
 * ns_to_timespec - Convert nanoseconds to timespec
 * @nsec:	the nanoseconds value to be converted
 *
 * Returns the timespec representation of the nsec parameter.
 */
struct timespec ns_to_timespec(const s64 nsec);

/**
 * ns_to_timeval - Convert nanoseconds to timeval
 * @nsec:	the nanoseconds value to be converted
 *
 * Returns the timeval representation of the nsec parameter.
 */
struct timeval ns_to_timeval(const s64 nsec);

#if !defined(HAVE_PPOLL)
#include <poll.h>
#include <sys/select.h>
#include <signal.h>

int ppoll(struct pollfd fds[], nfds_t nfds, struct timespec *timeout, sigset_t *set);

#endif /* HAVE_PPOLL */

#include <assert.h>
#ifndef BUG_ON
#define BUG() do {                                                      \
                fprintf(stderr, "BUG: failure at %s:%d/%s()!\n",        \
                        __FILE__, __LINE__, __func__);                  \
                exit(-1);                                               \
        } while (0)
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while(0)
#endif 
#else
#ifndef BUG_ON
#define BUG_ON(x) 
#endif 

#endif /* OS_USER */

const char *mac_ntop(const void *src, char *dst, size_t size);
const char *get_strtime(void);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37))
#define route_dst(rt) (&(rt)->u.dst)
#else
#define route_dst(rt) (&(rt)->dst)
#endif /* LINUX_VERSION_CODE */

#endif /* _PLATFORM_H */
