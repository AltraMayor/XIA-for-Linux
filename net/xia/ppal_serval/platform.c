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
#include <platform.h>
#include <debug.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/time.h>
#endif
#if defined(OS_USER)
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <serval/timer.h>
#endif

const char *mac_ntop(const void *src, char *dst, size_t size)
{	
	const char *mac = (const char *)src;

	if (size < 18)
		return NULL;

	sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0] & 0xff, 
                mac[1] & 0xff, 
                mac[2] & 0xff, 
                mac[3] & 0xff, 
                mac[4] & 0xff, 
                mac[5] & 0xff);

	return dst;
}

const char *get_strtime(void)
{
    static char buf[30];
    struct timeval now;
#if defined(OS_LINUX_KERNEL)
    do_gettimeofday(&now);
#endif
#if defined(OS_USER)
    gettimeofday(&now, NULL);
#endif

    snprintf(buf, 30, "%ld.%03ld", 
             (long)now.tv_sec, (long)(now.tv_usec / 1000));

    return buf;
}

#if defined(OS_LINUX_KERNEL)
#include <linux/inet.h>

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
        unsigned char *ip = (unsigned char *)src;

        if (size < 16 || af != AF_INET)
                return NULL;
        
        sprintf(dst, "%u.%u.%u.%u", 
                ip[0], ip[1], ip[2], ip[3]);
        
        return dst;
}
#endif

#if defined(OS_USER)

/* From http://groups.google.com/group/comp.lang.c/msg/52820a5d19679089 */
/***********************************************/
/* Locate the position of the highest bit set. */
/* A binary search is used.  The result is an  */
/* approximation of log2(n) [the integer part] */
/***********************************************/
int ilog2(unsigned long n)
{
        int i = (-1);
        /* Is there a bit on in the high word? */
        /* Else, all the high bits are already zero. */
        if (n & 0xffff0000) {
                i += 16;                /* Update our search position */
                n >>= 16;               /* Shift out lower (irrelevant) bits */
        }
        /* Is there a bit on in the high byte of the current word? */
        /* Else, all the high bits are already zero. */
        if (n & 0xff00) {
                i += 8;                 /* Update our search position */
                n >>= 8;                /* Shift out lower (irrelevant) bits */
        }
        /* Is there a bit on in the current nybble? */
        /* Else, all the high bits are already zero. */
        if (n & 0xf0) {
                i += 4;                 /* Update our search position */
                n >>= 4;                /* Shift out lower (irrelevant) bits */
        }
        /* Is there a bit on in the high 2 bits of the current nybble? */
        /* 0xc is 1100 in binary... */
        /* Else, all the high bits are already zero. */
        if (n & 0xc) {
                i += 2;                 /* Update our search position */
                n >>= 2;                /* Shift out lower (irrelevant) bits */
        }
        /* Is the 2nd bit on? [ 0x2 is 0010 in binary...] */
        /* Else, all the 2nd bit is already zero. */
        if (n & 0x2) {
                i++;                    /* Update our search position */
                n >>= 1;                /* Shift out lower (irrelevant) bit */
        }
        /* Is the lowest bit set? */
        if (n)
                i++;                    /* Update our search position */
        return i;
}
int memcpy_toiovec(struct iovec *iov, unsigned char *from, int len)
{
        while (len > 0) {
                if (iov->iov_len) {
                        int copy = min_t(unsigned int, iov->iov_len, len);

                        memcpy(iov->iov_base, from, copy);

                        from += copy;
                        len -= copy;
                        iov->iov_len -= copy;
                        iov->iov_base += copy;
                }
                iov++;
        }
        return 0;
}

int memcpy_fromiovec(unsigned char *to, struct iovec *iov, int len)
{
        while (len > 0) {
                if (iov->iov_len) {
                        int copy = min_t(unsigned int, len, iov->iov_len);
                        memcpy(to, iov->iov_base, copy);
                        len -= copy;
                        to += copy;
                        iov->iov_base += copy;
                        iov->iov_len -= copy;
                }
                iov++;
        }
        return 0;
}

int memcpy_fromiovecend(unsigned char *kdata, const struct iovec *iov,
			int offset, int len)
{
	/* Skip over the finished iovecs */
	while ((unsigned int)offset >= iov->iov_len) {
		offset -= iov->iov_len;
		iov++;
	}

	while (len > 0) {
		uint8_t *base = (uint8_t *)iov->iov_base + offset;
		int copy = min_t(unsigned int, len, iov->iov_len - offset);

		offset = 0;
		if (memcpy(kdata, base, copy))
			return -EFAULT;
		len -= copy;
		kdata += copy;
		iov++;
	}

	return 0;
}

#if BITS_PER_LONG == 64
/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div_s64_rem - signed 64bit divide with 32bit divisor with remainder
 */
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

/**
 * div64_s64 - signed 64bit divide with 64bit divisor
 */
static inline s64 div64_s64(s64 dividend, s64 divisor)
{
	return dividend / divisor;
}
#endif /* BITS_PER_LONG == 64 */

#if BITS_PER_LONG == 32

#ifndef div_u64_rem
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = do_div(dividend, divisor);
	return dividend;
}
#endif

#ifndef div_s64_rem
static s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
	u64 quotient;

	if (dividend < 0) {
		quotient = div_u64_rem(-dividend, abs(divisor), 
                                       (u32 *)remainder);
		*remainder = -*remainder;
		if (divisor > 0)
			quotient = -quotient;
	} else {
		quotient = div_u64_rem(dividend, abs(divisor), 
                                       (u32 *)remainder);
		if (divisor < 0)
			quotient = -quotient;
	}
	return quotient;
}
#endif

#endif /* BITS_PER_LONG == 32 */

/**
 * div_u64 - unsigned 64bit divide with 32bit divisor
 *
 * This is the most common 64bit divide and should be used if possible,
 * as many 32bit archs can optimize this variant better than a full 64bit
 * divide.
 */
#ifndef div_u64
static inline u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;
	return div_u64_rem(dividend, divisor, &remainder);
}
#endif

/**
 * ns_to_timespec - Convert nanoseconds to timespec
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timespec representation of the nsec parameter.
 */
struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}

/**
 * ns_to_timeval - Convert nanoseconds to timeval
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timeval representation of the nsec parameter.
 */
struct timeval ns_to_timeval(const s64 nsec)
{
	struct timespec ts = ns_to_timespec(nsec);
	struct timeval tv;

	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = (suseconds_t) ts.tv_nsec / 1000;

	return tv;
}

#if !defined(HAVE_PPOLL)
#include <poll.h>
#include <signal.h>

int ppoll(struct pollfd fds[], nfds_t nfds, struct timespec *timeout, 
          sigset_t *set)
{
        int to = 0;
        sigset_t oldset;
        int ret;

        if (!timeout) {
                to = -1;
        } else if (timeout->tv_sec == 0 && timeout->tv_nsec == 0)  {
                to = 0;
        } else {
                to = timeout->tv_sec * 1000 + (timeout->tv_nsec / 1000000);
        }

        if (set) {
                sigprocmask(SIG_SETMASK, set, &oldset);
                ret = poll(fds, nfds, to);
                sigprocmask(SIG_SETMASK, &oldset, NULL);
        } else {
                ret = poll(fds, nfds, to);
        }
        return ret;
}

#endif /* OS_ANDROID */

#endif /* OS_USER */
