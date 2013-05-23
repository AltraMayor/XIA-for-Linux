/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

#if defined(OS_LINUX_KERNEL)
#include <asm/checksum.h>
#else
#if defined(OS_LINUX)
#include <linux/types.h>
#endif
#include <serval/platform.h>
#include <errno.h>
#include <string.h>

#ifndef __WSUM__
#define __WSUM__
typedef __u32 __wsum;
#endif
#ifndef __SUM16__
#define __SUM16__
typedef __u16 __sum16;
#endif
#define __force

/* Taken from Linux kernel sources */

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
extern __wsum csum_partial(const void *buff, int len, __wsum sum);

/*
 * the same as csum_partial, but copies from src while it
 * checksums
 *
 * here even more important to align src and dst on a 32-bit (or even
 * better 64-bit) boundary
 */
extern __wsum csum_partial_copy(const void *src, void *dst, int len, __wsum sum);

/*
 * the same as csum_partial_copy, but copies from user space.
 *
 * here even more important to align src and dst on a 32-bit (or even
 * better 64-bit) boundary
 */
extern __wsum csum_partial_copy_from_user(const void *src, void *dst,
					int len, __wsum sum, int *csum_err);

#define csum_partial_copy_nocheck(src, dst, len, sum)	\
	csum_partial_copy((src), (dst), (len), (sum))

/*
 * This is a version of ip_compute_csum() optimized for IP headers,
 * which always checksum on 4 octet boundaries.
 */
extern __sum16 ip_fast_csum(const void *iph, unsigned int ihl);

/*
 * Fold a partial checksum
 */
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (__force u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__force __sum16)~sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
extern __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len,
		   unsigned short proto, __wsum sum);

static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, unsigned short len,
		  unsigned short proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

/*
 * this routine is used for miscellaneous IP-like checksums, mainly
 * in icmp.c
 */
extern __sum16 ip_compute_csum(const void *buff, int len);


static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	u32 res = (__force u32)csum;
	res += (__force u32)addend;
	return (__force __wsum)(res + (res < (__force u32)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static inline __wsum
csum_block_add(__wsum csum, __wsum csum2, int offset)
{
	u32 sum = (__force u32)csum2;
	if (offset&1)
		sum = ((sum&0xFF00FF)<<8)+((sum>>8)&0xFF00FF);
	return csum_add(csum, (__force __wsum)sum);
}

static inline __wsum
csum_block_sub(__wsum csum, __wsum csum2, int offset)
{
	u32 sum = (__force u32)csum2;
	if (offset&1)
		sum = ((sum&0xFF00FF)<<8)+((sum>>8)&0xFF00FF);
	return csum_sub(csum, (__force __wsum)sum);
}

static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}

static inline
__wsum csum_and_copy_from_user (const void *src, void *dst,
				int len, __wsum sum, int *err_ptr)
{
        if (1 /* access_ok(VERIFY_READ, src, len) */)
                return csum_partial_copy_from_user(src, dst, 
                                                   len, sum, err_ptr);
        
        if (len)
                *err_ptr = -EFAULT;
  
        return sum;
}


static __inline__ __wsum csum_and_copy_to_user
(const void *src, void *dst, int len, __wsum sum, int *err_ptr)
{
	sum = csum_partial(src, len, sum);
        
	if (1 /* access_ok(VERIFY_WRITE, dst, len) */) {
		if (memcpy(dst, src, len) == 0)
			return sum;
	}
	if (len)
		*err_ptr = -EFAULT;

	return (__force __wsum)-1; /* invalid checksum */
}

#endif /* __CHECKSUM_H_ */

#endif /* OS_LINUX_KERNEL */
