/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Platform detection and compatibility 
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef _COMMON_PLATFORM_H_
#define _COMMON_PLATFORM_H_

/* Detect platform */
#if defined(__unix__)
#define OS_UNIX 1
#if !defined(__KERNEL__)
#define OS_USER 1
#endif
#endif

#if defined(__linux__)
#define OS_LINUX 1
#define OS_UNIX 1
#if defined(ANDROID)
#define OS_ANDROID 1
#endif
#if defined(__KERNEL__)
#define OS_KERNEL 1
#define OS_LINUX_KERNEL 1
#else
#define OS_USER 1
#endif
#endif /* OS_LINUX */

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE__)
#define OS_BSD 1
#define OS_UNIX 1
#define OS_USER 1
#endif

#if defined(__APPLE__)
#define OS_MACOSX 1
#define OS_UNIX 1
#define OS_USER 1
#endif

#if defined(OS_LINUX)
/* For passing credentials over UNIX domain sockets */
typedef struct ucred ucred_t;
#define ucred_uid uid
#define ucred_pid pid
#define ucred_gid gid
#if !defined(OS_ANDROID)
#define HAVE_LIBIO 1
#define HAVE_PPOLL 1
#define HAVE_PSELECT 1
#define HAVE_OFFSETOF 1
#endif
#include <stddef.h>
#endif

#if defined(OS_ANDROID)
#undef OS_KERNEL
#define HAVE_OFFSETOF 1
#undef HAVE_LIBIO
#undef HAVE_PPOLL
#undef HAVE_PSELECT
#endif

#if defined(OS_BSD)
#define EBADFD EBADF
/* For passing credentials over UNIX domain sockets */
#define SO_PASSCRED LOCAL_PEERCRED
#define SCM_CREDENTIALS SCM_CREDS
#if defined(OS_MACOSX)
typedef struct xucred ucred_t;
#define ucred_uid cr_uid
#define ucred_pid cr_uid
#else
#include <sys/socket.h>
typedef struct scmsgcred ucred_t;
#define ucred_uid cmcred_uid
#define ucred_pid cmcred_pid
#define ucred_gid cmcred_gid
#endif /* OS_MACOSX */
#endif /* OS_BSD */

#if defined(OS_USER)
#include <stdint.h>

#if defined(OS_LINUX)
#include <endian.h>
#elif defined(OS_MACOSX)
#include <machine/endian.h>
#define __BYTE_ORDER __DARWIN_BYTE_ORDER
#define __BIG_ENDIAN __DARWIN_BIG_ENDIAN
#define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#endif

#if HAVE_LIBIO
#include <libio.h>
#endif

#if defined(OS_ANDROID)
#define __WORDSIZE 32
#endif

#if __WORDSIZE == 64
#define BITS_PER_LONG 64
#elif __WORDSIZE == 32
#define BITS_PER_LONG 32
#else
#error "Could not detect word size of this machine!"
#endif

#ifndef U64__
#define U64__
typedef uint64_t u64;
#endif
#ifndef S64__
#define S64__
typedef int64_t s64;
#endif
#ifndef U32__
#define U32__
typedef uint32_t u32;
#endif
#ifndef OS_ANDROID
#ifndef __U32__
#define __U32__
typedef uint32_t __u32;
#endif
#endif /* OS_ANDROID */
#ifndef S32__
#define S32__
typedef int32_t s32;
#endif 
#ifndef OS_ANDROID
#ifndef __S32__
#define __S32__
typedef int32_t __s32;
#endif 
#endif /* OS_ANDROID */
#ifndef U16__
#define U16__
typedef uint16_t u16;
#endif
#ifndef OS_ANDROID 
#ifndef __U16__
#define __U16__
typedef uint16_t __u16;
#endif
#endif /* OS_ANDROID */
#ifndef S16__
#define S16__
typedef int16_t s16;
#endif
#ifndef OS_ANDROID
#ifndef __S16__
#define __S16__
typedef int16_t __s16;
#endif
#endif /* OS_ANDROID */
#ifndef U8__
#define U8__
typedef uint8_t u8;
#endif 
#ifndef OS_ANDROID
#ifndef __U8__
#define __U8__
typedef uint8_t __u8;
#endif
#endif /* OS_ANDROID */
#ifndef S8__
#define S8__
typedef int8_t s8;
#endif
#ifndef OS_ANDROID
#ifndef __S8__
#define __S8__
typedef int8_t __s8;
#endif
#endif /* OS_ANDROID */

/* Setup byte order defines according to the Linux kernel */
#if __BYTE_ORDER == __BIG_ENDIAN
#ifdef __LITTLE_ENDIAN
#undef __LITTLE_ENDIAN
#endif
#define __BIG_ENDIAN_BITFIELD
#undef  __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#ifdef __BIG_ENDIAN
#undef __BIG_ENDIAN
#endif
#define __LITTLE_ENDIAN_BITFIELD
#undef __BIG_ENDIAN_BITFIELD
#else
#error "Could not figure out the byte order of this platform!"
#endif

#if defined(OS_BSD)
#ifndef BE32__
#define BE32__
typedef uint32_t be32;
#endif 
#ifndef __BE32__
#define __BE32__
typedef uint32_t __be32;
#endif 
#ifndef __BE16__
#define __BE16__
typedef uint16_t __be16;
#endif 
#ifndef BE16__
#define BE16__
typedef uint16_t be16;
#endif 
#endif /* OS_BSD */


#define min_t(type, x, y) ({                        \
            type __min1 = (x);                      \
            type __min2 = (y);                      \
            __min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({                        \
            type __max1 = (x);                      \
            type __max2 = (y);                      \
            __max1 > __max2 ? __max1: __max2; })

/*
 * min()/max()/clamp() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x, y) ({                            \
            typeof(x) _min1 = (x);              \
            typeof(y) _min2 = (y);              \
            (void) (&_min1 == &_min2);          \
            _min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({                            \
            typeof(x) _max1 = (x);              \
            typeof(y) _max2 = (y);              \
            (void) (&_max1 == &_max2);          \
            _max1 > _max2 ? _max1 : _max2; })


#if !HAVE_OFFSETOF
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                          \
            const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
            (type *)( (char *)__mptr - offsetof(type,member) );})

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#endif /* OS_USER */

#endif /* _COMMON_PLATFORM_H_ */
