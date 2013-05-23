/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef __DEBUG_H_
#define __DEBUG_H_

#include <platform.h>

#if defined(OS_LINUX_KERNEL)
#include <linux/kernel.h>
#include <linux/sched.h>
#elif defined(OS_USER)
#include <stdio.h>
#include <stdarg.h>
#include <errno.h> 
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

struct sock;

/* Allows convenient wrapping of kernel-style error codes (negative
 * error codes) into userlevel ones. */
#define KERN_ERR(err) (-(err))
#define KERN_STRERROR(err) (strerror(KERN_ERR(err)))
#endif /* OS_LINUX_KERNEL */

typedef enum {
	LOG_LEVEL_CRIT = 1,
	LOG_LEVEL_ERR,
	LOG_LEVEL_WARN,
	LOG_LEVEL_INF,
	LOG_LEVEL_DBG,
        LOG_LEVEL_PKT /* For logging output that happens for every
                         incoming or outgoing packet */
} log_level_t;

void logme(log_level_t level, const char *func, const char *format, ...);

#if defined(ENABLE_DEBUG)

static inline const char *hexdump(const void *data, int datalen, 
                                  char *buf, int buflen)
{
        int i = 0, len = 0;
        const unsigned char *h = (const unsigned char *)data;
        
        while (i < datalen) {
                unsigned char c = (i + 1 < datalen) ? h[i+1] : 0;
                len += snprintf(buf + len, buflen - len, 
                                "%02x%02x ", h[i], c);
                i += 2;
        }
        return buf;
}

const char *print_ssk(struct sock *sk, char *buf, size_t buflen);
 
#define LOG_CRIT(fmt, ...) logme(LOG_LEVEL_CRIT, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) logme(LOG_LEVEL_ERR, __func__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) logme(LOG_LEVEL_WARN, __func__, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) logme(LOG_LEVEL_INF, __func__, fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...) logme(LOG_LEVEL_DBG, __func__, fmt, ##__VA_ARGS__)
#define LOG_PKT(fmt, ...) logme(LOG_LEVEL_PKT, __func__, fmt, ##__VA_ARGS__)
#define LOG_SSK(sk, fmt, ...) ({ char _buf[200]; logme(LOG_LEVEL_PKT, __func__, \
                                "%s "fmt, print_ssk(sk, _buf, 200), ##__VA_ARGS__); })

#else

#define LOG_CRIT(fmt, ...) logme(LOG_LEVEL_CRIT, __func__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) 
#define LOG_WARN(fmt, ...)
#define LOG_INF(fmt, ...)
#define LOG_DBG(fmt, ...)
#define LOG_PKT(fmt, ...)
#define LOG_SSK(fmt, ...)

#endif /* ENABLE_DEBUG */

#endif /* __DEBUG_H_ */
