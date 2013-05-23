/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Debug output support for Serval.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <debug.h>
#include <serval_sock.h>
#include <af_serval.h>
#if defined(OS_USER)
#include <pthread.h>
#endif

static const char *log_level_str[] = {
        [ 0 ] = "UNDEF",
        [LOG_LEVEL_CRIT] = "CRIT",
	[LOG_LEVEL_ERR] = "ERR",
        [LOG_LEVEL_WARN] = "WARN",
	[LOG_LEVEL_INF] = "INF",
	[LOG_LEVEL_DBG] = "DBG",
        [LOG_LEVEL_PKT] = "PKT"
};

#if defined(OS_LINUX_KERNEL)
extern int log_vprintk(const char *levelstr, const char *func, 
                       const char *fmt, va_list args);
#endif


const char *print_ssk(struct sock *sk, char *buf, size_t buflen)
{
        return serval_sock_print(sk, buf, buflen);
}

void logme(log_level_t level, const char *func, const char *format, ...)
{
	va_list ap;
        
        if ((unsigned int)level > net_serval.sysctl_debug) {
                return;
        }
        
#if defined(OS_LINUX_KERNEL)
        switch (level) {
        case LOG_LEVEL_ERR:
        case LOG_LEVEL_WARN:
        case LOG_LEVEL_CRIT:
                pr_alert("{%d}[%3s]%s: ", 
                         task_pid_nr(current), 
                         log_level_str[level], func);
                va_start(ap, format);
                vprintk(format, ap);
                va_end(ap);
        case LOG_LEVEL_DBG:
        case LOG_LEVEL_INF:
        case LOG_LEVEL_PKT:
                va_start(ap, format);
                log_vprintk(log_level_str[level], func, format, ap);
                va_end(ap);
                break;
        }
#endif
}
