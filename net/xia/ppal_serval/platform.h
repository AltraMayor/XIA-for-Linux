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

#include <stddef.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <net/sock.h>

#define OS_LINUX_KERNEL 1

const char *inet_ntop(int af, const void *src, char *dst, size_t size);
const char *mac_ntop(const void *src, char *dst, size_t size);

#define route_dst(rt) (&(rt)->dst)

#endif /* _PLATFORM_H */
