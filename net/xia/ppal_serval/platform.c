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
#include <linux/time.h>
#include <linux/inet.h>

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

const char *inet_ntop(int af, const void *src, char *dst, size_t size)
{
        unsigned char *ip = (unsigned char *)src;

        if (size < 16 || af != AF_INET)
                return NULL;
        
        sprintf(dst, "%u.%u.%u.%u", 
                ip[0], ip[1], ip[2], ip[3]);
        
        return dst;
}
