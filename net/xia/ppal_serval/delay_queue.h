/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Packet queue for DELAY rule functionality of the SAL.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#ifndef __SERVAL_DELAY_QUEUE_H__
#define __SERVAL_DELAY_QUEUE_H__

#include <ctrlmsg.h>

int delay_queue_set_verdict(unsigned int pkt_id, 
                            enum delay_verdict verdict,
                            int pid);
int delay_queue_skb(struct sk_buff *skb, struct service_id *srvid);
void delay_queue_purge_sock(struct sock *sk);

#endif /* __SERVAL_DELAY_QUEUE_H__ */
