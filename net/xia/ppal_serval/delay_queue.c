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
#include <platform.h>
#include <list.h>
#include <lock.h>
#include <ctrlmsg.h>
#include <skbuff.h>
#include <debug.h>
#include <sock.h>
#if defined(OS_LINUX_KERNEL)
#include <linux/netlink.h>
#endif
#include "ctrl.h"
#include "delay_queue.h"
#include "serval_sal.h"

#define DELAY_QUEUE_MAX_DEFAULT 1024

static int peer_pid __read_mostly;
static unsigned int queue_id = 0;
static unsigned int queue_total = 0;
static unsigned int queue_dropped = 0;
static unsigned int queue_maxlen = DELAY_QUEUE_MAX_DEFAULT;
static DEFINE_SPINLOCK(queue_lock);
static struct list_head delay_queue = { &delay_queue, &delay_queue };

struct delay_entry {
        struct list_head lh;
        unsigned int id;
        struct sk_buff *skb;
        struct sock *sk;
};

static inline void __delay_queue_add(struct delay_entry *de)
{
        list_add_tail(&de->lh, &delay_queue);
        queue_total++;
}

static inline void __delay_queue_remove(struct delay_entry *de)
{
        list_del(&de->lh);
        queue_total--;
}

static inline struct delay_entry *__delay_queue_find(unsigned int id)
{
        struct delay_entry *entry;

        list_for_each_entry(entry, &delay_queue, lh) {
                if (id == entry->id)
                        return entry;
        }
        return NULL;
}

static inline void delay_entry_free(struct delay_entry *de)
{
        if (de->sk)
                sock_put(de->sk);
        kfree(de);
}

static inline void __delay_queue_purge_sock(struct sock *sk)
{
        struct delay_entry *entry, *tmp;
        
        list_for_each_entry_safe(entry, tmp, &delay_queue, lh) {                
                if (sk == NULL || (sk == entry->sk)) {
                        list_del_init(&entry->lh);
                        queue_total--;
                        kfree_skb(entry->skb);
                        delay_entry_free(entry);
                        queue_dropped++;
                }
        }
}

void delay_queue_purge_sock(struct sock *sk)
{
        spin_lock_bh(&queue_lock);
        __delay_queue_purge_sock(sk);
        spin_unlock_bh(&queue_lock);
}

static void __delay_queue_reset(void)
{
        __delay_queue_purge_sock(NULL);
        peer_pid = 0;
}

int delay_queue_skb(struct sk_buff *skb, struct service_id *srvid)
{
        struct delay_entry *de;
        struct ctrlmsg_delay cmd;
        int ret;

        de = kmalloc(sizeof(*de), GFP_ATOMIC);
        
        if (!de) {
                kfree_skb(skb);
                return -ENOMEM;
        }

        *de = (struct delay_entry) {
                .skb = skb,
                .id = queue_id++,
                .sk = skb->sk,
        };
        
        if (de->sk) 
                sock_hold(de->sk);

        spin_lock_bh(&queue_lock);

	if (queue_total >= queue_maxlen) {
		ret = -ENOSPC;
#if defined(OS_LINUX_KERNEL)
		if (net_ratelimit())
                        LOG_WARN("delay_queue: queue is full."
                                 " Queue total: %u Dropped: %u\n", 
                                 queue_total,
                                 queue_dropped);
#endif
		goto err_out_drop;
	}        

        memset(&cmd, 0, sizeof(cmd));
        cmd.cmh.type = CTRLMSG_TYPE_DELAY_NOTIFY;
        cmd.cmh.len = sizeof(cmd);
        cmd.pkt_id = de->id;
        memcpy(&cmd.service, srvid, sizeof(*srvid));
        
        ret = ctrl_sendmsg(&cmd.cmh, peer_pid, GFP_ATOMIC);
                           
        if (ret != 0) {
                LOG_DBG("No NETLINK_SERVAL listener, dropping packet\n");
                ret = -EHOSTUNREACH;
                goto err_out_drop;
        }
        __delay_queue_add(de);

        spin_unlock_bh(&queue_lock);
        
        return 0;

 err_out_drop:
        spin_unlock_bh(&queue_lock);
        kfree_skb(skb);
        delay_entry_free(de);
        queue_dropped++;
        return ret;
}

int delay_queue_set_verdict(unsigned int pkt_id, 
                            enum delay_verdict verdict,
                            int pid)
{
        struct delay_entry *entry;
        int ret = 0;

        spin_lock_bh(&queue_lock);
        
        if (peer_pid) {
                if (peer_pid != pid) {
                        LOG_ERR("Verdict from wrong peer!\n");
			spin_unlock_bh(&queue_lock);
			return -EBUSY;
		}
	} else {
		peer_pid = pid;
	}

        entry = __delay_queue_find(pkt_id);
        
        if (!entry) {
                spin_unlock_bh(&queue_lock);
                return 0;
        }

        list_del(&entry->lh);
        queue_total--;

        switch (verdict) {
        case DELAY_DROP:
                LOG_DBG("Verdict for pkt %u is DROP\n");
                kfree_skb(entry->skb);
                queue_dropped++;
                break;
        case DELAY_RELEASE:
                LOG_DBG("Verdict for pkt %u is RELEASE\n");
                /* FIXME: 
                   Here we need to be careful that the RELEASE does
                   not cause the skb to be DELAYED again, which could
                   cause a loop until the queue is full. This only
                   happens with unbehaved apps though. We should
                   figure out a way to ensure that a re-resolution
                   does not hit a DELAY rule more than once.
                */
                if (entry->sk) {
                        /* If the skb is owned by a socket, it means
                           it was generated locally and was not
                           received from the network */
                        if (sock_flag(entry->sk, SOCK_DEAD)) {
                                kfree_skb(entry->skb);
                                queue_dropped++;
                                LOG_DBG("Socket is DEAD, dropping pkt %u\n",
                                        pkt_id);
                        } else {
                                serval_sal_xmit_skb(entry->skb);
                                ret = 1;
                        }
                } else {
                        /* Just reinject this packet as if received
                           from the network */
                        serval_sal_reresolve(entry->skb);
                        ret = 1;
                }
                break;
        }

        spin_unlock_bh(&queue_lock);
        
        delay_entry_free(entry);

        return ret;
}

#if defined(OS_LINUX_KERNEL)
static int delay_queue_rcv_nl_event(struct notifier_block *this,
                                    unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;

	if (event == NETLINK_URELEASE && n->protocol == NETLINK_SERVAL) {
		spin_lock_bh(&queue_lock);
		if ((net_eq(n->net, &init_net)) && (n->portid == peer_pid))
                        __delay_queue_reset();
		spin_unlock_bh(&queue_lock);
	}
	return NOTIFY_DONE;
}

static struct notifier_block delay_queue_nl_notifier = {
	.notifier_call	= delay_queue_rcv_nl_event,
};

#endif /* OS_LINUX_KERNEL */

int delay_queue_init(void)
{
        peer_pid = 0;
#if defined(OS_LINUX_KERNEL)
	netlink_register_notifier(&delay_queue_nl_notifier);
#endif
        return 0;
}

void delay_queue_fini(void)
{
        __delay_queue_reset();
#if defined(OS_LINUX_KERNEL)
	netlink_unregister_notifier(&delay_queue_nl_notifier);
#endif
}
