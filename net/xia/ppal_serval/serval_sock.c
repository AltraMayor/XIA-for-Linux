/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Serval socket implementation. Contains all the Serval-specific state. 
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
#include <netdevice.h>
#include <netinet_serval.h>
#include <serval_sock.h>
#include <serval_tcp_sock.h>
#include <serval_sal.h>
#include <service.h>
#include <linux/ip.h>
#include <net/route.h>
#include "serval_ipv4.h"

atomic_t serval_nr_socks = ATOMIC_INIT(0);
static atomic_t serval_flow_id = ATOMIC_INIT(1);
static struct serval_table established_table;
static struct serval_table request_table;
static struct list_head sock_list = { &sock_list, &sock_list };
static DEFINE_RWLOCK(sock_list_lock);

/* The number of (prefix) bytes to hash on in the serviceID */
#define SERVICE_KEY_LEN (8)

static const char *sock_state_str[] = {
        [ SAL_INIT ]      = "INIT",
        [ SAL_CONNECTED ] = "CONNECTED",
        [ SAL_REQUEST ]   = "REQUEST",
        [ SAL_RESPOND ]   = "RESPOND",
        [ SAL_FINWAIT1 ]  = "FINWAIT1",
        [ SAL_FINWAIT2 ]  = "FINWAIT2",
        [ SAL_TIMEWAIT ]  = "TIMEWAIT",
        [ SAL_CLOSED ]    = "CLOSED",
        [ SAL_CLOSEWAIT ] = "CLOSEWAIT",
        [ SAL_LASTACK ]   = "LASTACK",
        [ SAL_LISTEN ]    = "LISTEN",
        [ SAL_CLOSING ]   = "CLOSING"
};

static const char *sock_sal_state_str[] = {
        [ SAL_RSYN_INITIAL ]   = "SAL_RSYN_INITIAL",
        [ SAL_RSYN_SENT ]      = "SAL_RSYN_SENT",
        [ SAL_RSYN_RECV ]      = "SAL_RSYN_RECV",
        [ SAL_RSYN_SENT_RECV ] = "SAL_RSYN_SENT_RECV",
};

static void serval_sock_destruct(struct sock *sk);

int serval_table_init(struct serval_table *table,
                      unsigned int (*hashfn)(struct serval_table *tbl, 
                                             struct sock *sk),
                      struct serval_hslot *(*hashslot)(struct serval_table *tbl,
                                                       struct net *net,
                                                       void *key,
                                                       size_t keylen),
                      const char *name)
{
	unsigned int i;

	table->hash = kmalloc(SERVAL_HTABLE_SIZE_MIN * 
                              sizeof(struct serval_hslot), GFP_KERNEL);

	if (!table->hash) {
		/* panic(name); */
		return -1;
	}

	table->mask = SERVAL_HTABLE_SIZE_MIN - 1;
        table->hashfn = hashfn;
        table->hashslot = hashslot;

	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&table->hash[i].head);
		table->hash[i].count = 0;
		spin_lock_init(&table->hash[i].lock);
	}

	return 0;
}

void serval_table_fini(struct serval_table *table)
{
        unsigned int i;

        for (i = 0; i <= table->mask; i++) {
                spin_lock_bh(&table->hash[i].lock);
                        
                while (!hlist_empty(&table->hash[i].head)) {
                        struct sock *sk;

                        sk = hlist_entry(table->hash[i].head.first, 
                                         struct sock, sk_node);
                        LOG_SSK(sk, "unhashing socket %p\n", sk);
                        hlist_del_init(&sk->sk_node);
                        table->hash[i].count--;
                        serval_sock_done(sk);
                }
                spin_unlock_bh(&table->hash[i].lock);           
	}

        kfree(table->hash);
}

void serval_sock_migrate_iface(int old_dev, int new_dev)
{
        struct sock *sk = NULL;
        int i, n = 0;

        for (i = 0; i < SERVAL_HTABLE_SIZE_MIN; i++) {
                struct serval_hslot *slot;
                
                slot = &established_table.hash[i];
                
                local_bh_disable();
                spin_lock(&slot->lock);
                                
                hlist_for_each_entry(sk, &slot->head, sk_node) {
                        int should_migrate = 0;

                        if (old_dev > 0 && new_dev > 0) {
                                if (old_dev == new_dev) {
                                        /* An existing interface changed its address,
                                         * i.e., physical mobility. */
                                        should_migrate = 1;
                                } else {
                                        /* We were told which
                                         * interface to migrate, but
                                         * we need to check that this
                                         * sock matches. */
                                        should_migrate = sk->sk_bound_dev_if == old_dev;
                                }
                        } else if (old_dev <= 0) {
                                /* A new interface came up, migrate all flows
                                 * with a DOWN interface to this new
                                 * interface. */
                                struct net_device *i = dev_get_by_index(sock_net(sk), 
                                                                        sk->sk_bound_dev_if);
                                
                                if (i) {
                                        /* If this interface is down, then
                                         * migrate its flows. */
                                        if (!(i->flags & IFF_UP))
                                                should_migrate = 1;
                                        dev_put(i);
                                }
                        } else if (new_dev <= 0 && old_dev == sk->sk_bound_dev_if) {
                                /* An interface went down, and we
                                 * need to figure out a new target
                                 * dev. */
#if defined(OS_LINUX_KERNEL)
                                struct rtable *rt;
                                
                                rt = serval_ip_route_output(sock_net(sk),
                                                            inet_sk(sk)->inet_daddr,
                                                            0, 0, 0);
                                
                                if (rt) {
                                        should_migrate = 1;
                                        new_dev = rt->rt_iif;
                                        LOG_SSK(sk, "Found new output dev %d\n", new_dev);
                                        ip_rt_put(rt);
                                } else {
                                        LOG_SSK(sk, "socket not routable\n");
                                } 
#endif /* OS_LINUX_KERNEL */
                        }
                        
                        if (should_migrate) {
#if defined(ENABLE_DEBUG)
                                struct net_device *dev1 = dev_get_by_index(sock_net(sk), 
                                                                           old_dev);
                                struct net_device *dev2 = dev_get_by_index(sock_net(sk), 
                                                                           new_dev);
                                if (dev1) {
                                        if (dev2) {
                                                LOG_SSK(sk, "migrating from dev %s to %s\n", 
                                                        dev1, dev2);
                                                
                                                dev_put(dev2);
                                        }
                                        dev_put(dev1);
                                }
#endif
                                bh_lock_sock(sk);
                                serval_sock_set_mig_dev(sk, new_dev);
                                serval_sal_migrate(sk);
                                bh_unlock_sock(sk);
                                n++;
                        }                       
                }
                spin_unlock(&slot->lock);
                local_bh_enable();
        }

        LOG_DBG("Migrated %d flows\n", n);
}

/*
  This function is called from BH context.
*/
void serval_sock_freeze_flows(struct net_device *dev)
{
        int i;

        for (i = 0; i < SERVAL_HTABLE_SIZE_MIN; i++) {
                struct serval_hslot *slot;
                struct sock *sk;                
                
                slot = &established_table.hash[i];
                
                spin_lock_bh(&slot->lock);
                                
                hlist_for_each_entry(sk, &slot->head, sk_node) {          
                        struct serval_sock *ssk = serval_sk(sk);                       
                        
                        if (sk->sk_bound_dev_if > 0 && 
                            sk->sk_bound_dev_if == dev->ifindex) {
                                if (ssk->af_ops->freeze_flow) {
                                        bh_lock_sock(sk);
                                        ssk->af_ops->freeze_flow(sk);
                                        bh_unlock_sock(sk);
                                }
                        }
                }
                spin_unlock_bh(&slot->lock);
        }
}

void serval_sock_migrate_flow(struct flow_id *old_flow, int new_dev)
{
        struct sock *sk = serval_sock_lookup_flow(old_flow);

        if (sk) {
                LOG_SSK(sk, "Found sock, migrating...\n");
                lock_sock(sk);
                serval_sock_set_mig_dev(sk, new_dev);
                serval_sal_migrate(sk);
                release_sock(sk);
                sock_put(sk);
        }
}

/* For now this looks pretty much like migrating a flow, but I suspect it'll
 * be a little more involved once we support multiple flows per service.
 */
void serval_sock_migrate_service(struct service_id *old_s, int new_dev)
{
        /* FIXME: Set protocol type of socket */
        struct sock *sk = serval_sock_lookup_service(old_s, IPPROTO_TCP);

        if (sk) {
                lock_sock(sk);
                serval_sock_set_mig_dev(sk, new_dev);
                serval_sal_migrate(sk);
                release_sock(sk);
                sock_put(sk);
        }
}

static unsigned long get_socket_inode(struct socket *socket)
{
        if (socket) {
                struct address_space *faddr;
                struct inode *inode;
                if (!socket->file) {
                        goto out;
                }

                faddr = socket->file->f_mapping;
                if (!faddr) {
                        goto out;
                }
        
                inode = faddr->host;
                if (inode) {
                        return inode->i_ino;
                }
        }
out:
        return 0;
}

struct flow_info *serval_sock_stats_flow(struct flow_id *flow, 
                                         struct ctrlmsg_stats_response *resp,
                                         int idx)
{
        struct sock *sk = serval_sock_lookup_flow(flow);
        struct flow_info *ret = NULL;

        if (sk) {
                int info_size = sizeof(struct flow_id) + sizeof(uint8_t) + 
                                sizeof(unsigned long) + sizeof(uint16_t);
                struct socket *socket = sk->sk_socket;
                if (sk->sk_protocol == IPPROTO_TCP) {
                        struct serval_tcp_sock *tsk = 
                                (struct serval_tcp_sock *) sk;
                        struct stats_proto_tcp *st = NULL;
                        info_size += sizeof(struct stats_proto_tcp);
                        ret = kmalloc(info_size, GFP_KERNEL);
                        memset(ret, 0, info_size);
                        ret->len = info_size;

                        st = (struct stats_proto_tcp *)&ret->stats;
                        st->retrans = tsk->total_retrans;
                        st->lost = tsk->lost_out;
                        st->srtt = tsk->srtt;
                        st->rttvar = tsk->mdev;
                        st->mss = tsk->mss_cache;
                        st->snd_ssthresh = tsk->snd_ssthresh;
                        st->snd_cwnd = tsk->snd_cwnd;
                        st->snd_wnd = tsk->snd_wnd;
                        st->snd_una = tsk->snd_una;
                        st->snd_nxt = tsk->snd_nxt;
                        st->rcv_wnd = tsk->rcv_wnd;
                        st->rcv_nxt = tsk->rcv_nxt;      
                } else {
                        info_size += sizeof(struct stats_proto_base);
                        ret = kmalloc(info_size, GFP_KERNEL);
                        memset(ret, 0, info_size);
                        ret->len = info_size;
                }
                ret->proto = sk->sk_protocol;
                ret->inode = get_socket_inode(socket);
                memcpy(&ret->flow, flow, sizeof(struct flow_id));
                ret->pkts_sent = serval_sk(sk)->tot_pkts_sent;
                ret->pkts_recv = serval_sk(sk)->tot_pkts_recv;
                ret->bytes_sent = serval_sk(sk)->tot_bytes_sent;
                ret->bytes_recv = serval_sk(sk)->tot_bytes_recv;
                sock_put(sk);
                LOG_DBG("Flow %s, proto %d\n", flow_id_to_str(flow), ret->proto);
        }
        return ret;
}

static struct sock *serval_sock_lookup(struct serval_table *table,
                                       struct net *net, void *key, 
                                       size_t keylen)
{
        struct serval_hslot *slot;
        struct sock *sk = NULL;

        if (!key)
                return NULL;

        slot = table->hashslot(table, net, key, keylen);

        if (!slot)
                return NULL;

        spin_lock_bh(&slot->lock);
        
        hlist_for_each_entry(sk, &slot->head, sk_node) {
                struct serval_sock *ssk = serval_sk(sk);
                if (memcmp(key, ssk->hash_key, keylen) == 0) {
                        sock_hold(sk);
                        goto out;
                }
        }
        sk = NULL;
out:
        spin_unlock_bh(&slot->lock);
        
        return sk;
}

struct sock *serval_sock_lookup_flow(struct flow_id *flowid)
{
        return serval_sock_lookup(&established_table, &init_net, 
                                  flowid, sizeof(*flowid));
}

struct sock *serval_sock_lookup_service(struct service_id *srvid, int protocol)
{
        return service_find_sock(srvid, SERVICE_ID_MAX_PREFIX_BITS, protocol);
}

static inline unsigned int serval_sock_ehash(struct serval_table *table,
                                             struct sock *sk)
{
        return serval_hashfn(sock_net(sk), 
                             serval_sk(sk)->hash_key,
                             serval_sk(sk)->hash_key_len,
                             table->mask);
}

static void __serval_table_hash(struct serval_table *table, struct sock *sk)
{
        struct serval_hslot *slot;

        sk->sk_hash = table->hashfn(table, sk);

        slot = &table->hash[sk->sk_hash];
        
        /* Bottom halfs already disabled here */
        spin_lock(&slot->lock);
        slot->count++;
        hlist_add_head(&sk->sk_node, &slot->head);
#if defined(OS_LINUX_KERNEL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
#else
        sock_prot_inc_use(sk->sk_prot);
#endif
#endif
        spin_unlock(&slot->lock);     
}

static void __serval_sock_hash(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
 
        if (!hlist_unhashed(&sk->sk_node)) {
                LOG_ERR("socket %p already hashed\n", sk);
        }
        
        if (sk->sk_state == SAL_REQUEST ||
            sk->sk_state == SAL_RESPOND) {
                LOG_SSK(sk, "hashing socket %p based on socket id %s\n",
                        sk, flow_id_to_str(&ssk->local_flowid));
                ssk->hash_key = &ssk->local_flowid;
                ssk->hash_key_len = sizeof(ssk->local_flowid);

                __serval_table_hash(&established_table, sk);
        }
}

void serval_sock_hash(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        
        /* Do not hash if closed or already hashed */
        if (sk->sk_state == SAL_CLOSED ||
            ssk->hash_key_len > 0)
                return;

        if (sk->sk_state == SAL_REQUEST ||
            sk->sk_state == SAL_RESPOND) {
		local_bh_disable();
		__serval_sock_hash(sk);
                serval_sock_set_flag(ssk, SSK_FLAG_HASHED);
		local_bh_enable();
        } else {
                int err = 0;
                
                LOG_SSK(sk, "adding socket %p based on service id %s\n",
                        sk, service_id_to_str(&ssk->local_srvid));

                ssk->hash_key = &ssk->local_srvid;
                ssk->hash_key_len = ssk->srvid_prefix_bits == 0 ? 
                        SERVICE_ID_MAX_PREFIX_BITS : 
                        ssk->srvid_prefix_bits;

                err = service_add(ssk->hash_key, ssk->hash_key_len, 
                                  SERVICE_RULE_DEMUX, ssk->srvid_flags, 
                                  LOCAL_SERVICE_DEFAULT_PRIORITY, 
                                  LOCAL_SERVICE_DEFAULT_WEIGHT,
                                  NULL, 0, make_target(sk), GFP_ATOMIC);
                if (err < 0) {
#if defined(OS_LINUX_KERNEL)
                        LOG_ERR("could not add service for listening demux\n");
#else
                        LOG_ERR("could not add service for listening demux: %s\n", strerror(-err));
#endif
                } else {
                        
#if defined(OS_LINUX_KERNEL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                        sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
#else
                        sock_prot_inc_use(sk->sk_prot);
#endif
#endif
                        serval_sock_set_flag(ssk, SSK_FLAG_HASHED);
                }
	}
}

void serval_sock_unhash(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        struct net *net = sock_net(sk);
        spinlock_t *lock;

        if (ssk->hash_key_len == 0)
                return;
                
        if (sk->sk_state == SAL_LISTEN ||
            sk->sk_state == SAL_INIT) {
                LOG_SSK(sk, "removing socket %p from service table\n", sk);

                service_del_target(&ssk->local_srvid,
                                   ssk->srvid_prefix_bits == 0 ?
                                   SERVICE_ID_MAX_PREFIX_BITS :
                                   ssk->srvid_prefix_bits, 
                                   SERVICE_RULE_DEMUX,
                                   NULL, 0, NULL);
#if defined(OS_LINUX_KERNEL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
#else
                sock_prot_dec_use(sk->sk_prot);
#endif
#endif
                serval_sock_reset_flag(ssk, SSK_FLAG_HASHED);
                ssk->hash_key_len = 0;
                return;
        } 

        LOG_SSK(sk, "unhashing socket %p\n", sk);

        lock = &established_table.hashslot(&established_table,
                                           net, &ssk->local_flowid, 
                                           ssk->hash_key_len)->lock;       

        if (!hlist_unhashed(&sk->sk_node)) {
                spin_lock_bh(lock);
                hlist_del_init(&sk->sk_node);
#if defined(OS_LINUX_KERNEL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
#else
                sock_prot_dec_use(sk->sk_prot);
#endif
#endif
                serval_sock_reset_flag(ssk, SSK_FLAG_HASHED);
                ssk->hash_key_len = 0;        
                spin_unlock_bh(lock);
        }
}

int serval_sock_tables_init(void)
{
        int ret;

        ret = serval_table_init(&request_table,
                                serval_sock_ehash, 
                                serval_hashslot,
                                "REQUEST");

        if (ret < 0)
                goto fail_table;
        
        ret = serval_table_init(&established_table, 
                                serval_sock_ehash,
                                serval_hashslot,
                                "ESTABLISHED");

fail_table:
        return ret;
}

void serval_sock_tables_fini(void)
{
        serval_table_fini(&request_table);
        serval_table_fini(&established_table);
        if (sock_state_str[0]) {} /* Avoid compiler warning when
                                   * compiling with debug off */

}

int __serval_assign_flowid(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
       
        /* 
           TODO: 
           - Check for ID wraparound and conflicts 
           - Make sure code does not assume flowid is a short
        */
        return serval_sock_get_flowid(&ssk->local_flowid);
}

int serval_sock_get_flowid(struct flow_id *sid)
{
        sid->s_id32 = htonl(atomic_inc_return(&serval_flow_id));

        return 0;
}

struct sock *serval_sk_alloc(struct net *net, struct socket *sock, 
                             gfp_t priority, int protocol, 
                             struct proto *prot)
{
        struct sock *sk;

        sk = sk_alloc(net, PF_SERVAL, priority, prot);

	if (!sk)
		return NULL;

	sock_init_data(sock, sk);
        sk->sk_family = PF_SERVAL;
	sk->sk_protocol	= protocol;
	sk->sk_destruct	= serval_sock_destruct;
        sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

        /* Only assign socket id here in case we have a user
         * socket. If socket is NULL, then it means this socket is a
         * child socket from a LISTENing socket, and it will be
         * assigned the socket id from the request sock */
        if (sock && __serval_assign_flowid(sk) < 0) {
                LOG_SSK(sk, "could not assign sock id\n");
                sock_put(sk);
                return NULL;
        }

        atomic_inc(&serval_nr_socks);
                
        LOG_SSK(sk, "SERVAL socket %p created, %d are alive.\n", 
                sk, atomic_read(&serval_nr_socks));

        return sk;
}

void serval_sock_init(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        sk->sk_state = 0;
        ssk->sal_state = SAL_RSYN_INITIAL;
        ssk->udp_encap_sport = 0;
        ssk->udp_encap_dport = 0;
        INIT_LIST_HEAD(&ssk->sock_node);
        INIT_LIST_HEAD(&ssk->accept_queue);
        INIT_LIST_HEAD(&ssk->syn_queue);
        setup_timer(&ssk->retransmit_timer, 
                    serval_sal_rexmit_timeout,
                    (unsigned long)sk);
        setup_timer(&ssk->tw_timer, 
                    serval_sal_timewait_timeout,
                    (unsigned long)sk);
	setup_timer(&sk->sk_timer, 
                    serval_sal_keepalive_timeout, 
                    (unsigned long)sk);

        serval_sal_init_ctrl_queue(sk);

#if defined(OS_LINUX_KERNEL)
        get_random_bytes(ssk->local_nonce, SAL_NONCE_SIZE);
        get_random_bytes(&ssk->snd_seq.iss, sizeof(ssk->snd_seq.iss));
#else
        {
                unsigned int i;
                unsigned char *seqno = (unsigned char *)&ssk->snd_seq.iss;
                for (i = 0; i < SAL_NONCE_SIZE; i++) {
                        ssk->local_nonce[i] = random() & 0xff;
                }
                for (i = 0; i < sizeof(ssk->snd_seq.iss); i++) {
                        seqno[i] = random() & 0xff;
                }
        }       
#endif
        ssk->hash_key = NULL;
        ssk->hash_key_len = 0;
        ssk->rcv_seq.nxt = 0;        
        ssk->snd_seq.una = 0;
        ssk->snd_seq.nxt = 0;
        /* Default to stop-and-wait behavior (wnd = 1) */
        ssk->rcv_seq.wnd = 1;
        ssk->snd_seq.wnd = 1;
        ssk->retransmits = 0;
        ssk->backoff = 0;
        ssk->srtt = 0;
        ssk->mdev = ssk->mdev_max = ssk->rttvar = SAL_TIMEOUT_INIT;
        ssk->rto = SAL_TIMEOUT_INIT;

        write_lock_bh(&sock_list_lock);
        list_add_tail(&ssk->sock_node, &sock_list);
        write_unlock_bh(&sock_list_lock);
}

void serval_sock_destroy(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);

        LOG_SSK(sk, "Destroying Serval sock %p\n", sk);
        
	WARN_ON(sk->sk_state != SAL_CLOSED);

	/* It cannot be in hash table! */
	/* WARN_ON(!sk_unhashed(sk)); */

	if (!sock_flag(sk, SOCK_DEAD)) {
		LOG_WARN("Attempt to release alive inet socket %p\n", sk);
		return;
	}

        /* Stop timers */
        LOG_SSK(sk, "Stopping timers\n");
        sk_stop_timer(sk, &ssk->retransmit_timer);
        sk_stop_timer(sk, &ssk->tw_timer);
        
        /* Clean control queue */
        serval_sal_ctrl_queue_purge(sk);

	if (sk->sk_prot->destroy)
		sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

        LOG_SSK(sk, "SERVAL sock %p refcnt=%d tot_bytes_sent=%lu\n",
                sk, atomic_read(&sk->sk_refcnt) - 1, 
                serval_sk(sk)->tot_bytes_sent);
        
        LOG_SSK(sk, "sock rmem=%u wmem=%u omem=%u\n",
                atomic_read(&sk->sk_rmem_alloc),
                atomic_read(&sk->sk_wmem_alloc),
                atomic_read(&sk->sk_omem_alloc));

        if (ssk->old_sk) {
                sock_put(ssk->old_sk);
                sk_common_release(ssk->old_sk);
        }

	sock_put(sk);
}

static void serval_sock_clear_xmit_timers(struct sock *sk)
{
        struct serval_sock *ssk = serval_sk(sk);
        sk_stop_timer(sk, &ssk->retransmit_timer);
	sk_stop_timer(sk, &sk->sk_timer);   
}

void serval_sock_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}

void serval_sock_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

void serval_sock_done(struct sock *sk)
{
	serval_sock_set_state(sk, SAL_CLOSED);
	serval_sock_clear_xmit_timers(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

        /* If there is still a user around, notify it. Otherwise,
         * destroy the socket now. */
	if (!sock_flag(sk, SOCK_DEAD)) 
                sk->sk_state_change(sk); 
        else
                serval_sock_destroy(sk); 
}

/* Destructor, called when refcount hits zero */
void serval_sock_destruct(struct sock *sk)
{
        /* Purge queues */
        __skb_queue_purge(&sk->sk_receive_queue);
        __skb_queue_purge(&sk->sk_error_queue);

        /* Clean control queue */
        serval_sal_ctrl_queue_purge(sk);

	if (sk->sk_type == SOCK_STREAM && 
            (sk->sk_state != SAL_CLOSED && 
             sk->sk_state != 0)) {
                /*
                  Note: in user mode, a respond sock created as a
                  result of accept() will replace an existing socket,
                  causing it to be destroyed.

                  See userlevel/client.c:client_handle_accept2_req_msg().
                 */
                
		LOG_ERR("Bad state %s %p\n",
                        serval_sock_state_str(sk), sk);
		return;
	}

	if (!sock_flag(sk, SOCK_DEAD)) {
		LOG_WARN("Attempt to release alive serval socket: %p\n", sk);
		return;
	}

	if (atomic_read(&sk->sk_rmem_alloc)) {
                LOG_WARN("sk_rmem_alloc is not zero\n");
        }

	if (atomic_read(&sk->sk_wmem_alloc)) {
                LOG_WARN("sk_wmem_alloc is not zero\n");
        }

	atomic_dec(&serval_nr_socks);

        write_lock_bh(&sock_list_lock);
        list_del(&serval_sk(sk)->sock_node);
        write_unlock_bh(&sock_list_lock);

	LOG_SSK(sk, "SERVAL socket %p destroyed, %d are still alive.\n", 
                sk, atomic_read(&serval_nr_socks));
}

const char *serval_sock_print_state(struct sock *sk, char *buf, size_t buflen)
{
        struct serval_sock *ssk = serval_sk(sk);

        snprintf(buf, buflen, "%s snd_seq[una=%u nxt=%u wnd=%u iss=%u] "
                 "rcv_seq[nxt=%u wnd=%u iss=%u]",
                 serval_sock_sal_state_str(sk), 
                 ssk->snd_seq.una, 
                 ssk->snd_seq.nxt, 
                 ssk->snd_seq.wnd, 
                 ssk->snd_seq.iss,
                 ssk->rcv_seq.nxt,
                 ssk->rcv_seq.wnd,
                 ssk->rcv_seq.iss);

        return buf;
}

const char *serval_sock_print(struct sock *sk, char *buf, size_t buflen)
{
        struct serval_sock *ssk = serval_sk(sk);

        snprintf(buf, buflen, "[%s:%s]",
                 flow_id_to_str(&ssk->local_flowid),
                 flow_id_to_str(&ssk->peer_flowid));

        return buf;
}

const char *serval_sock_state_str(struct sock *sk)
{
        if (sk->sk_state >= __SAL_MAX_STATE) {
                LOG_ERR("invalid state\n");
                return sock_state_str[0];
        }
        return sock_state_str[sk->sk_state];
}

const char *serval_state_str(unsigned int state)
{
        if (state >= __SAL_MAX_STATE) {
                LOG_ERR("invalid state\n");
                return sock_state_str[0];
        }
        return sock_state_str[state];
}

int serval_sock_set_state(struct sock *sk, unsigned int new_state)

{ 
        if (new_state == __SAL_MIN_STATE ||
            new_state >= __SAL_MAX_STATE) {
                LOG_ERR("invalid state\n");
                return -1;
        }
        
        LOG_SSK(sk, "%s -> %s\n",
                sock_state_str[sk->sk_state],
                sock_state_str[new_state]);
        
        switch (new_state) {
        case SAL_CLOSED:
                sk->sk_prot->unhash(sk);
                break;
        default:
                break;
        }

        sk->sk_state = new_state;

        return new_state;
}

const char *serval_sock_sal_state_str(struct sock *sk)
{
        if (serval_sk(sk)->sal_state >= __SAL_RSYN_MAX_STATE) {
                LOG_ERR("invalid state %u\n",
                        serval_sk(sk)->sal_state);
                return sock_sal_state_str[0];
        }
        return sock_sal_state_str[serval_sk(sk)->sal_state];
}

const char *serval_sal_state_str(unsigned int state)
{
        if (state >= __SAL_RSYN_MAX_STATE) {
                LOG_ERR("invalid state %u\n", state);
                return sock_sal_state_str[0];
        }
        return sock_sal_state_str[state];
}

int serval_sock_set_sal_state(struct sock *sk, unsigned int new_state)
{ 
        if (new_state >= __SAL_RSYN_MAX_STATE) {
                LOG_ERR("invalid state %u\n", new_state);
                return -1;
        }
        
        LOG_SSK(sk, "SAL %s -> %s\n",
                sock_sal_state_str[serval_sk(sk)->sal_state],
                sock_sal_state_str[new_state]);
        
        serval_sk(sk)->sal_state = new_state;

        return new_state;
}

/* 
   These functions are equivalent to the sock_wfree() and sock_rfree()
   of sock.c. However, these can be used as destructors for an skb to
   free up associated sock state and bindings, specific to Serval and
   control packets, when an skb is free'd.

   These will be pointed to by skb->destructor and set by
   skb_serval_set_owner_w() and skb_serval_set_owner_r().
 */
void serval_sock_wfree(struct sk_buff *skb)
{
        sock_put(skb->sk);
}

void serval_sock_rfree(struct sk_buff *skb)
{
}

/* 
   This function reroutes a socket. 
*/
int serval_sock_rebuild_header(struct sock *sk)
{
	int err = 0;
#if defined(OS_LINUX_KERNEL)
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_check(sk, 0);
        struct flowi fl;

	/* Route is OK, nothing to do. */
	if (rt)
		return 0;

        serval_flow_init_output(&fl, sk->sk_bound_dev_if, 
                                sk->sk_mark, RT_CONN_FLAGS(sk), 0,
                                sk->sk_protocol,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28))
                                inet_sk_flowi_flags(sk),
#else
                                0,
#endif
                                inet->inet_daddr,
                                inet->inet_saddr,
                                0, 0);
#if defined(ENABLE_DEBUG)
        {
                char rmtstr[18], locstr[18];
                LOG_SSK(sk, "rmt_addr=%s loc_addr=%s sk_protocol=%u\n",
                        inet_ntop(AF_INET, &inet->inet_daddr, rmtstr, 18),
                        inet_ntop(AF_INET, &inet->inet_saddr, locstr, 18),
                        sk->sk_protocol);
        }
#endif
	serval_security_sk_classify_flow(sk, &fl);

        rt = serval_ip_route_output_flow(sock_net(sk), &fl, sk, 0);

	if (rt) {
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
		sk_setup_caps(sk, &rt->dst);
#else
                sk_setup_caps(sk, &rt->u.dst);
#endif
        } else {
		/* Routing failed... */
                err = -EHOSTUNREACH;
		sk->sk_route_caps = 0;
                LOG_ERR("Routing failed for socket %p\n", sk);
	}
#endif /* OS_LINUX_KERNEL */
	return err;
}

void flow_table_read_lock(void)
{
        read_lock_bh(&sock_list_lock);
}

void flow_table_read_unlock(void)
{
        read_unlock_bh(&sock_list_lock);
}

void sock_list_iterator_init(struct sock_list_iterator *iter)
{
        read_lock_bh(&sock_list_lock);
        iter->head = &sock_list;
        iter->curr = iter->head;
        iter->sk = NULL;
}

void sock_list_iterator_destroy(struct sock_list_iterator *iter)
{
        read_unlock_bh(&sock_list_lock);
}

struct sock *sock_list_iterator_next(struct sock_list_iterator *iter)
{
        iter->curr = iter->curr->next;
        
        if (iter->curr == iter->head)
                iter->sk = NULL;
        else
                iter->sk = (struct sock *)list_entry(iter->curr, 
                                                     struct serval_sock, 
                                                     sock_node);
        return iter->sk;
}

int serval_sock_flow_print_header(char *buf, size_t buflen)
{
        return snprintf(buf, buflen, 
                        "%-10s %-10s %-17s %-17s %-10s %s\n",
                        "srcFlowID", "dstFlowID", 
                        "srcIP", "dstIP", "state", "dev");
}

int serval_sock_flow_print(struct sock *sk, char *buf, size_t buflen)
{
        struct serval_sock *ssk = serval_sk(sk);
        char src[18], dst[18];
        int len;
        struct net_device *dev = dev_get_by_index(sock_net(sk), 
                                                  sk->sk_bound_dev_if);
        
        len = snprintf(buf, buflen, 
                       "%-10s %-10s %-17s %-17s %-10s %s\n",
                       flow_id_to_str(&ssk->local_flowid), 
                       flow_id_to_str(&ssk->peer_flowid),
                       inet_ntop(AF_INET, &inet_sk(sk)->inet_saddr,
                                 src, 18),
                       inet_ntop(AF_INET, &inet_sk(sk)->inet_daddr,
                                 dst, 18),
                       serval_sock_state_str(sk),
                       dev ? dev->name : "unbound");
        
        if (dev)
                dev_put(dev);
        
        return len;
}

/*
  If this function is called with buflen < 0, the buffer size required
  for fitting the entire table will be returned. In that case, any
  output in buf should be ignored.
 */
int flow_table_print(char *buf, size_t buflen) 
{
        int tot_len, len;
        struct sock_list_iterator iter;

        sock_list_iterator_init(&iter);

        len = serval_sock_flow_print_header(buf, buflen);

        tot_len = len;

        if (len > buflen)
                buflen = 0;
        else
                buflen -= len;

        while (1) {
                struct sock *sk = sock_list_iterator_next(&iter);

                if (!sk)
                        break;
                
                len = serval_sock_flow_print(sk, buf + tot_len, 
                                             buflen - tot_len);
                
                tot_len += len;

                if (len > buflen)
                        buflen = 0;
                else
                        buflen -= len;
        }

        sock_list_iterator_destroy(&iter);
      
        return tot_len;
}

