THIS FILE AND ITS HEADER FILES ARE ONLY KEPT HERE TO HELP
IMPLEMETING SOCKET MIGRATION.




/* Serval socket implementation. Contains all the Serval-specific state.
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
#include <linux/ip.h>
#include <net/route.h>

#include "serval_ipv4.h"

/* Hash table with active FlowIDs. */
static struct serval_table established_table;

static const char * const sock_state_str[] = {
	[SAL_INIT]      = "INIT",
	[SAL_CONNECTED] = "CONNECTED",
	[SAL_REQUEST]   = "REQUEST",
	[SAL_RESPOND]   = "RESPOND",
	[SAL_FINWAIT1]  = "FINWAIT1",
	[SAL_FINWAIT2]  = "FINWAIT2",
	[SAL_TIMEWAIT]  = "TIMEWAIT",
	[SAL_CLOSED]    = "CLOSED",
	[SAL_CLOSEWAIT] = "CLOSEWAIT",
	[SAL_LASTACK]   = "LASTACK",
	[SAL_LISTEN]    = "LISTEN",
	[SAL_CLOSING]   = "CLOSING"
};

static const char * const sock_sal_state_str[] = {
	[SAL_RSYN_INITIAL]   = "SAL_RSYN_INITIAL",
	[SAL_RSYN_SENT]      = "SAL_RSYN_SENT",
	[SAL_RSYN_RECV]      = "SAL_RSYN_RECV",
	[SAL_RSYN_SENT_RECV] = "SAL_RSYN_SENT_RECV",
};

static int serval_table_init(struct serval_table *table,
	unsigned int (*hashfn)(struct serval_table *tbl, struct sock *sk),
	struct serval_hslot *(*hashslot)(struct serval_table *tbl,
					 struct net *net, void *key,
					 size_t keylen))
{
	unsigned int i;

	table->hash = kmalloc(SERVAL_HTABLE_SIZE_MIN *
			      sizeof(struct serval_hslot), GFP_KERNEL);

	if (!table->hash)
		return -1;

	BUILD_BUG_ON_NOT_POWER_OF_2(SERVAL_HTABLE_SIZE_MIN);
	table->mask = SERVAL_HTABLE_SIZE_MIN - 1;
	table->hashfn = hashfn;
	table->hashslot = hashslot;

	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&table->hash[i].head);
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
			/* Unhashing socket. */
			hlist_del_init(&sk->sk_node);
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
					/* An existing interface changed
					 * its address, i.e., physical
					 * mobility.
					 */
					should_migrate = 1;
				} else {
					/* We were told which
					 * interface to migrate, but
					 * we need to check that this
					 * sock matches.
					 */
					should_migrate = sk->sk_bound_dev_if
						== old_dev;
				}
			} else if (old_dev <= 0) {
				/* A new interface came up, migrate all flows
				 * with a DOWN interface to this new
				 * interface.
				 */
				struct net_device *i = dev_get_by_index(
					sock_net(sk), sk->sk_bound_dev_if);

				if (i) {
					/* If this interface is down, then
					 * migrate its flows.
					 */
					if (!(i->flags & IFF_UP))
						should_migrate = 1;
					dev_put(i);
				}
			} else if (new_dev <= 0 &&
				old_dev == sk->sk_bound_dev_if) {
				/* An interface went down, and we need
				 * to figure out a new target dev.
				 */
				struct rtable *rt;

				rt = serval_ip_route_output(sock_net(sk),
					inet_sk(sk)->inet_daddr, 0, 0, 0);

				if (rt) {
					should_migrate = 1;
					new_dev = rt->rt_iif;
					/* Found new output dev @new_dev. */
					ip_rt_put(rt);
				} else {
					/* Socket not routable. */
				}
			}

			if (should_migrate) {
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

	/* Migrated @n flows. */
}

/* This function is called from BH context. */
void serval_sock_freeze_flows(struct net_device *dev)
{
	int i;

	for (i = 0; i < SERVAL_HTABLE_SIZE_MIN; i++) {
		struct serval_hslot *slot;
		struct sock *sk;

		slot = &established_table.hash[i];

		spin_lock_bh(&slot->lock);

		hlist_for_each_entry(sk, &slot->head, sk_node) {
			struct serval_sock *ssk = sk_ssk(sk);

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
		/* Found sock, migrate it. */
		lock_sock(sk);
		serval_sock_set_mig_dev(sk, new_dev);
		serval_sal_migrate(sk);
		release_sock(sk);
		sock_put(sk);
	}
}

/* XXX Deal with socket migration. */

#if 0

struct sock *serval_sock_lookup_service(struct service_id *srvid, int protocol)
{
	return service_find_sock(srvid, SERVICE_ID_MAX_PREFIX_BITS, protocol);
}

/* For now this looks pretty much like migrating a flow, but I suspect it'll
 * be a little more involved once we support multiple flows per service.
 */
void serval_sock_migrate_service(struct service_id *old_s, int new_dev)
{
	/* XXX Set protocol type of socket */
	struct sock *sk = serval_sock_lookup_service(old_s, IPPROTO_TCP);

	if (sk) {
		lock_sock(sk);
		serval_sock_set_mig_dev(sk, new_dev);
		serval_sal_migrate(sk);
		release_sock(sk);
		sock_put(sk);
	}
}

#endif

static unsigned long get_socket_inode(struct socket *socket)
{
	if (socket) {
		struct address_space *faddr;
		struct inode *inode;

		if (!socket->file)
			goto out;

		faddr = socket->file->f_mapping;
		if (!faddr)
			goto out;

		inode = faddr->host;
		if (inode)
			return inode->i_ino;
	}
out:
	return 0;
}

struct flow_info *serval_sock_stats_flow(struct flow_id *flow)
{
	struct sock *sk = serval_sock_lookup_flow(flow);
	struct flow_info *ret = NULL;

	if (sk) {
		int info_size = sizeof(struct flow_id) + sizeof(uint8_t)
				sizeof(unsigned long) + sizeof(uint16_t);
		struct socket *socket = sk->sk_socket;

		if (sk->sk_protocol == IPPROTO_TCP) {
			struct serval_tcp_sock *tsk =
				(struct serval_tcp_sock *)sk;
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
		ret->pkts_sent = sk_ssk(sk)->tot_pkts_sent;
		ret->pkts_recv = sk_ssk(sk)->tot_pkts_recv;
		ret->bytes_sent = sk_ssk(sk)->tot_bytes_sent;
		ret->bytes_recv = sk_ssk(sk)->tot_bytes_recv;
		sock_put(sk);
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
		struct serval_sock *ssk = sk_ssk(sk);

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

static inline unsigned int serval_sock_ehash(struct serval_table *table,
					     struct sock *sk)
{
	return serval_hashfn(sock_net(sk),
			     sk_ssk(sk)->hash_key,
			     sk_ssk(sk)->hash_key_len,
			     table->mask);
}

static void __serval_table_hash(struct serval_table *table, struct sock *sk)
{
	struct serval_hslot *slot;

	sk->sk_hash = table->hashfn(table, sk);

	slot = &table->hash[sk->sk_hash];

	/* Bottom halfs already disabled here */
	spin_lock(&slot->lock);
	hlist_add_head(&sk->sk_node, &slot->head);
	spin_unlock(&slot->lock);
}

int serval_sock_tables_init(void)
{
	return serval_table_init(&established_table, serval_sock_ehash,
		serval_hashslot);
}

void serval_sock_tables_fini(void)
{
	serval_table_fini(&established_table);
}

const char *serval_sock_print_state(struct sock *sk, char *buf, size_t buflen)
{
	struct serval_sock *ssk = sk_ssk(sk);

	snprintf(buf, buflen, "%s snd_seq[una=%u nxt=%u wnd=%u iss=%u] rcv_seq[nxt=%u wnd=%u iss=%u]",
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
	struct serval_sock *ssk = sk_ssk(sk);

	snprintf(buf, buflen, "[%s:%s]",
		 flow_id_to_str(&ssk->local_flowid),
		 flow_id_to_str(&ssk->peer_flowid));

	return buf;
}

const char *serval_sock_state_str(struct sock *sk)
{
	if (sk->sk_state >= __SAL_MAX_STATE) {
		/* Invalid state. */
		return sock_state_str[0];
	}
	return sock_state_str[sk->sk_state];
}

const char *serval_sock_sal_state_str(struct sock *sk)
{
	BUG_ON(sk_ssk(sk)->sal_state >= __SAL_RSYN_MAX_STATE);
	return sock_sal_state_str[sk_ssk(sk)->sal_state];
}

void serval_sock_rfree(struct sk_buff *skb)
{
}
