#ifndef _SERVAL_SOCK_H
#define _SERVAL_SOCK_H

#include <netinet_serval.h>
#include <net/request_sock.h>
#include <net/inet_sock.h>
#include <net/tcp_states.h>
#include <net/xia_serval.h>

/* Should be power of two */
#define SERVAL_HTABLE_SIZE_MIN 256

struct serval_hslot {
	struct hlist_head head;
	spinlock_t        lock;
};

struct serval_table {
	struct serval_hslot *hash;
        unsigned int (*hashfn)(struct serval_table *tbl, struct sock *sk);
        struct serval_hslot *(*hashslot)(struct serval_table *tbl,
                                         struct net *net,
                                         void *key,
                                         size_t keylen);
	unsigned int mask;
};

static inline unsigned int
full_bitstring_hash(const void *bits_in, unsigned int num_bits)
{
	const unsigned char *bits = (const unsigned char *)bits_in;
	unsigned int len = num_bits / 8;
	unsigned long hash = init_name_hash();
	
	/* Compute the number of bits in the last byte to hash */
	num_bits -= (len * 8);

	/* Hash up to the last byte. */
	while (len--)
		hash = partial_name_hash(*bits++, hash);
	
	/* Hash the bits of the last byte if necessary */
	if (num_bits) {
		/* We need to mask off the last bits to use and hash those */
		unsigned char last_bits = (0xff << (8 - num_bits)) & *bits;
		partial_name_hash(last_bits, hash);
	}
	return end_name_hash(hash);
}

static inline unsigned int serval_hashfn(struct net *net, 
                                         void *key,
                                         size_t keylen,
                                         unsigned int mask)
{
	/* XXX Fix the following bug:
	 * According to serval_sock.c:serval_sock_lookup_flow(), keylen is
	 * in bytes, but full_bitstring_hash() expects the size in bits.
	 */
        return full_bitstring_hash(key, keylen) & mask;
}

static inline 
struct serval_hslot *serval_hashslot(struct serval_table *table,
                                     struct net *net, 
                                     void *key,
                                     size_t keylen)
{
	return &table->hash[serval_hashfn(net, key, keylen, table->mask)];
}

/* Base stats type included for all protocols.
 * Equivalent to protocol stats for UDP.
 */
struct stats_proto_base {
        unsigned long pkts_sent;
        unsigned long pkts_recv;

        unsigned long bytes_sent;
        unsigned long bytes_recv;
};

/* Stats type for the TCP protocol. */
struct stats_proto_tcp {
        struct stats_proto_base base; /* It needs to be first field. */

        uint32_t retrans;
        uint32_t lost;
        uint32_t srtt;
        uint32_t rttvar;  
        uint32_t mss;

        uint32_t snd_wnd;
        uint32_t snd_cwnd;
        uint32_t snd_ssthresh;    
        uint32_t snd_una;  /* next ACK we want */
        uint32_t snd_nxt;  /* next # we'll send */

        uint32_t rcv_wnd;
        uint32_t rcv_nxt;
};

/* Contains the individual flow statistics */
struct flow_info {
        struct flow_id flow;
        uint8_t proto;
        unsigned long inode;
        uint16_t len;

        struct stats_proto_base stats; // needs to be last
#define pkts_sent stats.pkts_sent
#define pkts_recv stats.pkts_recv
#define bytes_sent stats.bytes_sent
#define bytes_recv stats.bytes_recv
};

struct flow_info *serval_sock_stats_flow(struct flow_id *flow);

void serval_sock_migrate_iface(int old_dev, int new_dev);
void serval_sock_migrate_flow(struct flow_id *old_f, int new_dev);
void serval_sock_migrate_service(struct service_id *old_s, int new_if);
void serval_sock_freeze_flows(struct net_device *dev);
struct sock *serval_sock_lookup_flow(struct flow_id *);


const char *serval_sock_print_state(struct sock *sk, char *buf, size_t buflen);
const char *serval_sock_state_str(struct sock *sk);

const char *serval_sock_print(struct sock *sk, char *buf, size_t buflen);

const char *serval_sock_sal_state_str(struct sock *sk);
void serval_sock_rexmit_timeout(unsigned long data);

int serval_sock_tables_init(void);
void serval_sock_tables_fini(void);

void serval_sock_rfree(struct sk_buff *skb);

static inline void skb_serval_set_owner_r(struct sk_buff *skb, 
                                          struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = serval_sock_rfree;
}

#endif /* _SERVAL_SOCK_H */
