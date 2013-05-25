#ifndef _SERVAL_TCP_REQUEST_SOCK_H_
#define _SERVAL_TCP_REQUEST_SOCK_H_

#include <net/xia_serval.h>

struct serval_tcp_request_sock {
	struct serval_request_sock rsk;
	__u32 snt_isn; /* SeNT Initial Sequence Number.		*/
	__u32 rcv_isn; /* ReCeiVed Initial Sequence Number.	*/

	/* Flags copied from struct inet_request_sock. */
	u16		snd_wscale : 4,
			rcv_wscale : 4,
			tstamp_ok  : 1,
			sack_ok    : 1,
			wscale_ok  : 1;
};

static inline struct serval_tcp_request_sock *serval_tcp_rsk(
	struct request_sock *rsk)
{
	return (struct serval_tcp_request_sock *)rsk;
}

#endif /* _SERVAL_TCP_REQUEST_SOCK_H_ */
