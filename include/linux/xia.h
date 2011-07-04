#ifndef _LINUX_XIA_H
#define _LINUX_XIA_H

/* XIP protocols. */
enum {
  XIPPROTO_XIP = 0,		/* eXpressive Internet Protocol		*/
  XIPPROTO_RAW = 255,		/* Raw XIP packets			*/
  XIPPROTO_MAX
};

struct xiphdr {
	__u8	version;	/* XIP version				*/
	__u8	nxt_hdr;	/* Next header				*/
	__be16	payload_len; 	/* Length of the payload in bytes	*/
	__u8	hop;	/* Number of remaining hops allowed		*/
	__u8	nd;	/* Number of rows of the destination address	*/
	__u8	ns;	/* Number of rows of the source address		*/
	__u8	ln;	/* Last Node visited				*/
	
	/*
	 * Destination address starts here, and is followed by
	 * the source address.
	 */
};

#endif	/* _LINUX_XIA_H */
