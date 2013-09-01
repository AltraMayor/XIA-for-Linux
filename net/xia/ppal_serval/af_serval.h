#ifndef _AF_SERVAL_H
#define _AF_SERVAL_H

struct ctl_table_header;

/* XXX It should be part of Serval's principal context per struct net. */
/* Control variables for Serval. */
struct netns_serval {
	unsigned int sysctl_sal_max_retransmits;
	struct ctl_table_header *ctl;
};

extern struct netns_serval net_serval;

#endif /* _AF_SERVAL_H */
