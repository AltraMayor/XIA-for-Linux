/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#ifndef _AF_SERVAL_H
#define _AF_SERVAL_H

#include <platform.h>

int serval_init(void);
void serval_fini(void);

struct ctl_table_header;

/* Control variables for Serval. */
struct netns_serval {
	unsigned int sysctl_sal_forward;
        unsigned int sysctl_inet_to_serval;
        unsigned int sysctl_auto_migrate;
        unsigned int sysctl_debug;
	unsigned int sysctl_udp_encap;
        unsigned int sysctl_sal_max_retransmits;
        unsigned int sysctl_resolution_mode;
        unsigned short sysctl_udp_encap_client_port;
        unsigned short sysctl_udp_encap_server_port;
	struct ctl_table_header *ctl;
};

extern struct netns_serval net_serval;

#endif /* AF_SERVAL_H */
