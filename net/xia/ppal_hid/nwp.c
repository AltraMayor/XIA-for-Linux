#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <asm/cache.h>
#include <net/xia_hid.h>

/*
 *	Announce myself
 */

/* The reason it doesn't process the announcement right away is that
 * it's common to have other announces to do soon, so we wait a little
 * bit to make a single announcement.
 */
void announce_myself(struct net *net)
{
	/* TODO Use attomic here! */
	net->xia.hid_state->new_hids_to_announce++;

	/* XXX Put this as a parameter in /proc. */
	mod_timer(&net->xia.hid_state->announce_timer, jiffies + 1*HZ);
}

void stop_announcements(struct net *net)
{
	del_timer_sync(&net->xia.hid_state->announce_timer);
}

static void announce_event(unsigned long data)
{
	struct net *net = (struct net *)data;

	if (net->xia.hid_state->new_hids_to_announce) {
		/* TODO Announce myself! */

		/* TODO Use attomic here! */
		net->xia.hid_state->new_hids_to_announce--;
	} else {
		/* TODO Decide if I'll announce myself based on the number of
		 * neighbors.
		 */
		/* TODO Announce myself if it's the case. */
	}


	/* XXX Put this as a parameter in /proc. */
	mod_timer(&net->xia.hid_state->announce_timer, jiffies + 60*HZ);
}

/*
 *	State associated to net
 */

int hid_new_hid_state(struct net *net)
{
	int rc = -ENOMEM;
	struct xia_hid_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto state;

	init_timer(&state->announce_timer);
	state->announce_timer.function = announce_event;
	/* TODO This reference to net needs to be released when it goes away! */
	state->announce_timer.data = (unsigned long)net;

	net->xia.hid_state = state;
	rc = 0;
	goto out;

/*
free_state:
	kfree(state);
*/
state:
	net->xia.hid_state = NULL;
out:
	return rc;
}

void hid_free_hid_state(struct net *net)
{
	struct xia_hid_state *state = net->xia.hid_state;
	del_timer_sync(&state->announce_timer);
	kfree(state);
	net->xia.hid_state = NULL;
}

/*
 *	Receive NWP packets from the device layer
 */

/* This function is based on net/ipv4/arp.c:arp_rcv */
static int nwp_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	/* TODO */
	return 0;
}

static struct packet_type nwp_packet_type __read_mostly = {
	.type = cpu_to_be16(ETH_P_NWP),
	.func = nwp_rcv,
};

/*
 *	Initialize NWP
 */

int hid_nwp_init(void)
{
	dev_add_pack(&nwp_packet_type);
	return 0;
}

void hid_nwp_exit(void)
{
	dev_remove_pack(&nwp_packet_type);
}
