/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * Handlers for Serval's control channel.
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 *          David Shue <dshue@cs.princeton.edu>
 *          Rob Kiefer <rkiefer@cs.princeton.edu> 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <debug.h>
#include <platform.h>
#include <netdevice.h>
#include <ctrlmsg.h>
#include <service.h>
#if defined(OS_LINUX_KERNEL)
#include <net/route.h>
#endif
#include "af_serval.h"
#include "ctrl.h"
#include "serval_sock.h"
#include "serval_sal.h"
#include "serval_ipv4.h"

#if defined(ENABLE_DEBUG)
static const char *ctrlmsg_str[] = {
        [CTRLMSG_TYPE_REGISTER] = "CTRLMSG_TYPE_REGISTER",
        [CTRLMSG_TYPE_UNREGISTER] = " CTRLMSG_TYPE_UNREGISTER",
        [CTRLMSG_TYPE_RESOLVE] = "CTRLMSG_TYPE_RESOLVE",
        [CTRLMSG_TYPE_ADD_SERVICE] = "CTRLMSG_TYPE_ADD_SERVICE",
        [CTRLMSG_TYPE_DEL_SERVICE] = "CTRLMSG_TYPE_DEL_SERVICE",
        [CTRLMSG_TYPE_MOD_SERVICE] = "CTRLMSG_TYPE_MOD_SERVICE",
        [CTRLMSG_TYPE_GET_SERVICE] = "CTRLMSG_TYPE_GET_SERVICE",
        [CTRLMSG_TYPE_SERVICE_STAT] = "CTRLMSG_TYPE_SERVICE_STAT",
        [CTRLMSG_TYPE_CAPABILITIES] = "CTRLMSG_TYPE_CAPABILITIES",
        [CTRLMSG_TYPE_MIGRATE] = "CTRLMSG_TYPE_MIGRATE",
        [CTRLMSG_TYPE_DELAY_NOTIFY] = "CTRLMSG_TYPE_DELAY_NOTIFY",
        [CTRLMSG_TYPE_DELAY_VERDICT] = "CTRLMSG_TYPE_DELAY_VERDICT",
        [CTRLMSG_TYPE_DUMMY] = "CTRLMSG_TYPE_DUMMY",
        NULL
};
#endif

extern struct net_device *resolve_dev_impl(const struct in_addr *addr,
                                           int ifindex);

static inline struct net_device *resolve_dev(struct service_info *entry)
{
        return resolve_dev_impl(&entry->address, entry->if_index);
}

static int dummy_ctrlmsg_handler(struct ctrlmsg *cm, int peer)
{
	LOG_DBG("control message %s from pid %d\n", 
                ctrlmsg_str[cm->type], peer);
        return 0;
}

static int ctrl_handle_add_service_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        /* TODO - flags, etc */
        unsigned int i, index = 0;
        int err = 0;

        LOG_DBG("adding %u services, msg size %u\n", 
                num_res, CTRLMSG_SERVICE_LEN(cmr));
        
        for (i = 0; i < num_res; i++) {
                struct net_device *dev = NULL;
                struct service_info *entry = &cmr->service[i];
                unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;

                if (entry->type == SERVICE_RULE_FORWARD) {
                        dev = resolve_dev(entry);
                        
                        if (!dev)
                                continue;
                }

                if (entry->srvid_prefix_bits > 0)
                        prefix_bits = entry->srvid_prefix_bits;
         
#if defined(ENABLE_DEBUG)
                {
                        char ipstr[18];
                        LOG_DBG("Adding service id: %s(%u) "
                                "@ address %s, priority %u, weight %u\n", 
                                service_id_to_str(&entry->srvid), 
                                prefix_bits, 
                                inet_ntop(AF_INET, &entry->address,
                                          ipstr, sizeof(ipstr)),
                                entry->priority, entry->weight);
                }
#endif
                err = service_add(&entry->srvid, 
                                  prefix_bits, 
                                  entry->type,
                                  entry->srvid_flags, 
                                  entry->priority, 
                                  entry->weight,
                                  &entry->address, 
                                  sizeof(entry->address),
                                  make_target(dev), GFP_KERNEL);
                if (dev)
                        dev_put(dev);

                if (err > 0) {
                        if (index < i) {
                                /* copy it over */
                                memcpy(&cmr->service[index], 
                                       entry, sizeof(*entry));
                        }
                        index++;
                } else {
                        LOG_ERR("Error adding service %s: err=%d\n", 
                                service_id_to_str(&entry->srvid), err);
                }
        }

        if (index == 0) {
                /* Just return the original request with a return value */
                cm->retval = CTRLMSG_RETVAL_NOENTRY;
        } else {
                /* Return the entries added */
                cm->retval = CTRLMSG_RETVAL_OK;
                cm->len = CTRLMSG_SERVICE_NUM_LEN(index);
        }

        ctrl_sendmsg(cm, peer, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_del_service_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        const size_t cmsg_size = sizeof(struct ctrlmsg_service_info_stat) + 
                sizeof(struct service_info_stat) * num_res;
        struct ctrlmsg_service_info_stat *cms;
        struct service_id null_service = { .s_sid = { 0 } };
        unsigned int i = 0, index = 0;
        int err = 0;       

        LOG_DBG("deleting %u services\n", num_res);

        cms = kmalloc(cmsg_size, GFP_KERNEL);

        if (!cms) {
                cm->retval = CTRLMSG_RETVAL_ERROR;
                ctrl_sendmsg(cm, peer, GFP_KERNEL);
                return -ENOMEM;
        }

        memset(cms, 0, cmsg_size);

        for (i = 0; i < num_res; i++) {
                struct service_info *entry = &cmr->service[i];
                struct service_info_stat *stat = &cms->service[index];
                struct target_stats tstat;
                struct service_entry *se;
                unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;

                /*
                  We might be trying to delete the "default" entry. In
                  that case
                */
                if (memcmp(&entry->srvid, &null_service, 
                           sizeof(null_service)) == 0 ||
                    entry->srvid_prefix_bits > 0)
                        prefix_bits = entry->srvid_prefix_bits;
                
                stat->service.srvid_prefix_bits = prefix_bits;
                se = service_find_exact(&entry->srvid, 
                                        prefix_bits);

                if (!se) {
                        LOG_DBG("No match for serviceID %s:(%u)\n",
                                service_id_to_str(&entry->srvid),
                                prefix_bits);
                        continue;
                }

                memset(&tstat, 0, sizeof(tstat));
                
                err = service_entry_remove_target(se,
                                                  entry->type,
                                                  &entry->address, 
                                                  sizeof(entry->address), 
                                                  &tstat);

                if (err > 0) {
                        stat->duration_sec = tstat.duration_sec;
                        stat->duration_nsec = tstat.duration_nsec;
                        stat->packets_resolved = tstat.packets_resolved;
                        stat->bytes_resolved = tstat.bytes_resolved;
                        stat->packets_dropped = tstat.packets_dropped;
                        stat->bytes_dropped = tstat.packets_dropped;

                        //if (index < i) {
                                memcpy(&stat->service, entry, 
                                       sizeof(*entry));
                        //}
                        LOG_DBG("Service ID %s:%u\n", service_id_to_str(&stat->service.srvid), stat->service.srvid_prefix_bits);
                        index++;
                } else if (err == 0) {
                        LOG_ERR("Could not find target for service %s\n", 
                                service_id_to_str(&entry->srvid));
                } else {
                        LOG_ERR("Could not remove service %s - err %d\n", 
                                service_id_to_str(&entry->srvid), 
                                err);
                }

                service_entry_put(se);
        }

        if (index == 0) {
                cm->retval = CTRLMSG_RETVAL_NOENTRY;
                ctrl_sendmsg(cm, peer, GFP_KERNEL);
        } else {
                cms->cmh.type = CTRLMSG_TYPE_DEL_SERVICE;
                cms->xid = cmr->xid;
                cms->cmh.xid = cm->xid;
                cms->cmh.retval = CTRLMSG_RETVAL_OK;
                cms->cmh.len = CTRLMSG_SERVICE_INFO_STAT_NUM_LEN(index);
                ctrl_sendmsg(&cms->cmh, peer, GFP_KERNEL);
        }

        kfree(cms);

        return 0;
}

static int ctrl_handle_capabilities_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_capabilities *cmt = (struct ctrlmsg_capabilities*)cm;
        net_serval.sysctl_sal_forward = cmt->capabilities & SVSTK_TRANSIT;
        return 0;
}

static int ctrl_handle_mod_service_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_service *cmr = (struct ctrlmsg_service *)cm;
        unsigned int num_res = CTRLMSG_SERVICE_NUM(cmr);
        unsigned int i, index = 0;
        int err = 0;

        if (num_res < 2 || num_res % 2 != 0) {
                LOG_DBG("Not an even number of service infos\n");
                return 0;
        }

        LOG_DBG("modifying %u services\n", num_res / 2);

        for (i = 0; i < num_res; i += 2) {
                struct net_device *dev;
                struct service_info *entry_old = &cmr->service[i];
                struct service_info *entry_new = &cmr->service[i+1];
                unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
                
                if (entry_old->srvid_prefix_bits > 0)
                        prefix_bits = entry_old->srvid_prefix_bits;

#if defined(ENABLE_DEBUG)
                {
                        char buf[18];
                        LOG_DBG("Modifying: %s flags(%i) bits(%i) %s\n", 
                                service_id_to_str(&entry_old->srvid), 
                                entry_old->srvid_flags, 
                                prefix_bits,
                                inet_ntop(AF_INET, &entry_old->address, 
                                          buf, 18));
                }
#endif
                dev = resolve_dev(entry_old);
                
                if (!dev)
                        continue;

                err = service_modify(&entry_old->srvid,
                                     prefix_bits,
                                     SERVICE_RULE_FORWARD,
                                     entry_old->srvid_flags, 
                                     entry_new->priority, 
                                     entry_new->weight, 
                                     &entry_old->address,
                                     sizeof(entry_old->address),
                                     &entry_new->address,
                                     sizeof(entry_new->address), 
                                     make_target(dev));
                if (err > 0) {
                        if (index < i) {
                                /* copy it over */
                                memcpy(&cmr->service[index], 
                                       entry_new, sizeof(*entry_new));
                        }
                        index++;
                } else {
                        LOG_ERR("Could not modify service %s: %i\n", 
                                service_id_to_str(&entry_old->srvid), 
                                err);
                }
                dev_put(dev);
        }
        
        if (index == 0) {
                cm->retval = CTRLMSG_RETVAL_NOENTRY;
        } else {
                cm->retval = CTRLMSG_RETVAL_OK;
                cm->len = CTRLMSG_SERVICE_NUM_LEN(index);
        }
        
        ctrl_sendmsg(cm, peer, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_get_service_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_service *cmg = (struct ctrlmsg_service *)cm;
        struct service_entry *se;
        struct service_iter iter;
        unsigned short prefix_bits = SERVICE_ID_MAX_PREFIX_BITS;
        struct target *t;

        LOG_DBG("getting service: %s\n",
                service_id_to_str(&cmg->service[0].srvid));

        if (cmg->service[0].srvid_prefix_bits > 0)
                prefix_bits = cmg->service[0].srvid_prefix_bits;

        se = service_find(&cmg->service[0].srvid, 
                          prefix_bits);

        if (se) {
                struct ctrlmsg_service *cres;
                size_t size = CTRLMSG_SERVICE_NUM_LEN(se->count);
                int i = 0;
                          
                cres = kmalloc(size, GFP_KERNEL);

                if (!cres) {
                        service_entry_put(se);
                        cm->retval = CTRLMSG_RETVAL_ERROR;
                        ctrl_sendmsg(cm, peer, GFP_KERNEL);
                        return -ENOMEM;
                }

                memset(cres, 0, size);
                cres->cmh.type = CTRLMSG_TYPE_GET_SERVICE;
                cres->cmh.len = size;
                cres->cmh.xid = cm->xid;
                cres->xid = cmg->xid;

                memset(&iter, 0, sizeof(iter));
                service_iter_init(&iter, se, SERVICE_ITER_FORWARD);

                while ((t = service_iter_next(&iter)) != NULL) {
                        struct service_info *entry = &cres->service[i++];

                        service_get_id(se, &entry->srvid);
                        memcpy(&entry->address, 
                               t->dst, t->dstlen);
                        
                        entry->srvid_prefix_bits = service_get_prefix_bits(se);
                        entry->srvid_flags = service_iter_get_flags(&iter);
                        entry->weight = t->weight;
                        entry->priority = service_iter_get_priority(&iter);
                        
#if defined(ENABLE_DEBUG)
                        {
                                char buf[18];
                                LOG_DBG("Get %s %s priority=%u weight=%u\n", 
                                service_id_to_str(&entry->srvid), 
                                        inet_ntop(AF_INET, &t->dst, 
                                                  buf, 18),
                                        entry->priority,
                                        entry->weight);
                        }
#endif
                        
                }

                service_iter_destroy(&iter);
                service_entry_put(se);

                if (i == 0)
                        cres->cmh.retval = CTRLMSG_RETVAL_NOENTRY;
                else
                        cres->cmh.retval = CTRLMSG_RETVAL_OK;

                ctrl_sendmsg(&cres->cmh, peer, GFP_KERNEL);
                kfree(cres);
                LOG_DBG("Service %s matched %u entries. msg_len=%u\n",
                        service_id_to_str(&cmg->service[0].srvid),
                        se->count, cres->cmh.len);
        } else {
                cmg->service[0].srvid_flags = SVSF_INVALID;
                cmg->cmh.retval = CTRLMSG_RETVAL_NOENTRY;
                ctrl_sendmsg(&cmg->cmh, peer, GFP_KERNEL);
                LOG_DBG("Service %s not found\n",
                        service_id_to_str(&cmg->service[0].srvid));
        }

        return 0;
}

static int ctrl_handle_service_stats_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_service_stat *cms = (struct ctrlmsg_service_stat *)cm;
        struct table_stats tstats;

        memset(&cms->stats, 0, sizeof(cms->stats));
        
        if (net_serval.sysctl_sal_forward) {
                cms->stats.capabilities = SVSTK_TRANSIT;
        }

        memset(&tstats, 0, sizeof(tstats));

        service_get_stats(&tstats);

        cms->stats.instances = tstats.instances;
        cms->stats.services = tstats.services;
        cms->stats.bytes_resolved = tstats.bytes_resolved;
        cms->stats.packets_resolved = tstats.packets_resolved;
        cms->stats.bytes_dropped = tstats.bytes_dropped;
        cms->stats.packets_dropped = tstats.packets_dropped;

        LOG_DBG("service stats: instances(%i) services(%i) "
                "bytes resolved(%i) packets resolved(%i) capabilities\n",
                tstats.instances, tstats.services, tstats.bytes_resolved,
                tstats.packets_resolved, cms->stats.capabilities);

        ctrl_sendmsg(&cms->cmh, peer, GFP_KERNEL);

        return 0;
}

static int ctrl_handle_migrate_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_migrate *cmm = (struct ctrlmsg_migrate*)cm;
        struct net_device *old_dev, *new_dev;
        int ret = 0;
        
        new_dev = dev_get_by_name(&init_net, cmm->to_i);

        /* Check that migration destination is valid. */
        if (!new_dev) {
                LOG_ERR("No new interface %s\n", cmm->to_i);
                return -1;
        }

        switch (cmm->migrate_type) {
        case CTRL_MIG_IFACE:
                LOG_DBG("migrate iface %s to iface %s\n", 
                        cmm->from_i, cmm->to_i);
                old_dev = dev_get_by_name(&init_net, cmm->from_i);

                if (!old_dev) {
                        LOG_ERR("No old interface %s\n", cmm->from_i);
                        ret = -1;
                } else {
                        serval_sock_migrate_iface(old_dev->ifindex, 
                                                  new_dev->ifindex);
                        dev_put(old_dev);
                }
                break;
        case CTRL_MIG_FLOW:
                LOG_DBG("migrate flow %s to iface %s\n", 
                        flow_id_to_str(&cmm->from_f), cmm->to_i);
                serval_sock_migrate_flow(&cmm->from_f, new_dev->ifindex);
                break;
        case CTRL_MIG_SERVICE:
                LOG_DBG("migrate service to iface %s\n", cmm->to_i);
                serval_sock_migrate_service(&cmm->from_s, new_dev->ifindex);
                break;
        }

        dev_put(new_dev);

        return ret;
}

static int ctrl_handle_stats_query_msg(struct ctrlmsg *cm, int peer)
{
        struct ctrlmsg_stats_query *csm = (struct ctrlmsg_stats_query*) cm;
        int num_flows = CTRLMSG_STATS_NUM_FLOWS(csm);
        int info_size = 2048 - sizeof(struct ctrlmsg) - 1;
        int offset = 0;
        int i, ret = 0;
        
        struct ctrlmsg_stats_response *temp = kmalloc(2048, GFP_KERNEL);
        if (!temp) {
                LOG_ERR("Could not allocate message\n");
                return -1;
        }
        memset(temp, 0, 2048);
        for (i = 0; i < num_flows; i++) {
                struct flow_info *info;
                LOG_DBG("Got a stats query for flow %s\n", 
                        flow_id_to_str(&csm->flows[i]));
                info = serval_sock_stats_flow(&csm->flows[i], temp, i);
                if (info) {
                        int info_len = info->len;
                        LOG_DBG("Got a response for flow %s (%d)\n",
                                flow_id_to_str(&info->flow), info->len);
                        if (info_len > info_size - offset) {
                                temp->cmh.type = CTRLMSG_TYPE_STATS_RESP;
                                temp->cmh.len = sizeof(struct ctrlmsg) + 1 + 
                                                offset;
                                temp->flags |= STATS_RESP_F_MORE;
                                ctrl_sendmsg(&temp->cmh, peer, GFP_KERNEL);
                                memset(temp, 0, 2048);
                                offset = 0;
                        }
                        memcpy(&temp->info[offset], info, info->len);
                        offset += info->len;
                        temp->num_infos += 1;
                        kfree(info);
                }
        }
        temp->cmh.type = CTRLMSG_TYPE_STATS_RESP;
        temp->cmh.len = sizeof(struct ctrlmsg) + 1 + offset;
        ctrl_sendmsg(&temp->cmh, peer, GFP_KERNEL);
        kfree(temp);
        return ret;
}

ctrlmsg_handler_t handlers[] = {
        [CTRLMSG_TYPE_REGISTER] = dummy_ctrlmsg_handler,
        [CTRLMSG_TYPE_UNREGISTER] = dummy_ctrlmsg_handler,
        [CTRLMSG_TYPE_RESOLVE] = dummy_ctrlmsg_handler,
        [CTRLMSG_TYPE_ADD_SERVICE] = ctrl_handle_add_service_msg,
        [CTRLMSG_TYPE_DEL_SERVICE] = ctrl_handle_del_service_msg,
        [CTRLMSG_TYPE_MOD_SERVICE] = ctrl_handle_mod_service_msg,
        [CTRLMSG_TYPE_GET_SERVICE] = ctrl_handle_get_service_msg,
        [CTRLMSG_TYPE_SERVICE_STAT] = ctrl_handle_service_stats_msg,
        [CTRLMSG_TYPE_CAPABILITIES] = ctrl_handle_capabilities_msg,
        [CTRLMSG_TYPE_MIGRATE] = ctrl_handle_migrate_msg,
        [CTRLMSG_TYPE_STATS_QUERY] = ctrl_handle_stats_query_msg,
        [CTRLMSG_TYPE_STATS_RESP] = dummy_ctrlmsg_handler,
        [CTRLMSG_TYPE_DUMMY] = dummy_ctrlmsg_handler,
};
