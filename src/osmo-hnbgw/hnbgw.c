/* kitchen sink for OsmoHNBGW implementation */

/* (C) 2015,2024 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <inttypes.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/jhash.h>

#include <osmocom/vty/vty.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/netif/stream.h>

#include "config.h"
#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_proto.h>
#endif

#include <osmocom/hnbgw/hnb.h>
#include <osmocom/hnbgw/hnb_persistent.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_hnbap.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/mgw_fsm.h>
#include <osmocom/hnbgw/tdefs.h>

struct hnbgw *g_hnbgw = NULL;

const struct value_string ranap_domain_names[] = {
	{ DOMAIN_CS, "CS" },
	{ DOMAIN_PS, "PS" },
	{}
};


/* timer call-back: Update the HNB_STAT_UPTIME_SECONDS stat item of each hnb_persistent */
static void hnbgw_store_hnb_uptime(void *data)
{
	struct hnb_persistent *hnbp;

	llist_for_each_entry(hnbp, &g_hnbgw->hnb_persistent_list, list) {
		HNBP_STAT_SET(hnbp, HNB_STAT_UPTIME_SECONDS, hnbp->ctx != NULL ? hnbp_get_updowntime(hnbp) : 0);
	}

	osmo_timer_schedule(&g_hnbgw->store_uptime_timer, STORE_UPTIME_INTERVAL, 0);
}

static void hnbgw_store_hnb_rab_durations(void *data)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (!hnb->persistent)
			continue;
		hnb_store_rab_durations(hnb);
	}

	/* Keep this timer ticking */
	osmo_timer_schedule(&g_hnbgw->hnb_store_rab_durations_timer, HNB_STORE_RAB_DURATIONS_INTERVAL, 0);
}

/***********************************************************************
 * UE Context
 ***********************************************************************/

uint32_t get_next_ue_ctx_id(void)
{
	return g_hnbgw->next_ue_ctx_id++;
}

int hnbgw_mgw_setup(void)
{
	struct mgcp_client *mgcp_client_single;
	unsigned int pool_members_initalized;

	/* Initialize MGW pool. This initalizes and connects all MGCP clients that are currently configured in
	 * the pool. Adding additional MGCP clients to the pool is possible but the user has to configure and
	 * (re)connect them manually from the VTY. */
	if (!mgcp_client_pool_empty(g_hnbgw->mgw_pool)) {
		pool_members_initalized = mgcp_client_pool_connect(g_hnbgw->mgw_pool);
		if (!pool_members_initalized) {
			LOGP(DMGW, LOGL_ERROR, "MGW pool failed to initialize any pool members\n");
			return -EINVAL;
		}
		LOGP(DMGW, LOGL_NOTICE,
		     "MGW pool with %u pool members configured, (ignoring MGW configuration in VTY node 'mgcp').\n",
		     pool_members_initalized);
		return 0;
	}

	/* Initialize and connect a single MGCP client. This MGCP client will appear as the one and only pool
	 * member if there is no MGW pool configured. */
	LOGP(DMGW, LOGL_NOTICE, "No MGW pool configured, using MGW configuration in VTY node 'mgcp'\n");
	mgcp_client_single = mgcp_client_init(g_hnbgw, g_hnbgw->config.mgcp_client);
	if (!mgcp_client_single) {
		LOGP(DMGW, LOGL_ERROR, "MGW (single) client initalization failed\n");
		return -EINVAL;
	}
	if (mgcp_client_connect(mgcp_client_single)) {
		LOGP(DMGW, LOGL_ERROR, "MGW (single) connect failed at (%s:%u)\n",
		     g_hnbgw->config.mgcp_client->remote_addr,
		     g_hnbgw->config.mgcp_client->remote_port);
		return -EINVAL;
	}
	mgcp_client_pool_register_single(g_hnbgw->mgw_pool, mgcp_client_single);

	return 0;
}

struct msgb *hnbgw_ranap_msg_alloc(const char *name)
{
	struct msgb *ranap_msg;
	ranap_msg = msgb_alloc_c(OTC_SELECT, sizeof(struct osmo_scu_prim) + 1500, name);
	msgb_reserve(ranap_msg, sizeof(struct osmo_scu_prim));
	ranap_msg->l2h = ranap_msg->data;
	return ranap_msg;
}

#define HNBGW_COPYRIGHT \
	"OsmoHNBGW - Osmocom Home Node B Gateway implementation\r\n" \
	"Copyright (C) 2016-2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n" \
	"Contributions by Daniel Willmann, Harald Welte, Neels Hofmeyr\r\n" \
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n" \
	"This is free software: you are free to change and redistribute it.\r\n" \
	"There is NO WARRANTY, to the extent permitted by law.\r\n"

static const struct log_info_cat hnbgw_log_cat[] = {
	[DMAIN] = {
		.name = "DMAIN", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "Main program",
	},
	[DHNBAP] = {
		.name = "DHNBAP", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "Home Node B Application Part",
	},
	[DRUA] = {
		.name = "DRUA", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "RANAP User Adaptation",
	},
	[DRANAP] = {
		.name = "DRANAP", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "RAN Application Part",
	},
	[DMGW] = {
		.name = "DMGW", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "\033[1;33m",
		.description = "Media Gateway",
	},
	[DHNB] = {
		.name = "DHNB", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_CYAN,
		.description = "HNB side (via RUA)",
	},
	[DCN] = {
		.name = "DCN", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_DARKYELLOW,
		.description = "Core Network side (via SCCP)",
	},
	[DNFT] = {
		.name = "DNFT", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_BLUE,
		.description = "nftables interaction for retrieving stats",
	},
};

const struct log_info hnbgw_log_info = {
	.cat = hnbgw_log_cat,
	.num_cat = ARRAY_SIZE(hnbgw_log_cat),
};

struct vty_app_info hnbgw_vty_info = {
	.name = "OsmoHNBGW",
	.version = PACKAGE_VERSION,
	.go_parent_cb = hnbgw_vty_go_parent,
	.copyright = HNBGW_COPYRIGHT,
};

void g_hnbgw_alloc(void *ctx)
{
	OSMO_ASSERT(!g_hnbgw);
	g_hnbgw = talloc_zero(ctx, struct hnbgw);

	/* strdup so we can easily talloc_free in the VTY code */
	g_hnbgw->config.iuh_local_ip = talloc_strdup(g_hnbgw, HNBGW_LOCAL_IP_DEFAULT);
	g_hnbgw->config.iuh_local_port = IUH_DEFAULT_SCTP_PORT;
	g_hnbgw->config.hnbap_allow_tmsi = true;
	g_hnbgw->config.log_prefix_hnb_id = true;
	g_hnbgw->config.accept_all_hnb = true;
	g_hnbgw->config.iuh.tx_queue_max_length = IUH_TX_QUEUE_MAX_LENGTH;

	/* Set zero PLMN to detect a missing PLMN when transmitting RESET */
	g_hnbgw->config.plmn = (struct osmo_plmn_id){ 0, 0, false };

	g_hnbgw->next_ue_ctx_id = 23;
	INIT_LLIST_HEAD(&g_hnbgw->hnb_list);

	INIT_LLIST_HEAD(&g_hnbgw->hnb_persistent_list);
	hash_init(g_hnbgw->hnb_persistent_by_id);

	INIT_LLIST_HEAD(&g_hnbgw->sccp.users);

	g_hnbgw->mgw_pool = mgcp_client_pool_alloc(g_hnbgw);
	g_hnbgw->config.mgcp_client = mgcp_client_conf_alloc(g_hnbgw);

#if ENABLE_PFCP
	g_hnbgw->config.pfcp.remote_port = OSMO_PFCP_PORT;
#endif

	g_hnbgw->sccp.cnpool_iucs = hnbgw_cnpool_alloc(DOMAIN_CS);
	g_hnbgw->sccp.cnpool_iups = hnbgw_cnpool_alloc(DOMAIN_PS);

	osmo_timer_setup(&g_hnbgw->store_uptime_timer, hnbgw_store_hnb_uptime, g_hnbgw);
	osmo_timer_schedule(&g_hnbgw->store_uptime_timer, STORE_UPTIME_INTERVAL, 0);

	osmo_timer_setup(&g_hnbgw->hnb_store_rab_durations_timer, hnbgw_store_hnb_rab_durations, g_hnbgw);
	osmo_timer_schedule(&g_hnbgw->hnb_store_rab_durations_timer, HNB_STORE_RAB_DURATIONS_INTERVAL, 0);
}
