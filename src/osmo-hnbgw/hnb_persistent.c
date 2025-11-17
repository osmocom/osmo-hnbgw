/* HNB persistent related code */

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

#include "config.h"

#include <inttypes.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/jhash.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/netif/stream.h>

#include <osmocom/hnbgw/hnb.h>
#include <osmocom/hnbgw/hnb_persistent.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/tdefs.h>

/***********************************************************************
 * HNB Persistent Data
 ***********************************************************************/

const struct rate_ctr_desc hnb_ctr_description[] = {
	[HNB_CTR_IUH_ESTABLISHED] = {
		"iuh:established", "Number of times Iuh link was established" },

	[HNB_CTR_RANAP_PS_ERR_IND_UL] = {
		"ranap:ps:error_ind:ul", "Received ERROR Indications in Uplink (PS Domain)" },
	[HNB_CTR_RANAP_CS_ERR_IND_UL] = {
		"ranap:cs:error_ind:ul", "Received ERROR Indications in Uplink (PS Domain)" },

	[HNB_CTR_RANAP_PS_RESET_REQ_UL] = {
		"ranap:ps:reset_req:ul", "Received RESET Requests in Uplink (PS Domain)" },
	[HNB_CTR_RANAP_CS_RESET_REQ_UL] = {
		"ranap:cs:reset_req:ul", "Received RESET Requests in Uplink (CS Domain)" },


	[HNB_CTR_RANAP_PS_RAB_ACT_REQ] = {
		"ranap:ps:rab_act:req", "PS RAB Activations requested" },
	[HNB_CTR_RANAP_CS_RAB_ACT_REQ] = {
		"ranap:cs:rab_act:req", "CS RAB Activations requested" },
	[HNB_CTR_RANAP_PS_RAB_ACT_REQ_UNEXP] = {
		"ranap:ps:rab_act:req_unexp", "PS RAB Activations requested in unexpected state" },
	[HNB_CTR_RANAP_CS_RAB_ACT_REQ_UNEXP] = {
		"ranap:cs:rab_act:req_unexp", "CS RAB Activations requested in unexpected state" },

	[HNB_CTR_RANAP_PS_RAB_ACT_CNF] = {
		"ranap:ps:rab_act:cnf", "PS RAB Activations confirmed" },
	[HNB_CTR_RANAP_CS_RAB_ACT_CNF] = {
		"ranap:cs:rab_act:cnf", "CS RAB Activations confirmed" },
	[HNB_CTR_RANAP_PS_RAB_ACT_CNF_UNEXP] = {
		"ranap:ps:rab_act:cnf_unexp", "PS RAB Activations confirmed in unexpected state" },
	[HNB_CTR_RANAP_CS_RAB_ACT_CNF_UNEXP] = {
		"ranap:cs:rab_act:cnf_unexp", "CS RAB Activations confirmed in unexpected state" },

	[HNB_CTR_RANAP_PS_RAB_ACT_FAIL] = {
		"ranap:ps:rab_act:fail", "PS RAB Activations failed" },
	[HNB_CTR_RANAP_CS_RAB_ACT_FAIL] = {
		"ranap:cs:rab_act:fail", "CS RAB Activations failed" },
	[HNB_CTR_RANAP_PS_RAB_ACT_FAIL_UNEXP] = {
		"ranap:ps:rab_act:fail_unexp", "PS RAB Activations failed in unexpected state" },
	[HNB_CTR_RANAP_CS_RAB_ACT_FAIL_UNEXP] = {
		"ranap:cs:rab_act:fail_unexp", "CS RAB Activations failed in unexpected state" },


	[HNB_CTR_RANAP_PS_RAB_MOD_REQ] = {
		"ranap:ps:rab_mod:req", "PS RAB Modifications requested" },
	[HNB_CTR_RANAP_CS_RAB_MOD_REQ] = {
		"ranap:cs:rab_mod:req", "CS RAB Modifications requested" },

	[HNB_CTR_RANAP_PS_RAB_MOD_CNF] = {
		"ranap:ps:rab_mod:cnf", "PS RAB Modifications confirmed" },
	[HNB_CTR_RANAP_CS_RAB_MOD_CNF] = {
		"ranap:cs:rab_mod:cnf", "CS RAB Modifications confirmed" },

	[HNB_CTR_RANAP_PS_RAB_MOD_FAIL] = {
		"ranap:ps:rab_mod:fail", "PS RAB Modifications failed" },
	[HNB_CTR_RANAP_CS_RAB_MOD_FAIL] = {
		"ranap:cs:rab_mod:fail", "CS RAB Modifications failed" },

	[HNB_CTR_RANAP_PS_RAB_REL_REQ] = {
		"ranap:ps:rab_rel:req:normal", "PS RAB Release requested (by CN), normal" },
	[HNB_CTR_RANAP_CS_RAB_REL_REQ] = {
		"ranap:cs:rab_rel:req:normal", "CS RAB Release requested (by CN), normal" },
	[HNB_CTR_RANAP_PS_RAB_REL_REQ_ABNORMAL] = {
		"ranap:ps:rab_rel:req:abnormal", "PS RAB Release requested (by CN), abnormal" },
	[HNB_CTR_RANAP_CS_RAB_REL_REQ_ABNORMAL] = {
		"ranap:cs:rab_rel:req:abnormal", "CS RAB Release requested (by CN), abnormal" },
	[HNB_CTR_RANAP_PS_RAB_REL_REQ_UNEXP] = {
		"ranap:ps:rab_rel:req:unexp", "PS RAB Release requested (by CN) in unexpected state" },
	[HNB_CTR_RANAP_CS_RAB_REL_REQ_UNEXP] = {
		"ranap:cs:rab_rel:req:unexp", "CS RAB Release requested (by CN) in unexpected state" },

	[HNB_CTR_RANAP_PS_RAB_REL_CNF] = {
		"ranap:ps:rab_rel:cnf", "PS RAB Release confirmed" },
	[HNB_CTR_RANAP_CS_RAB_REL_CNF] = {
		"ranap:cs:rab_rel:cnf", "CS RAB Release confirmed" },
	[HNB_CTR_RANAP_PS_RAB_REL_CNF_UNEXP] = {
		"ranap:ps:rab_rel:cnf_unexp", "PS RAB Release confirmed in unexpected state" },
	[HNB_CTR_RANAP_CS_RAB_REL_CNF_UNEXP] = {
		"ranap:cs:rab_rel:cnf_unexp", "CS RAB Release confirmed in unexpected state" },

	[HNB_CTR_RANAP_PS_RAB_REL_FAIL] = {
		"ranap:ps:rab_rel:fail", "PS RAB Release failed" },
	[HNB_CTR_RANAP_CS_RAB_REL_FAIL] = {
		"ranap:cs:rab_rel:fail", "CS RAB Release failed" },
	[HNB_CTR_RANAP_PS_RAB_REL_FAIL_UNEXP] = {
		"ranap:ps:rab_rel:fail_unexp", "PS RAB Release failed in unexpected state" },
	[HNB_CTR_RANAP_CS_RAB_REL_FAIL_UNEXP] = {
		"ranap:cs:rab_rel:fail_unexp", "CS RAB Release failed in unexpected state" },

	[HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT] = {
		"ranap:ps:rab_rel:implicit:normal", "PS RAB Release implicit (during Iu Release), normal" },
	[HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT] = {
		"ranap:cs:rab_rel:implicit:normal", "CS RAB Release implicit (during Iu Release), normal" },
	[HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT_ABNORMAL] = {
		"ranap:ps:rab_rel:implicit:abnormal", "PS RAB Release implicit (during Iu Release), abnormal" },
	[HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT_ABNORMAL] = {
		"ranap:cs:rab_rel:implicit:abnormal", "CS RAB Release implicit (during Iu Release), abnormal" },

	[HNB_CTR_RUA_ERR_IND] = {
		"rua:error_ind", "Received RUA Error Indications" },

	[HNB_CTR_RUA_PS_CONNECT_UL] = {
		"rua:ps:connect:ul", "Received RUA Connect requests (PS Domain)" },
	[HNB_CTR_RUA_CS_CONNECT_UL] = {
		"rua:cs:connect:ul", "Received RUA Connect requests (CS Domain)" },

	[HNB_CTR_RUA_PS_DISCONNECT_UL] = {
		"rua:ps:disconnect:ul", "Received RUA Disconnect requests in uplink (PS Domain)" },
	[HNB_CTR_RUA_CS_DISCONNECT_UL] = {
		"rua:cs:disconnect:ul", "Received RUA Disconnect requests in uplink (CS Domain)" },
	[HNB_CTR_RUA_PS_DISCONNECT_DL] = {
		"rua:ps:disconnect:dl", "Transmitted RUA Disconnect requests in downlink (PS Domain)" },
	[HNB_CTR_RUA_CS_DISCONNECT_DL] = {
		"rua:cs:disconnect:dl", "Transmitted RUA Disconnect requests in downlink (CS Domain)" },

	[HNB_CTR_RUA_PS_DT_UL] = {
		"rua:ps:direct_transfer:ul", "Received RUA DirectTransfer in uplink (PS Domain)" },
	[HNB_CTR_RUA_CS_DT_UL] = {
		"rua:cs:direct_transfer:ul", "Received RUA DirectTransfer in uplink (CS Domain)" },
	[HNB_CTR_RUA_PS_DT_DL] = {
		"rua:ps:direct_transfer:dl", "Transmitted RUA DirectTransfer in downlink (PS Domain)" },
	[HNB_CTR_RUA_CS_DT_DL] = {
		"rua:cs:direct_transfer:dl", "Transmitted RUA DirectTransfer in downlink (CS Domain)" },

	[HNB_CTR_RUA_UDT_UL] = {
		"rua:unit_data:ul", "Received RUA UnitData (UDT) in uplink" },
	[HNB_CTR_RUA_UDT_DL] = {
		"rua:unit_data:dl", "Transmitted RUA UnitData (UDT) in downlink" },

	[HNB_CTR_PS_PAGING_ATTEMPTED] = {
		"paging:ps:attempted", "Transmitted PS Paging requests" },
	[HNB_CTR_CS_PAGING_ATTEMPTED] = {
		"paging:cs:attempted", "Transmitted CS Paging requests" },

	[HNB_CTR_RAB_ACTIVE_MILLISECONDS_TOTAL] = {
		"rab:cs:active_milliseconds:total", "Cumulative number of milliseconds of CS RAB activity" },

	[HNB_CTR_DTAP_CS_LU_REQ] = { "dtap:cs:location_update:req", "CS Location Update Requests" },
	[HNB_CTR_DTAP_CS_LU_ACC] = { "dtap:cs:location_update:accept", "CS Location Update Accepts" },
	[HNB_CTR_DTAP_CS_LU_REJ] = { "dtap:cs:location_update:reject", "CS Location Update Rejects" },

	[HNB_CTR_DTAP_PS_ATT_REQ] = { "dtap:ps:attach:req", "PS Attach Requests" },
	[HNB_CTR_DTAP_PS_ATT_ACK] = { "dtap:ps:attach:accept", "PS Attach Accepts" },
	[HNB_CTR_DTAP_PS_ATT_REJ] = { "dtap:ps:attach:reject", "PS Attach Rejects" },

	[HNB_CTR_DTAP_PS_RAU_REQ] = { "dtap:ps:routing_area_update:req", "PS Routing Area Update Requests" },
	[HNB_CTR_DTAP_PS_RAU_ACK] = { "dtap:ps:routing_area_update:accept", "PS Routing Area Update Accepts" },
	[HNB_CTR_DTAP_PS_RAU_REJ] = { "dtap:ps:routing_area_update:reject", "PS Routing Area Update Rejects" },

	[HNB_CTR_GTPU_PACKETS_UL] = {
		"gtpu:packets:ul",
		"Count of GTP-U packets received from the HNB",
	},
	[HNB_CTR_GTPU_TOTAL_BYTES_UL] = {
		"gtpu:total_bytes:ul",
		"Count of total GTP-U bytes received from the HNB, including the GTP-U/UDP/IP headers",
	},
	[HNB_CTR_GTPU_UE_BYTES_UL] = {
		"gtpu:ue_bytes:ul",
		"Assuming an IP header length of 20 bytes, GTP-U bytes received from the HNB, excluding the GTP-U/UDP/IP headers",
	},
	[HNB_CTR_GTPU_PACKETS_DL] = {
		"gtpu:packets:dl",
		"Count of GTP-U packets sent to the HNB",
	},
	[HNB_CTR_GTPU_TOTAL_BYTES_DL] = {
		"gtpu:total_bytes:dl",
		"Count of total GTP-U bytes sent to the HNB, including the GTP-U/UDP/IP headers",
	},
	[HNB_CTR_GTPU_UE_BYTES_DL] = {
		"gtpu:ue_bytes:dl",
		"Assuming an IP header length of 20 bytes, GTP-U bytes sent to the HNB, excluding the GTP-U/UDP/IP headers",
	},

};

const struct rate_ctr_group_desc hnb_ctrg_desc = {
	"hnb",
	"hNodeB",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(hnb_ctr_description),
	hnb_ctr_description,
};

const struct osmo_stat_item_desc hnb_stat_desc[] = {
	[HNB_STAT_UPTIME_SECONDS] = { "uptime:seconds", "Seconds of uptime", "s", 60, 0 },
};

const struct osmo_stat_item_group_desc hnb_statg_desc = {
	.group_name_prefix = "hnb",
	.group_description = "hNodeB",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(hnb_stat_desc),
	.item_desc = hnb_stat_desc,
};

static void hnb_persistent_disconnected_timeout_cb(void *data)
{
	hnb_persistent_free(data);
}

static void hnb_persistent_disconnected_timeout_schedule(struct hnb_persistent *hnbp)
{
	unsigned long period_s = osmo_tdef_get(hnbgw_T_defs, -35, OSMO_TDEF_S, 60*60*24*7);
	if (period_s < 1) {
		LOG_HNBP(hnbp, LOGL_INFO,
			 "timer X35 is zero, not setting a disconnected timeout for this hnb-persistent instance.\n");
		return;
	}
	/* It is fine if the timer is already active, osmo_timer_del() is done implicitly by the osmo_timer API. */
	osmo_timer_setup(&hnbp->disconnected_timeout, hnb_persistent_disconnected_timeout_cb, hnbp);
	osmo_timer_schedule(&hnbp->disconnected_timeout, period_s, 0);
}

struct hnb_persistent *hnb_persistent_alloc(const struct umts_cell_id *id)
{
	struct hnb_persistent *hnbp = talloc_zero(g_hnbgw, struct hnb_persistent);
	if (!hnbp)
		return NULL;

	hnbp->id = *id;
	hnbp->id_str = talloc_strdup(hnbp, umts_cell_id_to_str(id));
	hnbp->ctrs = rate_ctr_group_alloc(hnbp, &hnb_ctrg_desc, 0);
	if (!hnbp->ctrs)
		goto out_free;
	rate_ctr_group_set_name(hnbp->ctrs, hnbp->id_str);
	hnbp->statg = osmo_stat_item_group_alloc(hnbp, &hnb_statg_desc, 0);
	if (!hnbp->statg)
		goto out_free_ctrs;
	osmo_stat_item_group_set_name(hnbp->statg, hnbp->id_str);

	hnbp->config.iuh_tx_queue_max_length = -1; /* global HNBGW default */

	llist_add(&hnbp->list, &g_hnbgw->hnb_persistent_list);
	hash_add(g_hnbgw->hnb_persistent_by_id, &hnbp->node_by_id, umts_cell_id_hash(&hnbp->id));

	if (g_hnbgw->nft_kpi.active)
		nft_kpi_hnb_persistent_add(hnbp);

	/* Normally the disconnected timer runs only when the hNodeB is not currently connected on Iuh. This here is paranoia:
	 * In case we have to HNBAP HNB Register Reject, the disconnected timer should be active on this unused hnbp.
	 * On success, hnb_persistent_registered() will stop the disconnected timer directly after this. */
	hnb_persistent_disconnected_timeout_schedule(hnbp);

	return hnbp;

out_free_ctrs:
	rate_ctr_group_free(hnbp->ctrs);
out_free:
	talloc_free(hnbp);
	return NULL;
}

struct hnb_persistent *hnb_persistent_find_by_id(const struct umts_cell_id *id)
{
	struct hnb_persistent *hnbp;
	uint32_t id_hash = umts_cell_id_hash(id);
	hash_for_each_possible(g_hnbgw->hnb_persistent_by_id, hnbp, node_by_id, id_hash) {
		if (umts_cell_id_equal(&hnbp->id, id))
			return hnbp;
	}
	return NULL;
}

/* Read the peer's remote IP address from the Iuh conn's fd, and set up GTP-U counters for that remote address. */
static void hnb_persistent_update_remote_addr(struct hnb_persistent *hnbp)
{
	socklen_t socklen;
	struct osmo_sockaddr osa;
	struct osmo_sockaddr_str remote_str;
	int fd;

	fd = osmo_stream_srv_get_fd(hnbp->ctx->conn);
	if (fd < 0) {
		LOG_HNBP(hnbp, LOGL_ERROR, "no active socket fd, cannot set up traffic counters\n");
		return;
	}

	socklen = sizeof(struct osmo_sockaddr);
	if (getpeername(fd, &osa.u.sa, &socklen)) {
		LOG_HNBP(hnbp, LOGL_ERROR, "cannot read remote address, cannot set up traffic counters\n");
		return;
	}
	if (osmo_sockaddr_str_from_osa(&remote_str, &osa)) {
		LOG_HNBP(hnbp, LOGL_ERROR, "cannot parse remote address, cannot set up traffic counters\n");
		return;
	}

	/* We got the remote address from the Iuh link (RUA), and now we are blatantly assuming that the hNodeB has its
	 * GTP endpoint on the same IP address, just with UDP port 2152 (the fixed GTP port as per 3GPP spec). */
	remote_str.port = 2152;

	if (nft_kpi_hnb_start(hnbp, &remote_str))
		LOG_HNBP(hnbp, LOGL_ERROR, "failed to set up traffic counters\n");
}

/* Whenever HNBAP registers a HNB, hnbgw_hnbap.c calls this function to let the hnb_persistent update its state to the
 * (new) remote address being active. When calling this function, a hnbp->ctx should be present, with an active
 * osmo_stream_srv conn. */
void hnb_persistent_registered(struct hnb_persistent *hnbp)
{
	if (!hnbp->ctx) {
		LOG_HNBP(hnbp, LOGL_ERROR, "hnb_persistent_registered() invoked, but there is no hnb_ctx\n");
		return;
	}

	/* The hNodeB is now connected, i.e. not disconnected. */
	osmo_timer_del(&hnbp->disconnected_timeout);

	/* start counting traffic */
	if (g_hnbgw->nft_kpi.active)
		hnb_persistent_update_remote_addr(hnbp);
}

/* Whenever a HNB is regarded as no longer registered (HNBAP HNB De-Register, or the Iuh link drops), this function is
 * called to to let the hnb_persistent update its state to the hNodeB being disconnected. Clear the ctx->persistent and
 * hnbp->ctx relations; do not delete the hnb_persistent instance. */
void hnb_persistent_deregistered(struct hnb_persistent *hnbp)
{
	/* clear out cross references of hnb_context and hnb_persistent */
	if (hnbp->ctx) {
		if (hnbp->ctx->persistent == hnbp)
			hnbp->ctx->persistent = NULL;
		hnbp->ctx = NULL;
	}

	/* stop counting traffic */
	nft_kpi_hnb_stop(hnbp);

	/* The hNodeB is now disconnected. Clear out hnb_persistent when the disconnected timeout has passed. */
	hnb_persistent_disconnected_timeout_schedule(hnbp);
}

void hnb_persistent_free(struct hnb_persistent *hnbp)
{
	/* FIXME: check if in use? */
	osmo_timer_del(&hnbp->disconnected_timeout);
	nft_kpi_hnb_stop(hnbp);
	nft_kpi_hnb_persistent_remove(hnbp);
	osmo_stat_item_group_free(hnbp->statg);
	rate_ctr_group_free(hnbp->ctrs);
	llist_del(&hnbp->list);
	hash_del(&hnbp->node_by_id);
	talloc_free(hnbp);
}

/* return the amount of time the HNB is up (hnbp->ctx != NULL) or down (hnbp->ctx == NULL) */
unsigned long long hnbp_get_updowntime(const struct hnb_persistent *hnbp)
{
	struct timespec tp;

	if (!hnbp->updowntime)
		return 0;

	if (osmo_clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		return 0;

	return difftime(tp.tv_sec, hnbp->updowntime);
}
