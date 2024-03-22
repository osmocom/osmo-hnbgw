/* kitchen sink for OsmoHNBGW implementation */

/* (C) 2015,2024 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>

#include <osmocom/vty/vty.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/netif/stream.h>

#include "config.h"
#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_proto.h>
#endif

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_hnbap.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/mgw_fsm.h>

struct hnbgw *g_hnbgw = NULL;

const struct value_string ranap_domain_names[] = {
	{ DOMAIN_CS, "CS" },
	{ DOMAIN_PS, "PS" },
	{}
};

/* update the active RAB duration rate_ctr for given HNB */
static void hnb_store_rab_durations(struct hnb_context *hnb)
{
	struct hnbgw_context_map *map;
	struct timespec now;
	uint64_t elapsed_cs_rab_ms = 0;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	/* iterate over all context_maps (subscribers) */
	llist_for_each_entry(map, &hnb->map_list, hnb_list) {
		/* skip any PS maps, we care about CS RABs only here */
		if (map->is_ps)
			continue;
		elapsed_cs_rab_ms += mgw_fsm_get_elapsed_ms(map, &now);
	}

	/* Export to rate countes. */
	rate_ctr_add(HNBP_CTR(hnb->persistent, HNB_CTR_RAB_ACTIVE_MILLISECONDS_TOTAL), elapsed_cs_rab_ms);
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

struct ue_context *ue_context_by_id(uint32_t id)
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		if (ue->context_id == id)
			return ue;
	}
	return NULL;

}

struct ue_context *ue_context_by_imsi(const char *imsi)
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		if (!strcmp(ue->imsi, imsi))
			return ue;
	}
	return NULL;
}

struct ue_context *ue_context_by_tmsi(uint32_t tmsi)
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		if (ue->tmsi == tmsi)
			return ue;
	}
	return NULL;
}

static void ue_context_free_by_hnb(const struct hnb_context *hnb)
{
	struct ue_context *ue, *tmp;

	llist_for_each_entry_safe(ue, tmp, &g_hnbgw->ue_list, list) {
		if (ue->hnb == hnb)
			ue_context_free(ue);
	}
}

static uint32_t get_next_ue_ctx_id(void)
{
	uint32_t id;

	do {
		id = g_hnbgw->next_ue_ctx_id++;
	} while (ue_context_by_id(id));

	return id;
}

struct ue_context *ue_context_alloc(struct hnb_context *hnb, const char *imsi,
				    uint32_t tmsi)
{
	struct ue_context *ue;

	ue = talloc_zero(g_hnbgw, struct ue_context);
	if (!ue)
		return NULL;

	ue->hnb = hnb;
	if (imsi)
		OSMO_STRLCPY_ARRAY(ue->imsi, imsi);
	else
		ue->imsi[0] = '\0';
	ue->tmsi = tmsi;
	ue->context_id = get_next_ue_ctx_id();
	llist_add_tail(&ue->list, &g_hnbgw->ue_list);

	LOGP(DHNBAP, LOGL_INFO, "created UE context: id 0x%x, imsi %s, tmsi 0x%x\n",
	     ue->context_id, imsi? imsi : "-", tmsi);

	return ue;
}

void ue_context_free(struct ue_context *ue)
{
	llist_del(&ue->list);
	talloc_free(ue);
}


/***********************************************************************
 * HNB Context
 ***********************************************************************/

/* look-up HNB context by id. Used from CTRL */
static struct hnb_context *hnb_context_by_id(uint32_t cid)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (hnb->id.cid == cid)
			return hnb;
	}

	return NULL;
}

/* look-up HNB context by identity_info. Used from VTY */
struct hnb_context *hnb_context_by_identity_info(const char *identity_info)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (strcmp(identity_info, hnb->identity_info) == 0)
			return hnb;
	}

	return NULL;
}

static int hnb_read_cb(struct osmo_stream_srv *conn);
static int hnb_closed_cb(struct osmo_stream_srv *conn);

static struct hnb_context *hnb_context_alloc(struct osmo_stream_srv_link *link, int new_fd)
{
	struct hnb_context *ctx;

	ctx = talloc_zero(g_hnbgw, struct hnb_context);
	if (!ctx)
		return NULL;
	INIT_LLIST_HEAD(&ctx->map_list);

	ctx->conn = osmo_stream_srv_create(g_hnbgw, link, new_fd, hnb_read_cb, hnb_closed_cb, ctx);
	if (!ctx->conn) {
		LOGP(DMAIN, LOGL_INFO, "error while creating connection\n");
		talloc_free(ctx);
		return NULL;
	}

	llist_add_tail(&ctx->list, &g_hnbgw->hnb_list);
	return ctx;
}

const char *umts_cell_id_name(const struct umts_cell_id *ucid)
{
	const char *fmtstr = "%03u-%02u-L%u-R%u-S%u-C%u";

	if (g_hnbgw->config.plmn.mnc_3_digits)
		fmtstr = "%03u-%03u-L%u-R%u-S%u-C%u";

	return talloc_asprintf(OTC_SELECT, fmtstr, ucid->mcc, ucid->mnc, ucid->lac, ucid->rac,
			       ucid->sac, ucid->cid);
}

/* parse a string representation of an umts_cell_id into its decoded representation */
int umts_cell_id_from_str(struct umts_cell_id *ucid, const char *instr)
{
	int rc = sscanf(instr, "%hu-%hu-L%hu-R%hu-S%hu-C%u", &ucid->mcc, &ucid->mnc, &ucid->lac, &ucid->rac, &ucid->sac, &ucid->cid);
	if (rc < 0)
		return -errno;

	if (rc != 6)
		return -EINVAL;

	if (ucid->mcc > 999)
		return -EINVAL;

	if (ucid->mnc > 999)
		return -EINVAL;

	if (ucid->lac == 0 || ucid->lac == 0xffff)
		return -EINVAL;

	/* CellIdentity in the ASN.1 syntax is a bit-string of 28 bits length */
	if (ucid->cid >= (1 << 28))
		return -EINVAL;

	return 0;
}

const char *hnb_context_name(struct hnb_context *ctx)
{
	char *result;
	if (!ctx)
		return "NULL";

	if (ctx->conn) {
		char hostbuf_r[INET6_ADDRSTRLEN];
		char portbuf_r[6];
		int fd = osmo_stream_srv_get_ofd(ctx->conn)->fd;

		/* get remote addr */
		if (osmo_sock_get_ip_and_port(fd, hostbuf_r, sizeof(hostbuf_r), portbuf_r, sizeof(portbuf_r), false) == 0)
			result = talloc_asprintf(OTC_SELECT, "%s:%s", hostbuf_r, portbuf_r);
		else
			result = "?";
	} else {
		result = "disconnected";
	}

	if (g_hnbgw->config.log_prefix_hnb_id)
		result = talloc_asprintf(OTC_SELECT, "%s %s", result, ctx->identity_info);
	else
		result = talloc_asprintf(OTC_SELECT, "%s %s", result, umts_cell_id_name(&ctx->id));
	return result;
}

void hnb_context_release_ue_state(struct hnb_context *ctx)
{
	struct hnbgw_context_map *map, *map2;

	/* deactivate all context maps */
	llist_for_each_entry_safe(map, map2, &ctx->map_list, hnb_list) {
		context_map_hnb_released(map);
		/* hnbgw_context_map will remove itself from lists when it is ready. */
	}
	ue_context_free_by_hnb(ctx);
}

void hnb_context_release(struct hnb_context *ctx)
{
	struct hnbgw_context_map *map;

	LOGHNB(ctx, DMAIN, LOGL_INFO, "Releasing HNB context\n");

	if (ctx->persistent) {
		struct timespec tp;
		int rc;
		rc = osmo_clock_gettime(CLOCK_MONOTONIC, &tp);
		ctx->persistent->updowntime = (rc < 0) ? 0 : tp.tv_sec;
	}

	/* remove from the list of HNB contexts */
	llist_del(&ctx->list);

	hnb_context_release_ue_state(ctx);

	if (ctx->conn) { /* we own a conn, we must free it: */
		LOGHNB(ctx, DMAIN, LOGL_INFO, "Closing HNB SCTP connection %s\n",
		     osmo_sock_get_name2(osmo_stream_srv_get_ofd(ctx->conn)->fd));
		/* Avoid our closed_cb calling hnb_context_release() again: */
		osmo_stream_srv_set_data(ctx->conn, NULL);
		osmo_stream_srv_destroy(ctx->conn);
	} /* else: we are called from closed_cb, so conn is being freed separately */

	/* hnbgw_context_map are still listed in ctx->map_list, but we are freeing ctx. Remove all entries from the
	 * list, but keep the hnbgw_context_map around for graceful release. They are also listed under
	 * hnbgw_cnlink->map_list, and will remove themselves when ready. */
	while ((map = llist_first_entry_or_null(&ctx->map_list, struct hnbgw_context_map, hnb_list))) {
		llist_del(&map->hnb_list);
		map->hnb_ctx = NULL;
	}

	/* remove back reference from hnb_persistent to context */
	if (ctx->persistent)
		hnb_persistent_deregistered(ctx->persistent);

	talloc_free(ctx);
}

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

	[HNB_CTR_RANAP_PS_RAB_ACT_CNF] = {
		"ranap:ps:rab_act:cnf", "PS RAB Activations confirmed" },
	[HNB_CTR_RANAP_CS_RAB_ACT_CNF] = {
		"ranap:cs:rab_act:cnf", "CS RAB Activations confirmed" },

	[HNB_CTR_RANAP_PS_RAB_ACT_FAIL] = {
		"ranap:ps:rab_act:fail", "PS RAB Activations failed" },
	[HNB_CTR_RANAP_CS_RAB_ACT_FAIL] = {
		"ranap:cs:rab_act:fail", "CS RAB Activations failed" },


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

	[HNB_CTR_RANAP_PS_RAB_REL_CNF] = {
		"ranap:ps:rab_rel:cnf", "PS RAB Release confirmed" },
	[HNB_CTR_RANAP_CS_RAB_REL_CNF] = {
		"ranap:cs:rab_rel:cnf", "CS RAB Release confirmed" },

	[HNB_CTR_RANAP_PS_RAB_REL_FAIL] = {
		"ranap:ps:rab_rel:fail", "PS RAB Release failed" },
	[HNB_CTR_RANAP_CS_RAB_REL_FAIL] = {
		"ranap:cs:rab_rel:fail", "CS RAB Release failed" },

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

struct hnb_persistent *hnb_persistent_alloc(const struct umts_cell_id *id)
{
	struct hnb_persistent *hnbp = talloc_zero(g_hnbgw, struct hnb_persistent);
	if (!hnbp)
		return NULL;

	hnbp->id = *id;
	hnbp->id_str = talloc_strdup(hnbp, umts_cell_id_name(id));
	hnbp->ctrs = rate_ctr_group_alloc(hnbp, &hnb_ctrg_desc, 0);
	if (!hnbp->ctrs)
		goto out_free;
	rate_ctr_group_set_name(hnbp->ctrs, hnbp->id_str);
	hnbp->statg = osmo_stat_item_group_alloc(hnbp, &hnb_statg_desc, 0);
	if (!hnbp->statg)
		goto out_free_ctrs;
	osmo_stat_item_group_set_name(hnbp->statg, hnbp->id_str);

	llist_add(&hnbp->list, &g_hnbgw->hnb_persistent_list);

	if (g_hnbgw->nft_kpi.active)
		nft_kpi_hnb_persistent_add(hnbp);

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

	llist_for_each_entry(hnbp, &g_hnbgw->hnb_persistent_list, list) {
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
		LOGP(DHNB, LOGL_ERROR, "%s: no active socket fd, cannot set up traffic counters\n", hnbp->id_str);
		return;
	}

	socklen = sizeof(struct osmo_sockaddr);
	if (getpeername(fd, &osa.u.sa, &socklen)) {
		LOGP(DHNB, LOGL_ERROR, "%s: cannot read remote address, cannot set up traffic counters\n",
		     hnbp->id_str);
		return;
	}
	if (osmo_sockaddr_str_from_osa(&remote_str, &osa)) {
		LOGP(DHNB, LOGL_ERROR, "%s: cannot parse remote address, cannot set up traffic counters\n",
		     hnbp->id_str);
		return;
	}

	/* We got the remote address from the Iuh link (RUA), and now we are blatantly assuming that the hNodeB has its
	 * GTP endpoint on the same IP address, just with UDP port 2152 (the fixed GTP port as per 3GPP spec). */
	remote_str.port = 2152;

	if (nft_kpi_hnb_start(hnbp, &remote_str))
		LOGP(DHNB, LOGL_ERROR, "%s: failed to set up traffic counters\n", hnbp->id_str);
}

/* Whenever HNBAP registers a HNB, hnbgw_hnbap.c calls this function to let the hnb_persistent update its state to the
 * (new) remote address being active. When calling this function, a hnbp->ctx should be present, with an active
 * osmo_stream_srv conn. */
void hnb_persistent_registered(struct hnb_persistent *hnbp)
{
	if (!hnbp->ctx) {
		LOGP(DHNB, LOGL_ERROR, "hnb_persistent_registered() invoked, but there is no hnb_ctx\n");
		return;
	}

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
}

void hnb_persistent_free(struct hnb_persistent *hnbp)
{
	/* FIXME: check if in use? */
	nft_kpi_hnb_stop(hnbp);
	nft_kpi_hnb_persistent_remove(hnbp);
	rate_ctr_group_free(hnbp->ctrs);
	llist_del(&hnbp->list);
	talloc_free(hnbp);
}

/* return the amount of time the HNB is up (hnbp->ctx != NULL) or down (hnbp->ctx == NULL) */
static unsigned long long hnbp_get_updowntime(const struct hnb_persistent *hnbp)
{
	struct timespec tp;

	if (!hnbp->updowntime)
		return 0;

	if (osmo_clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		return 0;

	return difftime(tp.tv_sec, hnbp->updowntime);
}

unsigned long long hnb_get_updowntime(const struct hnb_context *ctx)
{
	if (!ctx->persistent)
		return 0;
	return hnbp_get_updowntime(ctx->persistent);
}

/* timer call-back: Update the HNB_STAT_UPTIME_SECONDS stat item of each hnb_persistent */
static void hnbgw_store_hnb_uptime(void *data)
{
	struct hnb_persistent *hnbp;

	llist_for_each_entry(hnbp, &g_hnbgw->hnb_persistent_list, list) {
		HNBP_STAT_SET(hnbp, HNB_STAT_UPTIME_SECONDS, hnbp->ctx != NULL ? hnbp_get_updowntime(hnbp) : 0);
	}

	osmo_timer_schedule(&g_hnbgw->store_uptime_timer, STORE_UPTIME_INTERVAL, 0);
}

/***********************************************************************
 * SCTP Socket / stream handling
 ***********************************************************************/

static int hnb_read_cb(struct osmo_stream_srv *conn)
{
	struct hnb_context *hnb = osmo_stream_srv_get_data(conn);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct msgb *msg = msgb_alloc(IUH_MSGB_SIZE, "Iuh rx");
	int rc;

	if (!msg)
		return -ENOMEM;

	OSMO_ASSERT(hnb);
	/* we store a reference to the HomeNodeB in the msg->dest for the
	 * benefit of various downstream processing functions */
	msg->dst = hnb;

	rc = osmo_stream_srv_recv(conn, msg);
	/* Notification received */
	if (msgb_sctp_msg_flags(msg) & OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *)msgb_data(msg);
		rc = 0;
		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_LOST:
				LOGHNB(hnb, DMAIN, LOGL_NOTICE,
				       "sctp_recvmsg(%s) = SCTP_COMM_LOST, closing conn\n",
				       osmo_sock_get_name2(ofd->fd));
				osmo_stream_srv_destroy(conn);
				rc = -EBADF;
				break;
			case SCTP_RESTART:
				LOGHNB(hnb, DMAIN, LOGL_NOTICE, "HNB SCTP conn RESTARTed, marking as HNBAP-unregistered\n");
				hnb->hnb_registered = false;
				hnb_context_release_ue_state(hnb);
				/* The tx queue may be quite full after an SCTP RESTART: (SYS#6113)
				 * The link may have been flaky (a possible reason for the peer restarting the conn) and
				 * hence the kernel socket Tx queue may be full (no ACKs coming back) and our own userspace
				 * queue may contain plenty of oldish messages to be sent. Since the HNB will re-register after
				 * this, we simply drop all those old messages: */
				osmo_stream_srv_clear_tx_queue(conn);
				break;
			}
			break;
		case SCTP_SHUTDOWN_EVENT:
			LOGHNB(hnb, DMAIN, LOGL_NOTICE,
			       "sctp_recvmsg(%s) = SCTP_SHUTDOWN_EVENT, closing conn\n",
			       osmo_sock_get_name2(ofd->fd));
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
			break;
		}
		goto out;
	} else if (rc == -EAGAIN) {
		/* Older versions of osmo_stream_srv_recv() not supporting
		 * msgb_sctp_msg_flags() may still return -EAGAIN when an sctp
		 * notification is received. */
		rc = 0;
		goto out;
	} else if (rc < 0) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Error during sctp_recvmsg(%s)\n",
		       osmo_sock_get_name2(ofd->fd));
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else if (rc == 0) {
		LOGHNB(hnb, DMAIN, LOGL_NOTICE, "Connection closed sctp_recvmsg(%s) = 0\n",
		       osmo_sock_get_name2(ofd->fd));
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else {
		msgb_put(msg, rc);
	}

	switch (msgb_sctp_ppid(msg)) {
	case IUH_PPI_HNBAP:
		hnb->hnbap_stream = msgb_sctp_stream(msg);
		rc = hnbgw_hnbap_rx(hnb, msg);
		break;
	case IUH_PPI_RUA:
		if (!hnb->hnb_registered) {
			LOGHNB(hnb, DMAIN, LOGL_NOTICE, "Discarding RUA as HNB is not registered\n");
			goto out;
		}
		hnb->rua_stream = msgb_sctp_stream(msg);
		rc = hnbgw_rua_rx(hnb, msg);
		break;
	case IUH_PPI_SABP:
	case IUH_PPI_RNA:
	case IUH_PPI_PUA:
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Unimplemented SCTP PPID=%lu received\n", msgb_sctp_ppid(msg));
		rc = 0;
		break;
	default:
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Unknown SCTP PPID=%lu received\n", msgb_sctp_ppid(msg));
		rc = 0;
		break;
	}

out:
	msgb_free(msg);
	return rc;
}

static int hnb_closed_cb(struct osmo_stream_srv *conn)
{
	struct hnb_context *hnb = osmo_stream_srv_get_data(conn);
	if (!hnb)
		return 0; /* hnb_context is being freed, nothing do be done */

	/* hnb: conn became broken, let's release the associated hnb.
	 * conn object is being freed after closed_cb(), so unassign it from hnb
	 * if available to avoid it freeing it again: */
	hnb->conn = NULL;
	hnb_context_release(hnb);

	return 0;
}

/*! call-back when the listen FD has something to read */
int hnbgw_rua_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct hnb_context *ctx;

	LOGP(DMAIN, LOGL_INFO, "New HNB SCTP connection %s\n",
	     osmo_sock_get_name2(fd));

	ctx = hnb_context_alloc(srv, fd);
	if (!ctx)
		return -ENOMEM;

	return 0;
}

CTRL_CMD_DEFINE_RO(hnb_info, "info");
static int get_hnb_info(struct ctrl_cmd *cmd, void *data)
{
	struct hnb_context *hnb = data;

	cmd->reply = talloc_strdup(cmd, hnb->identity_info);

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(hnbs, "num-hnb");
static int get_hnbs(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = talloc_asprintf(cmd, "%u", llist_count(&g_hnbgw->hnb_list));

	return CTRL_CMD_REPLY;
}

int hnb_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_hnbs);
	rc |= ctrl_cmd_install(CTRL_NODE_HNB, &cmd_hnb_info);

	return rc;
}

int hnb_ctrl_node_lookup(void *data, vector vline, int *node_type, void **node_data, int *i)
{
	const char *token = vector_slot(vline, *i);
	struct hnb_context *hnb;
	long num;

	switch (*node_type) {
	case CTRL_NODE_ROOT:
		if (strcmp(token, "hnb") != 0)
			return 0;

		(*i)++;

		if (!ctrl_parse_get_num(vline, *i, &num))
			return -ERANGE;

		hnb = hnb_context_by_id(num);
		if (!hnb)
			return -ENODEV;

		*node_data = hnb;
		*node_type = CTRL_NODE_HNB;
		break;
	default:
		return 0;
	}

	return 1;
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
	g_hnbgw->config.log_prefix_hnb_id = true;
	g_hnbgw->config.accept_all_hnb = true;

	/* Set zero PLMN to detect a missing PLMN when transmitting RESET */
	g_hnbgw->config.plmn = (struct osmo_plmn_id){ 0, 0, false };

	g_hnbgw->next_ue_ctx_id = 23;
	INIT_LLIST_HEAD(&g_hnbgw->hnb_list);
	INIT_LLIST_HEAD(&g_hnbgw->hnb_persistent_list);
	INIT_LLIST_HEAD(&g_hnbgw->ue_list);
	INIT_LLIST_HEAD(&g_hnbgw->sccp.users);

	g_hnbgw->mgw_pool = mgcp_client_pool_alloc(g_hnbgw);
	g_hnbgw->config.mgcp_client = mgcp_client_conf_alloc(g_hnbgw);

#if ENABLE_PFCP
	g_hnbgw->config.pfcp.remote_port = OSMO_PFCP_PORT;
#endif

	g_hnbgw->sccp.cnpool_iucs = (struct hnbgw_cnpool){
		.domain = DOMAIN_CS,
		.pool_name = "iucs",
		.peer_name = "msc",
		.default_remote_pc = DEFAULT_PC_MSC,
		.vty = {
			.nri_bitlen = OSMO_NRI_BITLEN_DEFAULT,
			.null_nri_ranges = osmo_nri_ranges_alloc(g_hnbgw),
		},
		.cnlink_ctrg_desc = &msc_ctrg_desc,

		.ctrs = rate_ctr_group_alloc(g_hnbgw, &iucs_ctrg_desc, 0),
	};
	INIT_LLIST_HEAD(&g_hnbgw->sccp.cnpool_iucs.cnlinks);

	g_hnbgw->sccp.cnpool_iups = (struct hnbgw_cnpool){
		.domain = DOMAIN_PS,
		.pool_name = "iups",
		.peer_name = "sgsn",
		.default_remote_pc = DEFAULT_PC_SGSN,
		.vty = {
			.nri_bitlen = OSMO_NRI_BITLEN_DEFAULT,
			.null_nri_ranges = osmo_nri_ranges_alloc(g_hnbgw),
		},
		.cnlink_ctrg_desc = &sgsn_ctrg_desc,

		.ctrs = rate_ctr_group_alloc(g_hnbgw, &iups_ctrg_desc, 0),
	};
	INIT_LLIST_HEAD(&g_hnbgw->sccp.cnpool_iups.cnlinks);

	osmo_timer_setup(&g_hnbgw->store_uptime_timer, hnbgw_store_hnb_uptime, g_hnbgw);
	osmo_timer_schedule(&g_hnbgw->store_uptime_timer, STORE_UPTIME_INTERVAL, 0);

	osmo_timer_setup(&g_hnbgw->hnb_store_rab_durations_timer, hnbgw_store_hnb_rab_durations, g_hnbgw);
	osmo_timer_schedule(&g_hnbgw->hnb_store_rab_durations_timer, HNB_STORE_RAB_DURATIONS_INTERVAL, 0);
}
