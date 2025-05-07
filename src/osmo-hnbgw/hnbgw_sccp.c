/* hnb-gw specific code for SCCP, ITU Q.711 - Q.714 */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/protocol/sua.h>

#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/hnbgw_ranap.h>

/***********************************************************************
 * Incoming primitives from SCCP User SAP
 ***********************************************************************/

static bool cnlink_matches(const struct hnbgw_cnlink *cnlink, const struct hnbgw_sccp_user *hsu, const struct osmo_sccp_addr *remote_addr)
{
	if (cnlink->hnbgw_sccp_user != hsu)
		return false;
	if (osmo_sccp_addr_cmp(&cnlink->remote_addr, remote_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
		return false;
	return true;
}

static struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_user *hsu,
					       const struct osmo_sccp_addr *remote_addr)
{
	struct hnbgw_cnlink *cnlink;
	llist_for_each_entry(cnlink, &g_hnbgw->sccp.cnpool_iucs.cnlinks, entry) {
		if (cnlink_matches(cnlink, hsu, remote_addr))
			return cnlink;
	}
	llist_for_each_entry(cnlink, &g_hnbgw->sccp.cnpool_iups.cnlinks, entry) {
		if (cnlink_matches(cnlink, hsu, remote_addr))
			return cnlink;
	}
	return NULL;
}

static struct hnbgw_cnlink *cnlink_from_addr(struct hnbgw_sccp_user *hsu, const struct osmo_sccp_addr *calling_addr,
					     const struct osmo_prim_hdr *oph)
{
	struct hnbgw_cnlink *cnlink = NULL;
	cnlink = hnbgw_cnlink_find_by_addr(hsu, calling_addr);
	if (!cnlink) {
		LOG_HSU(hsu, DRANAP, LOGL_ERROR, "Rx from unknown SCCP peer: %s: %s\n",
			osmo_sccp_inst_addr_name(osmo_ss7_get_sccp(hsu->ss7), calling_addr),
			osmo_scu_prim_hdr_name_c(OTC_SELECT, oph));
		return NULL;
	}
	return cnlink;
}

static struct hnbgw_context_map *map_from_conn_id(struct hnbgw_sccp_user *hsu, uint32_t conn_id,
						  const struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;
	hash_for_each_possible(hsu->hnbgw_context_map_by_conn_id, map, hnbgw_sccp_user_entry, conn_id) {
		if (map->scu_conn_id == conn_id)
			return map;
	}
	LOGP(DRANAP, LOGL_ERROR, "Rx for unknown SCCP connection ID: %u: %s\n",
	     conn_id, osmo_scu_prim_hdr_name_c(OTC_SELECT, oph));
	return NULL;
}

static int handle_cn_unitdata(struct hnbgw_sccp_user *hsu,
			      const struct osmo_scu_unitdata_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_cnlink *cnlink = cnlink_from_addr(hsu, &param->calling_addr, oph);
	if (!cnlink)
		return -ENOENT;

	if (param->called_addr.ssn != OSMO_SCCP_SSN_RANAP) {
		LOGP(DCN, LOGL_NOTICE, "N-UNITDATA.ind for unknown SSN %u\n",
			param->called_addr.ssn);
		return -1;
	}

	return hnbgw_ranap_rx_udt_dl(cnlink, param, msgb_l2(oph->msg), msgb_l2len(oph->msg));
}

static int handle_cn_conn_conf(struct hnbgw_sccp_user *hsu,
			       const struct osmo_scu_connect_param *param,
			       struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	map = map_from_conn_id(hsu, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	LOGP(DCN, LOGL_DEBUG, "handle_cn_conn_conf() conn_id=%d, addrs: called=%s calling=%s responding=%s\n",
	     param->conn_id,
	     cnlink_sccp_addr_to_str(map->cnlink, &param->called_addr),
	     cnlink_sccp_addr_to_str(map->cnlink, &param->calling_addr),
	     cnlink_sccp_addr_to_str(map->cnlink, &param->responding_addr));

	map_sccp_dispatch(map, MAP_SCCP_EV_RX_CONNECTION_CONFIRM, oph->msg);
	return 0;
}

static int handle_cn_data_ind(struct hnbgw_sccp_user *hsu,
			      const struct osmo_scu_data_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	map = map_from_conn_id(hsu, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_DATA_INDICATION, oph->msg);
}

static int handle_cn_disc_ind(struct hnbgw_sccp_user *hsu,
			      const struct osmo_scu_disconn_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;
	char cause_buf[128];

	map = map_from_conn_id(hsu, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	LOGP(DCN, LOGL_DEBUG, "handle_cn_disc_ind() conn_id=%u responding_addr=%s cause=%s\n",
	     param->conn_id,
	     cnlink_sccp_addr_to_str(map->cnlink, &param->responding_addr),
	     osmo_sua_sccp_cause_name(param->cause, cause_buf, sizeof(cause_buf)));

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_RELEASED, oph->msg);
}

static struct hnbgw_cnlink *_cnlink_find_by_remote_pc(struct hnbgw_cnpool *cnpool, struct osmo_ss7_instance *cs7, uint32_t pc)
{
	struct hnbgw_cnlink *cnlink;
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		if (!cnlink->hnbgw_sccp_user)
			continue;
		if (cnlink->hnbgw_sccp_user->ss7 != cs7)
			continue;
		if ((cnlink->remote_addr.presence & OSMO_SCCP_ADDR_T_PC) == 0)
			continue;
		if (cnlink->remote_addr.pc != pc)
			continue;
		return cnlink;
	}
	return NULL;
}

/* Find a cnlink by its remote sigtran point code on a given cs7 instance. */
static struct hnbgw_cnlink *cnlink_find_by_remote_pc(struct osmo_ss7_instance *cs7, uint32_t pc)
{
	struct hnbgw_cnlink *cnlink;
	cnlink = _cnlink_find_by_remote_pc(&g_hnbgw->sccp.cnpool_iucs, cs7, pc);
	if (!cnlink)
		cnlink = _cnlink_find_by_remote_pc(&g_hnbgw->sccp.cnpool_iups, cs7, pc);
	return cnlink;
}

static void handle_pcstate_ind(struct hnbgw_sccp_user *hsu, const struct osmo_scu_pcstate_param *pcst)
{
	struct hnbgw_cnlink *cnlink;
	bool connected;
	bool disconnected;
	struct osmo_ss7_instance *cs7 = hsu->ss7;

	LOGP(DCN, LOGL_DEBUG, "N-PCSTATE ind: affected_pc=%u sp_status=%s remote_sccp_status=%s\n",
	     pcst->affected_pc, osmo_sccp_sp_status_name(pcst->sp_status),
	     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));

	/* If we don't care about that point-code, ignore PCSTATE. */
	cnlink = cnlink_find_by_remote_pc(cs7, pcst->affected_pc);
	if (!cnlink)
		return;

	/* See if this marks the point code to have become available, or to have been lost.
	 *
	 * I want to detect two events:
	 * - connection event (both indicators say PC is reachable).
	 * - disconnection event (at least one indicator says the PC is not reachable).
	 *
	 * There are two separate incoming indicators with various possible values -- the incoming events can be:
	 *
	 * - neither connection nor disconnection indicated -- just indicating congestion
	 *   connected == false, disconnected == false --> do nothing.
	 * - both incoming values indicate that we are connected
	 *   --> trigger connected
	 * - both indicate we are disconnected
	 *   --> trigger disconnected
	 * - one value indicates 'connected', the other indicates 'disconnected'
	 *   --> trigger disconnected
	 *
	 * Congestion could imply that we're connected, but it does not indicate that a PC's reachability changed, so no need to
	 * trigger on that.
	 */
	connected = false;
	disconnected = false;

	switch (pcst->sp_status) {
	case OSMO_SCCP_SP_S_ACCESSIBLE:
		connected = true;
		break;
	case OSMO_SCCP_SP_S_INACCESSIBLE:
		disconnected = true;
		break;
	default:
	case OSMO_SCCP_SP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	switch (pcst->remote_sccp_status) {
	case OSMO_SCCP_REM_SCCP_S_AVAILABLE:
		if (!disconnected)
			connected = true;
		break;
	case OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN:
	case OSMO_SCCP_REM_SCCP_S_UNEQUIPPED:
	case OSMO_SCCP_REM_SCCP_S_INACCESSIBLE:
		disconnected = true;
		connected = false;
		break;
	default:
	case OSMO_SCCP_REM_SCCP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	if (disconnected && cnlink_is_conn_ready(cnlink)) {
		LOG_CNLINK(cnlink, DCN, LOGL_NOTICE,
			   "now unreachable: N-PCSTATE ind: pc=%u sp_status=%s remote_sccp_status=%s\n",
			   pcst->affected_pc,
			   osmo_sccp_sp_status_name(pcst->sp_status),
			   osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
		/* A previously usable cnlink has disconnected. Kick it back to DISC state. */
		cnlink_set_disconnected(cnlink);
	} else if (connected && !cnlink_is_conn_ready(cnlink)) {
		LOG_CNLINK(cnlink, DCN, LOGL_NOTICE,
			   "now available: N-PCSTATE ind: pc=%u sp_status=%s remote_sccp_status=%s\n",
			   pcst->affected_pc,
			   osmo_sccp_sp_status_name(pcst->sp_status),
			   osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
		/* A previously unusable cnlink has become reachable. Trigger immediate RANAP RESET -- we would resend a
		 * RESET either way, but we might as well do it now to speed up connecting. */
		cnlink_resend_reset(cnlink);
	}
}

/* Entry point for primitives coming up from SCCP User SAP.
 * Ownership of oph->msg is transferred to us. */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_sccp_user *scu = ctx;
	struct hnbgw_sccp_user *hsu;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	int rc = 0;

	LOGP(DCN, LOGL_DEBUG, "sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	if (!scu) {
		LOGP(DCN, LOGL_ERROR,
		     "sccp_sap_up(): NULL osmo_sccp_user, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	hsu = osmo_sccp_user_get_priv(scu);
	if (!hsu) {
		LOGP(DCN, LOGL_ERROR,
		     "sccp_sap_up(): NULL hnbgw_sccp_user, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	talloc_steal(OTC_SELECT, oph->msg);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		rc = handle_cn_unitdata(hsu, &prim->u.unitdata, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		rc = handle_cn_conn_conf(hsu, &prim->u.connect, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		rc = handle_cn_data_ind(hsu, &prim->u.data, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		rc = handle_cn_disc_ind(hsu, &prim->u.disconnect, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_PCSTATE, PRIM_OP_INDICATION):
		handle_pcstate_ind(hsu, &prim->u.pcstate);
		break;

	default:
		LOGP(DCN, LOGL_ERROR,
			"Received unknown prim %u from SCCP USER SAP\n",
			OSMO_PRIM_HDR(oph));
		break;
	}

	return rc;
}

static int hnbgw_sccp_user_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct hnbgw_sccp_user *hsu = e->use_count->talloc_object;
	int32_t total;
	int level;

	if (!e->use)
		return -EINVAL;

	total = osmo_use_count_total(&hsu->use_count);

	if (total == 0
	    || (total == 1 && old_use_count == 0 && e->count == 1))
		level = LOGL_INFO;
	else
		level = LOGL_DEBUG;

	LOGPSRC(DCN, level, file, line,
		"%s: %s %s: now used by %s\n",
		hsu->name,
		(e->count - old_use_count) > 0 ? "+" : "-",
		e->use,
		osmo_use_count_to_str_c(OTC_SELECT, &hsu->use_count));

	if (e->count < 0)
		return -ERANGE;

	if (total == 0)
		talloc_free(hsu);
	return 0;
}

static int hnbgw_sccp_user_talloc_destructor(struct hnbgw_sccp_user *hsu)
{
	if (hsu->sccp_user) {
		osmo_sccp_user_unbind(hsu->sccp_user);
		hsu->sccp_user = NULL;
	}
	llist_del(&hsu->entry);
	return 0;
}

struct hnbgw_sccp_user *hnbgw_sccp_user_alloc(int ss7_id)
{
	struct osmo_sccp_instance *sccp;
	uint32_t local_pc;
	struct hnbgw_sccp_user *hsu;

	hsu = talloc_zero(g_hnbgw, struct hnbgw_sccp_user);
	OSMO_ASSERT(hsu);
	*hsu = (struct hnbgw_sccp_user){
		.name = talloc_asprintf(hsu, "cs7-%u-sccp-OsmoHNBGW", ss7_id),
		.use_count = {
			.talloc_object = hsu,
			.use_cb = hnbgw_sccp_user_use_cb,
		},
	};
	hash_init(hsu->hnbgw_context_map_by_conn_id);
	llist_add_tail(&hsu->entry, &g_hnbgw->sccp.users);
	talloc_set_destructor(hsu, hnbgw_sccp_user_talloc_destructor);

	sccp = osmo_sccp_simple_client_on_ss7_id(g_hnbgw,
						 ss7_id,
						 hsu->name,
						 DEFAULT_PC_HNBGW,
						 OSMO_SS7_ASP_PROT_M3UA,
						 0,
						 "localhost",
						 -1,
						 "localhost");
	if (!sccp) {
		LOG_HSU(hsu, DCN, LOGL_ERROR, "Failed to configure SCCP on 'cs7 instance %u'\n",
			ss7_id);
		goto free_hsu_ret;
	}
	hsu->ss7 = osmo_sccp_get_ss7(sccp);
	LOG_HSU(hsu, DCN, LOGL_NOTICE, "created SCCP instance on cs7 instance %u\n", osmo_ss7_instance_get_id(hsu->ss7));

	/* Bind the SCCP user, using the cs7 instance's default point-code if one is configured, or osmo-hnbgw's default
	 * local PC. */
	local_pc = osmo_ss7_instance_get_primary_pc(hsu->ss7);
	if (!osmo_ss7_pc_is_valid(local_pc))
		local_pc = DEFAULT_PC_HNBGW;

	LOG_HSU(hsu, DCN, LOGL_DEBUG, "binding OsmoHNBGW user to cs7 instance %u, local PC %u = %s\n",
		osmo_ss7_instance_get_id(hsu->ss7), local_pc, osmo_ss7_pointcode_print(hsu->ss7, local_pc));

	char *sccp_user_name = talloc_asprintf(hsu, "%s-RANAP", hsu->name);
	hsu->sccp_user = osmo_sccp_user_bind_pc(sccp, sccp_user_name, sccp_sap_up, OSMO_SCCP_SSN_RANAP, local_pc);
	talloc_free(sccp_user_name);
	if (!hsu->sccp_user) {
		LOG_HSU(hsu, DCN, LOGL_ERROR, "Failed to init SCCP User\n");
		goto free_hsu_ret;
	}

	osmo_sccp_make_addr_pc_ssn(&hsu->local_addr, local_pc, OSMO_SCCP_SSN_RANAP);
	osmo_sccp_user_set_priv(hsu->sccp_user, hsu);

	return hsu;

free_hsu_ret:
	talloc_free(hsu);
	return NULL;
}

