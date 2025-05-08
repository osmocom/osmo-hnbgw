/* (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/stats.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/sigtran/sccp_helpers.h>

#include <asn1c/asn1helpers.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/context_map.h>

static const struct rate_ctr_desc cnlink_ctr_description[] = {
	[CNLINK_CTR_RANAP_RX_UDT_RESET] = {
		"ranap:rx:udt:reset",
		"RANAP Unitdata RESET messages received"
	},
	[CNLINK_CTR_RANAP_RX_UDT_RESET_ACK] = {
		"ranap:rx:udt:reset_ack",
		"RANAP Unitdata RESET ACK messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_PAGING] = {
		"ranap:rx:udt:paging",
		"RANAP Unitdata PAGING messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_UNKNOWN] = {
		"ranap:rx:udt:unknown",
		"Unknown RANAP Unitdata messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_UNSUPPORTED] = {
		"ranap:rx:udt:unsupported",
		"Unsupported RANAP Unitdata messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_OVERLOAD_IND] = {
		"ranap:rx:udt:overload_ind",
		"RANAP Unitdata Overload Indications received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_ERROR_IND] = {
		"ranap:rx:udt:error_ind",
		"RANAP Unitdata Error Indications received",
	},

	[CNLINK_CTR_RANAP_TX_UDT_RESET] = {
		"ranap:tx:udt:reset",
		"RANAP Unitdata RESET messages transmitted",
	},
	[CNLINK_CTR_RANAP_TX_UDT_RESET_ACK] = {
		"ranap:tx:udt:reset_ack",
		"RANAP Unitdata RESET ACK messages transmitted",
	},

	/* SCCP Counters: */
	[CNLINK_CTR_SCCP_N_UNITDATA_REQ] = {
		"sccp:n_unit_data:req",
		"Submit SCCP N-UNITDATA.req (UL)"
	},
	[CNLINK_CTR_SCCP_N_UNITDATA_IND] = {
		"sccp:n_unit_data:ind",
		"Received SCCP N-UNITDATA.ind (DL)"
	},
	[CNLINK_CTR_SCCP_N_CONNECT_REQ] = {
		"sccp:n_connect:req",
		"Submit SCCP N-CONNECT.req (UL SCCP CR)"
	},
	[CNLINK_CTR_SCCP_N_CONNECT_CNF] = {
		"sccp:n_connect:cnf",
		"Received SCCP N-CONNECT.cnf (DL SCCP CC)"
	},
	[CNLINK_CTR_SCCP_N_DATA_REQ] = {
		"sccp:n_data:req",
		"SUBMIT SCCP N-DATA.req (UL)"
	},
	[CNLINK_CTR_SCCP_N_DATA_IND] = {
		"sccp:n_data:ind",
		"Received SCCP N-DATA.ind (DL)"
	},
	[CNLINK_CTR_SCCP_N_DISCONNECT_REQ] = {
		"sccp:n_disconnect:req",
		"Submit SCCP N-DISCONNECT.req (UL SCCP RLC)"
	},
	[CNLINK_CTR_SCCP_N_DISCONNECT_IND] = {
		"sccp:n_disconnect:ind",
		"Received SCCP N-DISCONNECT.ind (DL SCCP RLSD)"
	},
	[CNLINK_CTR_SCCP_N_PCSTATE_IND] = {
		"sccp:n_pcstate:ind",
		"Received SCCP N-PCSTATE.ind"
	},
	[CNLINK_CTR_SCCP_RLSD_CN_ORIGIN] = {
		"sccp:rlsd_cn_origin",
		"Received unexpected SCCP RSLD originated unilaterally by CN"
	},

	/* Indicators for CN pool usage */
	[CNLINK_CTR_CNPOOL_SUBSCR_NEW] = {
		"cnpool:subscr:new",
		"Complete Layer 3 requests assigned to this CN link by round-robin (no NRI was assigned yet).",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_REATTACH] = {
		"cnpool:subscr:reattach",
		"Complete Layer 3 requests assigned to this CN link by round-robin because the subscriber indicates a"
		" NULL-NRI (previously assigned by another CN link).",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_KNOWN] = {
		"cnpool:subscr:known",
		"Complete Layer 3 requests directed to this CN link because the subscriber indicates an NRI of this CN link.",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_PAGED] = {
		"cnpool:subscr:paged",
		"Paging Response directed to this CN link because the subscriber was recently paged by this CN link.",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_ATTACH_LOST] = {
		"cnpool:subscr:attach_lost",
		"A subscriber indicates an NRI value matching this CN link, but the CN link is not connected:"
		" a re-attach to another CN link (if available) was forced, with possible service failure.",
	},
	[CNLINK_CTR_CNPOOL_EMERG_FORWARDED] = {
		"cnpool:emerg:forwarded",
		"Emergency call requests forwarded to this CN link.",
	},
};

static const struct rate_ctr_group_desc msc_ctrg_desc = {
	"msc",
	"MSC",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(cnlink_ctr_description),
	cnlink_ctr_description,
};

static const struct rate_ctr_group_desc sgsn_ctrg_desc = {
	"sgsn",
	"SGSN",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(cnlink_ctr_description),
	cnlink_ctr_description,
};

struct hnbgw_cnlink *hnbgw_cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr)
{
	struct osmo_fsm_inst *fi;
	struct hnbgw_cnlink *cnlink;
	const struct rate_ctr_group_desc *ctrg_desc;

	OSMO_ASSERT(cnpool);
	char *name = talloc_asprintf(OTC_SELECT, "%s-%d", cnpool->peer_name, nr);

	switch (cnpool->domain) {
	case DOMAIN_CS:
		ctrg_desc = &msc_ctrg_desc;
		break;
	case DOMAIN_PS:
		ctrg_desc = &sgsn_ctrg_desc;
		break;
	default:
		OSMO_ASSERT(0);
	}


	fi = osmo_fsm_inst_alloc(&cnlink_fsm, g_hnbgw, NULL, LOGL_DEBUG, name);
	OSMO_ASSERT(fi);
	cnlink = talloc_zero(g_hnbgw, struct hnbgw_cnlink);
	fi->priv = cnlink;

	*cnlink = (struct hnbgw_cnlink){
		.name = name,
		.pool = cnpool,
		.fi = fi,
		.nr = nr,
		.vty = {
			/* VTY config defaults for the new cnlink */
			.nri_ranges = osmo_nri_ranges_alloc(cnlink),
		},
		.allow_attach = true,
		.ctrs = rate_ctr_group_alloc(g_hnbgw, ctrg_desc, nr),
	};
	talloc_steal(cnlink, name);
	INIT_LLIST_HEAD(&cnlink->map_list);
	INIT_LLIST_HEAD(&cnlink->paging);

	llist_add_tail(&cnlink->entry, &cnpool->cnlinks);
	LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "allocated\n");

	cnlink_resend_reset(cnlink);
	return cnlink;
}

void hnbgw_cnlink_drop_sccp(struct hnbgw_cnlink *cnlink)
{
	struct hnbgw_context_map *map, *map2;
	struct hnbgw_sccp_user *hsu;

	llist_for_each_entry_safe(map, map2, &cnlink->map_list, hnbgw_cnlink_entry) {
		map_sccp_dispatch(map, MAP_SCCP_EV_USER_ABORT, NULL);
	}

	OSMO_ASSERT(cnlink->hnbgw_sccp_user);
	hsu = cnlink->hnbgw_sccp_user;
	cnlink->hnbgw_sccp_user = NULL;
	hnbgw_sccp_user_put(hsu, HSU_USE_CNLINK);
}

void hnbgw_cnlink_term_and_free(struct hnbgw_cnlink *cnlink)
{
	if (!cnlink)
		return;
	osmo_fsm_inst_term(cnlink->fi, OSMO_FSM_TERM_REQUEST, NULL);
	if (cnlink->hnbgw_sccp_user)
		hnbgw_cnlink_drop_sccp(cnlink);
	talloc_free(cnlink);
}

static int hnbgw_cnlink_tx_sccp_unitdata_req(struct hnbgw_cnlink *cnlink, struct msgb *msg)
{
	CNLINK_CTR_INC(cnlink, CNLINK_CTR_SCCP_N_UNITDATA_REQ);
	return hnbgw_sccp_user_tx_unitdata_req(cnlink->hnbgw_sccp_user,
					       &cnlink->remote_addr,
					       msg);
}

int hnbgw_cnlink_tx_ranap_reset(struct hnbgw_cnlink *cnlink)
{
	struct msgb *msg;
	RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_transmissionNetwork,
		.choice. transmissionNetwork = RANAP_CauseTransmissionNetwork_signalling_transport_resource_failure,
	};
	RANAP_GlobalRNC_ID_t grnc_id;
	RANAP_GlobalRNC_ID_t *use_grnc_id = NULL;
	uint8_t plmn_buf[3];

	if (!cnlink)
		return -1;

	/* We need to have chosen an SCCP instance, and the remote SCCP address needs to be set.
	 * Only check the remote_addr, allowing use.remote_addr_name to be NULL: if the user has not set an explicit
	 * remote address book entry, auto-configuration may still have chosen a default remote point-code. */
	if (!cnlink->hnbgw_sccp_user
	    || !osmo_sccp_check_addr(&cnlink->remote_addr, OSMO_SCCP_ADDR_T_PC | OSMO_SCCP_ADDR_T_SSN)) {
		LOG_CNLINK(cnlink, DRANAP, LOGL_DEBUG, "not yet configured, not sending RANAP RESET\n");
		return -1;
	}

	LOG_CNLINK(cnlink, DRANAP, LOGL_DEBUG, "Tx RANAP RESET to %s %s\n",
		   cnlink_is_cs(cnlink) ? "IuCS" : "IuPS",
		   hnbgw_cnlink_sccp_addr_to_str(cnlink, &cnlink->remote_addr));

	if (g_hnbgw->config.plmn.mcc) {
		osmo_plmn_to_bcd(plmn_buf, &g_hnbgw->config.plmn);
		grnc_id = (RANAP_GlobalRNC_ID_t){
			.pLMNidentity = {
				.buf = plmn_buf,
				.size = 3,
			},
			.rNC_ID = g_hnbgw->config.rnc_id,
		};
		use_grnc_id = &grnc_id;
	} else {
		/* If no PLMN is configured, omit the Global RNC Id from the RESET message.
		 *
		 * According to 3GPP TS 25.413 8.26.2.2, "The RNC shall include the Global RNC-ID IE in the RESET
		 * message", so it should be considered a mandatory IE when coming from us, the RNC.
		 *
		 * But osmo-hnbgw < v1.5 worked well with osmo-hnbgw.cfg files that have no PLMN configured, and we are
		 * trying to stay backwards compatible for those users. Such a site should still work, but they should
		 * now see these error logs and can adjust the config.
		 */
		LOG_CNLINK(cnlink, DRANAP, LOGL_ERROR,
			   "No local PLMN is configured, so outgoing RESET messages omit the mandatory Global RNC-ID"
			   " IE. You should set a 'hnbgw' / 'plmn' in your config file (since v1.5)\n");
	}

	msg = ranap_new_msg_reset2(cnlink->pool->domain, &cause, use_grnc_id);
	CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_TX_UDT_RESET);
	return hnbgw_cnlink_tx_sccp_unitdata_req(cnlink, msg);
}

int hnbgw_cnlink_tx_ranap_reset_ack(struct hnbgw_cnlink *cnlink)
{
	struct msgb *msg;
	struct osmo_sccp_instance *sccp = hnbgw_cnlink_sccp(cnlink);
	RANAP_GlobalRNC_ID_t grnc_id;
	RANAP_GlobalRNC_ID_t *use_grnc_id = NULL;
	uint8_t plmn_buf[3];

	if (!sccp) {
		LOG_CNLINK(cnlink, DRANAP, LOGL_ERROR, "cannot send RANAP RESET ACK: no CN link\n");
		return -1;
	}

	LOG_CNLINK(cnlink, DRANAP, LOGL_NOTICE, "Tx RANAP RESET ACK %s %s --> %s\n",
		   cnlink_is_cs(cnlink) ? "IuCS" : "IuPS",
		   hnbgw_cnlink_sccp_addr_to_str(cnlink, &cnlink->hnbgw_sccp_user->local_addr),
		   hnbgw_cnlink_sccp_addr_to_str(cnlink, &cnlink->remote_addr));

	if (g_hnbgw->config.plmn.mcc) {
		osmo_plmn_to_bcd(plmn_buf, &g_hnbgw->config.plmn);
		grnc_id = (RANAP_GlobalRNC_ID_t){
			.pLMNidentity = {
				.buf = plmn_buf,
				.size = 3,
			},
			.rNC_ID = g_hnbgw->config.rnc_id,
		};
		use_grnc_id = &grnc_id;
	} else {
		/* If no PLMN is configured, omit the Global RNC Id from the RESET ACK message.
		 *
		 * According to 3GPP TS 25.413 8.26.2.1, "The RNC shall include the Global RNC-ID IE in the RESET
		 * ACKNOWLEDGE message", so it should be considered a mandatory IE when coming from us, the RNC.
		 *
		 * But osmo-hnbgw < v1.5 worked well with osmo-hnbgw.cfg files that have no PLMN configured, and we are
		 * trying to stay backwards compatible for those users. Such a site should still work, but they should
		 * now see these error logs and can adjust the config.
		 */
		LOG_CNLINK(cnlink, DRANAP, LOGL_ERROR,
			   "No local PLMN is configured, so outgoing RESET ACKNOWLEDGE messages omit the mandatory"
			   " Global RNC-ID IE. You should set a 'hnbgw' / 'plmn' in your config file (since v1.5)\n");
	}

	msg = ranap_new_msg_reset_ack(cnlink->pool->domain, use_grnc_id);
	CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_TX_UDT_RESET_ACK);
	return hnbgw_cnlink_tx_sccp_unitdata_req(cnlink, msg);
}
