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
#include <osmocom/core/stat_item.h>

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

static const struct osmo_stat_item_desc cnlink_stat_desc[] = {
	[CNLINK_STAT_CONNECTED] = { "connected", "Connected (1) or disconnected (0)", NULL, 60, 0 },
};

const struct osmo_stat_item_group_desc msc_statg_desc = {
	.group_name_prefix = "msc",
	.group_description = "MSC",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(cnlink_stat_desc),
	.item_desc = cnlink_stat_desc,
};

const struct osmo_stat_item_group_desc sgsn_statg_desc = {
	.group_name_prefix = "sgsn",
	.group_description = "SGSN",
	.class_id = OSMO_STATS_CLASS_GLOBAL,
	.num_items = ARRAY_SIZE(cnlink_stat_desc),
	.item_desc = cnlink_stat_desc,
};

struct hnbgw_cnlink *hnbgw_cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr)
{
	struct hnbgw_cnlink *cnlink;
	const struct rate_ctr_group_desc *ctrg_desc;
	const struct osmo_stat_item_group_desc *statg_desc;

	OSMO_ASSERT(cnpool);

	switch (cnpool->domain) {
	case DOMAIN_CS:
		ctrg_desc = &msc_ctrg_desc;
		statg_desc = &msc_statg_desc;
		break;
	case DOMAIN_PS:
		ctrg_desc = &sgsn_ctrg_desc;
		statg_desc = &sgsn_statg_desc;
		break;
	default:
		OSMO_ASSERT(0);
	}

	cnlink = talloc_zero(cnpool, struct hnbgw_cnlink);
	OSMO_ASSERT(cnlink);
	*cnlink = (struct hnbgw_cnlink){
		.pool = cnpool,
		.nr = nr,
		.vty = {
			/* VTY config defaults for the new cnlink */
			.nri_ranges = osmo_nri_ranges_alloc(cnlink),
		},
		.allow_attach = true,
		.ctrs = rate_ctr_group_alloc(cnlink, ctrg_desc, nr),
		.statg = osmo_stat_item_group_alloc(cnlink, statg_desc, nr),
	};
	cnlink->name = talloc_asprintf(cnlink, "%s-%d", cnpool->peer_name, nr);
	INIT_LLIST_HEAD(&cnlink->map_list);
	INIT_LLIST_HEAD(&cnlink->paging);

	cnlink->fi = osmo_fsm_inst_alloc(&cnlink_fsm, cnlink, cnlink, LOGL_DEBUG, cnlink->name);
	OSMO_ASSERT(cnlink->fi);

	llist_add_tail(&cnlink->entry, &cnpool->cnlinks);
	LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "allocated\n");

	cnlink_resend_reset(cnlink);
	return cnlink;
}

int hnbgw_cnlink_set_name(struct hnbgw_cnlink *cnlink, const char *name)
{
	talloc_free(cnlink->name);
	cnlink->name = talloc_strdup(cnlink, name);
	osmo_fsm_inst_update_id_f_sanitize(cnlink->fi, '-', cnlink->name);
	/* Update rate_ctr/stats to report by name instead of index: */
	rate_ctr_group_set_name(cnlink->ctrs, cnlink->name);
	osmo_stat_item_group_set_name(cnlink->statg, cnlink->name);
	return 0;
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

	if (cnlink->hnbgw_sccp_user)
		hnbgw_cnlink_drop_sccp(cnlink);

	osmo_fsm_inst_term(cnlink->fi, OSMO_FSM_TERM_REQUEST, NULL);
	cnlink->fi = NULL;
	osmo_stat_item_group_free(cnlink->statg);
	rate_ctr_group_free(cnlink->ctrs);
	llist_del(&cnlink->entry);
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

static bool addr_has_pc_and_ssn(const struct osmo_sccp_addr *addr)
{
	if (!(addr->presence & OSMO_SCCP_ADDR_T_SSN))
		return false;
	if (!(addr->presence & OSMO_SCCP_ADDR_T_PC))
		return false;
	return true;
}

static int resolve_addr_name(struct osmo_sccp_addr *dest, struct osmo_ss7_instance **ss7,
			     const char *addr_name, const char *label,
			     uint32_t default_pc)
{
	if (!addr_name) {
		osmo_sccp_make_addr_pc_ssn(dest, default_pc, OSMO_SCCP_SSN_RANAP);
		if (label)
			LOGP(DCN, LOGL_INFO, "%s remote addr not configured, using default: %s\n", label,
			     osmo_sccp_addr_name(*ss7, dest));
		return 0;
	}

	*ss7 = osmo_sccp_addr_by_name(dest, addr_name);
	if (!*ss7) {
		if (label)
			LOGP(DCN, LOGL_ERROR, "%s remote addr: no such SCCP address book entry: '%s'\n",
			     label, addr_name);
		return -1;
	}

	osmo_sccp_addr_set_ssn(dest, OSMO_SCCP_SSN_RANAP);

	if (!addr_has_pc_and_ssn(dest)) {
		if (label)
			LOGP(DCN, LOGL_ERROR, "Invalid/incomplete %s remote-addr: %s\n",
			     label, osmo_sccp_addr_name(*ss7, dest));
		return -1;
	}

	return 0;
}

char *hnbgw_cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr)
{
	struct osmo_sccp_instance *sccp = hnbgw_cnlink_sccp(cnlink);
	if (!sccp)
		return osmo_sccp_addr_dump(addr);
	return osmo_sccp_inst_addr_to_str_c(OTC_SELECT, sccp, addr);
}

static void hnbgw_cnlink_cfg_copy(struct hnbgw_cnlink *cnlink)
{
	struct osmo_nri_range *r;

	osmo_talloc_replace_string(cnlink, &cnlink->use.remote_addr_name, cnlink->vty.remote_addr_name);

	osmo_nri_ranges_free(cnlink->use.nri_ranges);
	cnlink->use.nri_ranges = osmo_nri_ranges_alloc(cnlink);
	llist_for_each_entry(r, &cnlink->vty.nri_ranges->entries, entry)
		osmo_nri_ranges_add(cnlink->use.nri_ranges, r);
}

static bool hnbgw_cnlink_sccp_cfg_changed(struct hnbgw_cnlink *cnlink)
{
	bool changed = false;

	if (cnlink->vty.remote_addr_name && cnlink->use.remote_addr_name) {
		struct osmo_ss7_instance *ss7;
		struct osmo_sccp_addr remote_addr = {};

		/* Instead of comparing whether the address book entry names are different, actually resolve the
		 * resulting SCCP address, and only restart the cnlink if the resulting address changed. */
		resolve_addr_name(&remote_addr, &ss7, cnlink->vty.remote_addr_name, NULL, cnlink->pool->default_remote_pc);
		if (osmo_sccp_addr_cmp(&remote_addr, &cnlink->remote_addr, OSMO_SCCP_ADDR_T_PC | OSMO_SCCP_ADDR_T_SSN))
			changed = true;
	} else if (cnlink->vty.remote_addr_name != cnlink->use.remote_addr_name) {
		/* One of them is NULL, the other is not. */
		changed = true;
	}

	/* if more cnlink configuration is added in the future, it needs to be compared here. */

	return changed;
}

static void hnbgw_cnlink_log_self(struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_instance *ss7 = cnlink->hnbgw_sccp_user->ss7;
	LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "using: cs7-%u %s <-> %s %s %s\n",
		   osmo_ss7_instance_get_id(ss7),
		   /* printing the entire SCCP address is quite long, rather just print the point-code */
		   osmo_ss7_pointcode_print(ss7, cnlink->hnbgw_sccp_user->local_addr.pc),
		   osmo_ss7_pointcode_print2(ss7, cnlink->remote_addr.pc),
		   cnlink->name, cnlink->use.remote_addr_name ? : "(default remote point-code)");
}

/* If not present yet, set up all of osmo_ss7_instance, osmo_sccp_instance and hnbgw_sccp_user for the given cnlink.
 * The cs7 instance nr to use is determined by cnlink->remote_addr_name, or cs7 instance 0 if that is not present.
 * Set cnlink->hnbgw_sccp_user to the new SCCP instance. Return 0 on success, negative on error. */
int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_instance *ss7 = NULL;
	struct hnbgw_sccp_user *hsu;

	/* If a hnbgw_sccp_user has already been set up, use that. */
	if (cnlink->hnbgw_sccp_user) {
		if (hnbgw_cnlink_sccp_cfg_changed(cnlink)) {
			LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "config changed, restarting SCCP\n");
			hnbgw_cnlink_drop_sccp(cnlink);
		} else {
			LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "SCCP instance already set up, using %s\n",
				   cnlink->hnbgw_sccp_user->name);
			return 0;
		}
	} else {
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "no SCCP instance selected yet\n");
	}

	/* Copy the current configuration: cnlink->use = cnlink->vty */
	hnbgw_cnlink_cfg_copy(cnlink);

	/* Figure out which cs7 instance to use. If cnlink->remote_addr_name is set, it points to an address book entry
	 * in a specific cs7 instance. If it is not set, leave ss7 == NULL to use cs7 instance 0. */
	if (cnlink->use.remote_addr_name) {
		if (resolve_addr_name(&cnlink->remote_addr, &ss7, cnlink->use.remote_addr_name, cnlink->name,
				      cnlink->pool->default_remote_pc)) {
			LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "cannot initialize SCCP: there is no SCCP address named '%s'\n",
				   cnlink->use.remote_addr_name);
			return -ENOENT;
		}

		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "remote-addr is '%s', using cs7 instance %u\n",
			   cnlink->use.remote_addr_name, osmo_ss7_instance_get_id(ss7));
	} else {
		/* If no address is configured, use the default remote CN address, according to legacy behavior. */
		osmo_sccp_make_addr_pc_ssn(&cnlink->remote_addr, cnlink->pool->default_remote_pc, OSMO_SCCP_SSN_RANAP);
	}

	/* If no 'cs7 instance' has been selected by the address, see if there already is a cs7 0 we can use by default.
	 * If it doesn't exist, it will get created by osmo_sccp_simple_client_on_ss7_id(). */
	if (!ss7) {
		ss7 = osmo_ss7_instance_find(0);
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "Using default 'cs7 instance 0' (%s)\n", ss7 ? "already exists" : "will create");
	}

	if (ss7) {
		/* Has another cnlink already set up an SCCP instance for this ss7? */
		llist_for_each_entry(hsu, &g_hnbgw->sccp.users, entry) {
			if (hsu->ss7 != ss7)
				continue;
			LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "using existing SCCP instance %s on cs7 instance %u\n",
				hsu->name, osmo_ss7_instance_get_id(ss7));
			cnlink->hnbgw_sccp_user = hsu;
			hnbgw_sccp_user_get(cnlink->hnbgw_sccp_user, HSU_USE_CNLINK);
			hnbgw_cnlink_log_self(cnlink);
			return 0;
		}
		/* else cnlink->hnbgw_sccp_user stays NULL and is set up below. */
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "cs7 instance %u has no configured SCCP instance yet\n", osmo_ss7_instance_get_id(ss7));
	}

	/* No SCCP instance yet for this ss7. Create it. If no address name is given that resolves to a
	 * particular cs7 instance above, use 'cs7 instance 0'. */
	cnlink->hnbgw_sccp_user = hnbgw_sccp_user_alloc(ss7 ? osmo_ss7_instance_get_id(ss7) : 0);
	hnbgw_sccp_user_get(cnlink->hnbgw_sccp_user, HSU_USE_CNLINK);
	hnbgw_cnlink_log_self(cnlink);
	return 0;
}
