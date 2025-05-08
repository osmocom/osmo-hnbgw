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

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/sigtran/sccp_helpers.h>

#include <asn1c/asn1helpers.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/context_map.h>

struct hnbgw_cnlink *hnbgw_cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr)
{
	struct osmo_fsm_inst *fi;
	struct hnbgw_cnlink *cnlink;

	char *name = talloc_asprintf(OTC_SELECT, "%s-%d", cnpool->peer_name, nr);

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
		.ctrs = rate_ctr_group_alloc(g_hnbgw, cnpool->cnlink_ctrg_desc, nr),
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
