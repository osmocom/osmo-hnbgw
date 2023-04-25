/* IuCS/IuPS Core Network interface of HNB-GW */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
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

#include <arpa/inet.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/hnbgw/context_map.h>

/***********************************************************************
 * Outbound RANAP RESET to CN
 ***********************************************************************/

void hnbgw_cnlink_change_state(struct hnbgw_cnlink *cnlink, enum hnbgw_cnlink_state state);

static int transmit_rst(struct hnbgw_cnlink *cnlink)
{
	struct msgb *msg;
	RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_transmissionNetwork,
		.choice. transmissionNetwork = RANAP_CauseTransmissionNetwork_signalling_transport_resource_failure,
	};

	if (!cnlink)
		return -1;

	if (!cnlink->hnbgw_sccp_inst) {
		LOG_CNLINK(cnlink, DRANAP, LOGL_ERROR, "cannot send RANAP RESET: no CN link\n");
		return -1;
	}

	LOG_CNLINK(cnlink, DRANAP, LOGL_NOTICE, "Tx RANAP RESET to %s %s\n",
		   cnlink_is_cs(cnlink) ? "IuCS" : "IuPS",
		   osmo_sccp_inst_addr_name(cnlink->hnbgw_sccp_inst->sccp, &cnlink->remote_addr));

	msg = ranap_new_msg_reset(cnlink->pool->domain, &cause);

	return osmo_sccp_tx_unitdata_msg(cnlink->hnbgw_sccp_inst->sccp_user,
					 &cnlink->local_addr,
					 &cnlink->remote_addr,
					 msg);
}

static int transmit_reset_ack(struct hnbgw_cnlink *cnlink)
{
	struct msgb *msg;
	struct osmo_sccp_instance *sccp = cnlink_sccp(cnlink);

	if (!sccp) {
		LOG_CNLINK(cnlink, DRANAP, LOGL_ERROR, "cannot send RANAP RESET ACK: no CN link\n");
		return -1;
	}

	LOG_CNLINK(cnlink, DRANAP, LOGL_NOTICE, "Tx RANAP RESET ACK %s %s --> %s\n",
		   cnlink_is_cs(cnlink) ? "IuCS" : "IuPS",
		   osmo_sccp_inst_addr_to_str_c(OTC_SELECT, cnlink->hnbgw_sccp_inst->sccp, &cnlink->local_addr),
		   osmo_sccp_inst_addr_to_str_c(OTC_SELECT, cnlink->hnbgw_sccp_inst->sccp, &cnlink->remote_addr));

	msg = ranap_new_msg_reset_ack(cnlink->pool->domain, NULL);

	return osmo_sccp_tx_unitdata_msg(cnlink->hnbgw_sccp_inst->sccp_user,
					 &cnlink->local_addr,
					 &cnlink->remote_addr,
					 msg);
}

/* Timer callback once T_RafC expires */
static void cnlink_trafc_cb(void *data)
{
	struct hnbgw_cnlink *cnlink = data;
	OSMO_ASSERT(false);

	transmit_rst(cnlink);
	hnbgw_cnlink_change_state(cnlink, CNLINK_S_EST_RST_TX_WAIT_ACK);
	/* The spec states that we should abandon after a configurable
	 * number of times.  We decide to simply continue trying */
}

/* change the state of a CN Link */
void hnbgw_cnlink_change_state(struct hnbgw_cnlink *cnlink, enum hnbgw_cnlink_state state)
{
	OSMO_ASSERT(false);
	switch (state) {
	case CNLINK_S_NULL:
	case CNLINK_S_EST_PEND:
		break;
	case CNLINK_S_EST_CONF:
		cnlink_trafc_cb(cnlink);
		break;
	case CNLINK_S_EST_RST_TX_WAIT_ACK:
		osmo_timer_schedule(&cnlink->T_RafC, 5, 0);
		break;
	case CNLINK_S_EST_ACTIVE:
		osmo_timer_del(&cnlink->T_RafC);
		break;
	}
}

/***********************************************************************
 * Incoming primitives from SCCP User SAP
 ***********************************************************************/

static int cn_ranap_rx_reset_cmd(struct hnbgw_cnlink *cnlink,
				 const struct osmo_scu_unitdata_param *unitdata,
				 RANAP_InitiatingMessage_t *imsg)
{
	RANAP_CN_DomainIndicator_t domain;
	RANAP_ResetIEs_t ies;
	int rc;

	rc = ranap_decode_reseties(&ies, &imsg->value);
	domain = ies.cN_DomainIndicator;
	ranap_free_reseties(&ies);

	LOG_CNLINK(cnlink, DRANAP, LOGL_NOTICE, "Rx RESET from %s %s, returning ACK\n",
		   domain == DOMAIN_CS ? "IuCS" : "IuPS",
		   osmo_sccp_inst_addr_name(cnlink_sccp(cnlink), &unitdata->calling_addr));

	/* FIXME: actually reset connections, if any */

	if (transmit_reset_ack(cnlink))
		LOGP(DRANAP, LOGL_ERROR, "Error: cannot send RESET ACK to %s %s\n",
		     domain == DOMAIN_CS ? "IuCS" : "IuPS",
		     osmo_sccp_inst_addr_name(cnlink_sccp(cnlink), &unitdata->calling_addr));

	return rc;
}

static int cn_ranap_rx_reset_ack(struct hnbgw_cnlink *cnlink,
				 RANAP_SuccessfulOutcome_t *omsg)
{
	RANAP_ResetAcknowledgeIEs_t ies;
	int rc;

	rc = ranap_decode_resetacknowledgeies(&ies, &omsg->value);

	hnbgw_cnlink_change_state(cnlink, CNLINK_S_EST_ACTIVE);

	ranap_free_resetacknowledgeies(&ies);
	return rc;
}

static int cn_ranap_rx_paging_cmd(struct hnbgw_cnlink *cnlink,
				  RANAP_InitiatingMessage_t *imsg,
				  const uint8_t *data, unsigned int len)
{
	struct hnb_context *hnb;
	RANAP_PagingIEs_t ies;
	int rc;

	rc = ranap_decode_pagingies(&ies, &imsg->value);
	if (rc < 0)
		return rc;

	/* FIXME: determine which HNBs to send this Paging command,
	 * rather than broadcasting to all HNBs */
	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		rc = rua_tx_udt(hnb, data, len);
	}

	ranap_free_pagingies(&ies);
	return 0;
}

static int cn_ranap_rx_initiating_msg(struct hnbgw_cnlink *cnlink,
				      const struct osmo_scu_unitdata_param *unitdata,
				      RANAP_InitiatingMessage_t *imsg,
				      const uint8_t *data, unsigned int len)
{
	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset:
		return cn_ranap_rx_reset_cmd(cnlink, unitdata, imsg);
	case RANAP_ProcedureCode_id_Paging:
		return cn_ranap_rx_paging_cmd(cnlink, imsg, data, len);
	case RANAP_ProcedureCode_id_OverloadControl: /* Overload ind */
		break;
	case RANAP_ProcedureCode_id_ErrorIndication: /* Error ind */
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* request */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "Procedure %ld from CN, ignoring\n", imsg->procedureCode);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %ld from CN, ignoring\n", imsg->procedureCode);
		break;
	}
	return 0;
}

static int cn_ranap_rx_successful_msg(struct hnbgw_cnlink *cnlink,
					RANAP_SuccessfulOutcome_t *omsg)
{
	switch (omsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset: /* Reset acknowledge */
		return cn_ranap_rx_reset_ack(cnlink, omsg);
	case RANAP_ProcedureCode_id_ResetResource: /* response */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "Procedure %ld from CN, ignoring\n", omsg->procedureCode);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %ld from CN, ignoring\n", omsg->procedureCode);
		break;
	}
	return 0;
}


static int _cn_ranap_rx(struct hnbgw_cnlink *cnlink,
			const struct osmo_scu_unitdata_param *unitdata,
			RANAP_RANAP_PDU_t *pdu, const uint8_t *data, unsigned int len)
{
	int rc;

	switch (pdu->present) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		rc = cn_ranap_rx_initiating_msg(cnlink, unitdata, &pdu->choice.initiatingMessage,
						data, len);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		rc = cn_ranap_rx_successful_msg(cnlink, &pdu->choice.successfulOutcome);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "unsuccessful outcome procedure %ld from CN, ignoring\n",
		     pdu->choice.unsuccessfulOutcome.procedureCode);
		rc = -ENOTSUP;
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "presence %u from CN, ignoring\n", pdu->present);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int handle_cn_ranap(struct hnbgw_cnlink *cnlink, const struct osmo_scu_unitdata_param *unitdata,
			   const uint8_t *data, unsigned int len)
{
	RANAP_RANAP_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGP(DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	rc = _cn_ranap_rx(cnlink, unitdata, pdu, data, len);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, pdu);

	return rc;
}

static struct hnbgw_cnlink *cnlink_from_addr(struct hnbgw_sccp_inst *hsi, const struct osmo_sccp_addr *calling_addr,
					     const struct osmo_prim_hdr *oph)
{
	struct hnbgw_cnlink *cnlink = NULL;
	cnlink = hnbgw_cnlink_find_by_addr(hsi, calling_addr);
	if (!cnlink) {
		LOG_HSI(hsi, DRANAP, LOGL_ERROR, "Rx from unknown SCCP peer: %s: %s\n",
			osmo_sccp_inst_addr_name(hsi->sccp, calling_addr),
			osmo_scu_prim_hdr_name_c(OTC_SELECT, oph));
		return NULL;
	}
	return cnlink;
}

static struct hnbgw_context_map *map_from_conn_id(struct hnbgw_sccp_inst *hsi, uint32_t conn_id,
						  const struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;
	hash_for_each_possible(hsi->hnbgw_context_map_by_conn_id, map, hnbgw_sccp_inst_entry, conn_id)
		return map;
	LOGP(DRANAP, LOGL_ERROR, "Rx for unknown SCCP connection ID: %u: %s\n",
	     conn_id, osmo_scu_prim_hdr_name_c(OTC_SELECT, oph));
	return NULL;
}

static int handle_cn_unitdata(struct hnbgw_sccp_inst *hsi,
			      const struct osmo_scu_unitdata_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_cnlink *cnlink = cnlink_from_addr(hsi, &param->calling_addr, oph);
	if (!cnlink)
		return -ENOENT;

	if (param->called_addr.ssn != OSMO_SCCP_SSN_RANAP) {
		LOGP(DMAIN, LOGL_NOTICE, "N-UNITDATA.ind for unknown SSN %u\n",
			param->called_addr.ssn);
		return -1;
	}

	return handle_cn_ranap(cnlink, param, msgb_l2(oph->msg), msgb_l2len(oph->msg));
}

static int handle_cn_conn_conf(struct hnbgw_sccp_inst *hsi,
			       const struct osmo_scu_connect_param *param,
			       struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;
	struct osmo_sccp_instance *sccp;

	map = map_from_conn_id(hsi, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	sccp = cnlink_sccp(map->cnlink);

	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_conn_conf() conn_id=%d, addrs: called=%s calling=%s responding=%s\n",
	     param->conn_id,
	     osmo_sccp_inst_addr_to_str_c(OTC_SELECT, sccp, &param->called_addr),
	     osmo_sccp_inst_addr_to_str_c(OTC_SELECT, sccp, &param->calling_addr),
	     osmo_sccp_inst_addr_to_str_c(OTC_SELECT, sccp, &param->responding_addr));

	map_sccp_dispatch(map, MAP_SCCP_EV_RX_CONNECTION_CONFIRM, oph->msg);
	return 0;
}

static int handle_cn_data_ind(struct hnbgw_sccp_inst *hsi,
			      const struct osmo_scu_data_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	map = map_from_conn_id(hsi, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_DATA_INDICATION, oph->msg);
}

static int handle_cn_disc_ind(struct hnbgw_sccp_inst *hsi,
			      const struct osmo_scu_disconn_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	map = map_from_conn_id(hsi, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_disc_ind() conn_id=%u responding_addr=%s\n",
	     param->conn_id,
	     osmo_sccp_inst_addr_to_str_c(OTC_SELECT, cnlink_sccp(map->cnlink), &param->responding_addr));

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_RELEASED, oph->msg);
}

/* Entry point for primitives coming up from SCCP User SAP */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_sccp_user *scu = ctx;
	struct hnbgw_sccp_inst *hsi;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	int rc = 0;

	LOGP(DMAIN, LOGL_DEBUG, "sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	if (!scu) {
		LOGP(DMAIN, LOGL_ERROR,
		     "sccp_sap_up(): NULL osmo_sccp_user, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	hsi = osmo_sccp_user_get_priv(scu);
	if (!hsi) {
		LOGP(DMAIN, LOGL_ERROR,
		     "sccp_sap_up(): NULL hnbgw_sccp_inst, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	talloc_steal(OTC_SELECT, oph->msg);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		rc = handle_cn_unitdata(hsi, &prim->u.unitdata, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		rc = handle_cn_conn_conf(hsi, &prim->u.connect, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		rc = handle_cn_data_ind(hsi, &prim->u.data, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		rc = handle_cn_disc_ind(hsi, &prim->u.disconnect, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_PCSTATE, PRIM_OP_INDICATION):
		LOGP(DMAIN, LOGL_DEBUG, "Ignoring prim %s from SCCP USER SAP\n",
		     osmo_scu_prim_hdr_name_c(OTC_SELECT, oph));
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR,
			"Received unknown prim %u from SCCP USER SAP\n",
			OSMO_PRIM_HDR(oph));
		break;
	}

	return rc;
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
		LOGP(DMAIN, LOGL_INFO, "%s remote addr not configured, using default: %s\n", label,
		     osmo_sccp_addr_name(*ss7, dest));
		return 0;
	}

	*ss7 = osmo_sccp_addr_by_name(dest, addr_name);
	if (!*ss7) {
		LOGP(DMAIN, LOGL_ERROR, "%s remote addr: no such SCCP address book entry: '%s'\n",
		     label, addr_name);
		return -1;
	}

	osmo_sccp_addr_set_ssn(dest, OSMO_SCCP_SSN_RANAP);

	if (!addr_has_pc_and_ssn(dest)) {
		LOGP(DMAIN, LOGL_ERROR, "Invalid/incomplete %s remote-addr: %s\n",
		     label, osmo_sccp_addr_name(*ss7, dest));
		return -1;
	}

	LOGP(DRANAP, LOGL_NOTICE, "Remote %s SCCP addr: %s\n",
	     label, osmo_sccp_addr_name(*ss7, dest));
	return 0;
}

static void cnlink_set_sccp_inst(struct hnbgw_cnlink *cnlink, struct hnbgw_sccp_inst *hsi)
{
	uint32_t local_pc;

	cnlink->hnbgw_sccp_inst = hsi;

	/* Figure out which local address this cnlink uses: the cs7 instance's primary PC or another one already
	 * configured in cnlink->local_addr? */
	if ((cnlink->local_addr.presence & OSMO_SCCP_ADDR_T_PC)
	    && osmo_ss7_pc_is_valid(cnlink->local_addr.pc)) {
		local_pc = cnlink->local_addr.pc;
	} else {
		struct osmo_ss7_instance *ss7 = osmo_sccp_get_ss7(hsi->sccp);
		OSMO_ASSERT(ss7);
		local_pc = ss7->cfg.primary_pc;
	}

	osmo_sccp_make_addr_pc_ssn(&cnlink->local_addr, local_pc, OSMO_SCCP_SSN_RANAP);
}

void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool)
{
	struct osmo_nri_range *r;

	cnpool->use.nri_bitlen = cnpool->vty.nri_bitlen;

	osmo_nri_ranges_free(cnpool->use.null_nri_ranges);
	cnpool->use.null_nri_ranges = osmo_nri_ranges_alloc(g_hnbgw);
	llist_for_each_entry(r, &cnpool->vty.null_nri_ranges->entries, entry)
		osmo_nri_ranges_add(cnpool->use.null_nri_ranges, r);
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
	if (!cnlink->vty.remote_addr_name ||
	    !cnlink->use.remote_addr_name)
		return true;
	return strcmp(cnlink->vty.remote_addr_name, cnlink->use.remote_addr_name) != 0;
}

static void hnbgw_cnlink_drop_sccp(struct hnbgw_cnlink *cnlink)
{
	struct hnbgw_context_map *map, *map2;

	llist_for_each_entry_safe(map, map2, &cnlink->map_list, hnbgw_cnlink_entry) {
		map_sccp_dispatch(map, MAP_SCCP_EV_USER_ABORT, NULL);
	}

	cnlink->hnbgw_sccp_inst = NULL;
}

/* If not present yet, set up all of osmo_ss7_instance, osmo_sccp_instance and hnbgw_sccp_inst for the given cnlink.
 * The cs7 instance nr to use is determined by cnlink->remote_addr_name, or cs7 instance 0 if that is not present.
 * Set cnlink->hnbgw_sccp_inst to the new SCCP instance. Return 0 on success, negative on error. */
int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_instance *ss7 = NULL;
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *sccp_user;
	uint32_t local_pc;
	struct hnbgw_sccp_inst *hsi;

	/* If a hnbgw_sccp_inst has already been set up, and the SCCP config has not changed since starting, use that.
	 */
	if (cnlink->hnbgw_sccp_inst) {
		if (hnbgw_cnlink_sccp_cfg_changed(cnlink)) {
			/* User is asking to restart the SCCP. Drop all contexts. */
			hnbgw_cnlink_drop_sccp(cnlink);
		} else {
			return 0;
		}
	}
	if (!cnlink->vty.remote_addr_name) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "cannot initialize SCCP: no remote address set\n");
		return -EINVAL;
	}

	/* Copy the current configuration. */
	hnbgw_cnlink_cfg_copy(cnlink);

	/* Figure out which cs7 instance to use. cnlink->remote_addr_name is set, it points to an address book entry
	 * in a specific cs7 instance. */
	if (resolve_addr_name(&cnlink->remote_addr, &ss7, cnlink->use.remote_addr_name, cnlink->name,
			      DEFAULT_PC_HNBGW)) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "cannot initialize SCCP: there is no SCCP address named '%s'\n",
			   cnlink->use.remote_addr_name);
		return -ENOENT;
	}

	LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "using cs7 instance %u\n", ss7->cfg.id);

	/* Has another cnlink already set up an SCCP instance for this ss7? */
	llist_for_each_entry(hsi, &g_hnbgw->sccp.instances, entry) {
		if (hsi->cs7_instance != ss7->cfg.id)
			continue;
		cnlink_set_sccp_inst(cnlink, hsi);
		return 0;
	}
	/* else cnlink->hnbgw_sccp_inst stays NULL and is set up below. */

	/* All SCCP instances should originate from this function. So if there is no hnbgw_sccp_inst for the cs7
	 * instance, then the cs7 instance should not have an SCCP instance yet. */
	OSMO_ASSERT(!ss7->sccp);

	/* No SCCP instance yet for this ss7. Create it. */
	sccp = osmo_sccp_simple_client_on_ss7_id(g_hnbgw, ss7 ? ss7->cfg.id : 0, cnlink->name, DEFAULT_PC_HNBGW,
						 OSMO_SS7_ASP_PROT_M3UA, 0, "localhost", -1, "localhost");
	if (!sccp) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Failed to configure 'cs7 instance %u'\n", ss7->cfg.id);
		return -1;
	}
	ss7 = osmo_sccp_get_ss7(sccp);

	/* If the cnlink provides a local point-code, use that. */
	if ((cnlink->local_addr.presence & OSMO_SCCP_ADDR_T_PC)
	    && osmo_ss7_pc_is_valid(cnlink->local_addr.pc))
		local_pc = cnlink->local_addr.pc;
	else if (osmo_ss7_pc_is_valid(ss7->cfg.primary_pc))
		local_pc = ss7->cfg.primary_pc;
	else
		local_pc = DEFAULT_PC_HNBGW;

	sccp_user = osmo_sccp_user_bind_pc(sccp, "OsmoHNBGW", sccp_sap_up, OSMO_SCCP_SSN_RANAP, local_pc);
	if (!sccp_user) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to init SCCP User\n");
		return -1;
	}

	hsi = talloc_zero(cnlink, struct hnbgw_sccp_inst);
	*hsi = (struct hnbgw_sccp_inst){
		.name = talloc_asprintf(hsi, "cs7-%u.sccp", ss7->cfg.id),
		.cs7_instance = ss7->cfg.id,
		.sccp = sccp,
		.sccp_user = sccp_user,
	};
	hash_init(hsi->hnbgw_context_map_by_conn_id);

	osmo_sccp_user_set_priv(sccp_user, hsi);

	llist_add_tail(&hsi->entry, &g_hnbgw->sccp.instances);

	cnlink_set_sccp_inst(cnlink, hsi);
	return 0;
}

void hnbgw_cnpool_cnlinks_start_or_restart(struct hnbgw_cnpool *cnpool)
{
	struct hnbgw_cnlink *cnlink;
	hnbgw_cnpool_apply_cfg(cnpool);
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		hnbgw_cnlink_start_or_restart(cnlink);
	}
}

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool)
{
	/* Legacy compat: when there is no 'msc N' at all in the config file, set up 'msc 0' with default values (or
	 * 'sgsn' depending on cnpool). */
	if (llist_empty(&cnpool->cnlinks))
		cnlink_get_nr(cnpool, 0, true);
	hnbgw_cnpool_cnlinks_start_or_restart(cnpool);
}

static struct hnbgw_cnlink *cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr)
{
	struct hnbgw_cnlink *cnlink;
	cnlink = talloc_zero(g_hnbgw, struct hnbgw_cnlink);
	*cnlink = (struct hnbgw_cnlink){
		.pool = cnpool,
		.nr = nr,
		.vty = {
			/* VTY config defaults for the new cnlink */
			.nri_ranges = osmo_nri_ranges_alloc(cnlink),
		},
		.name = talloc_asprintf(cnlink, "%s-%d", cnpool->peer_name, nr),
		.T_RafC = {
			.cb = cnlink_trafc_cb,
			.data = cnlink,
		},
		.allow_attach = true,
	};
	osmo_sccp_addr_set_ssn(&cnlink->local_addr, OSMO_SCCP_SSN_RANAP);
	INIT_LLIST_HEAD(&cnlink->map_list);

	llist_add_tail(&cnlink->entry, &cnpool->cnlinks);
	return cnlink;
}

struct hnbgw_cnlink *cnlink_get_nr(struct hnbgw_cnpool *cnpool, int nr, bool create_if_missing)
{
	struct hnbgw_cnlink *cnlink;
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		if (cnlink->nr == nr)
			return cnlink;
	}

	if (!create_if_missing)
		return NULL;

	return cnlink_alloc(cnpool, nr);
}

static bool cnlink_matches(const struct hnbgw_cnlink *cnlink, const struct hnbgw_sccp_inst *hsi, const struct osmo_sccp_addr *remote_addr)
{
	if (cnlink->hnbgw_sccp_inst != hsi)
		return false;
	if (osmo_sccp_addr_cmp(&cnlink->remote_addr, remote_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
		return false;
	return true;
}

struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_inst *hsi,
					       const struct osmo_sccp_addr *remote_addr)
{
	struct hnbgw_cnlink *cnlink;
	llist_for_each_entry(cnlink, &g_hnbgw->sccp.cnpool_iucs.cnlinks, entry) {
		if (cnlink_matches(cnlink, hsi, remote_addr))
			return cnlink;
	}
	llist_for_each_entry(cnlink, &g_hnbgw->sccp.cnpool_iups.cnlinks, entry) {
		if (cnlink_matches(cnlink, hsi, remote_addr))
			return cnlink;
	}
	return NULL;
}

struct hnbgw_cnlink *hnbgw_cnlink_select(struct hnbgw_context_map *map)
{
	struct hnbgw_cnpool *cnpool = map->is_ps ? &g_hnbgw->sccp.cnpool_iups : &g_hnbgw->sccp.cnpool_iucs;
	struct hnbgw_cnlink *cnlink;
	/* FUTURE: soon we will pick one of many configurable CN peers from a pool. There will be more input arguments
	 * (MI, or TMSI, or NRI decoded from RANAP) and this function will do round robin for new subscribers. */
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		if (!cnlink->hnbgw_sccp_inst || !cnlink->hnbgw_sccp_inst->sccp)
			continue;
		LOG_MAP(map, DCN, LOGL_INFO, "Selected %s / %s\n",
			cnlink->name,
			cnlink->hnbgw_sccp_inst->name);
		return cnlink;
	}
	return NULL;
}
