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

#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/hnbgw/context_map.h>

#if 0
this code will soon move to new file cnlink.c
static int transmit_rst(struct hnbgw_cnlink *cnlink)
{
	struct msgb *msg;
	RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_transmissionNetwork,
		.choice. transmissionNetwork = RANAP_CauseTransmissionNetwork_signalling_transport_resource_failure,
	};

	LOGP(DRANAP, LOGL_NOTICE, "Tx RESET to %s %s\n",
	     domain == RANAP_CN_DomainIndicator_cs_domain ? "IuCS" : "IuPS",
	     osmo_sccp_inst_addr_name(g_hnbgw->sccp.cnlink->sccp, remote_addr));

	msg = ranap_new_msg_reset(domain, &cause);

	return osmo_sccp_tx_unitdata_msg(g_hnbgw->sccp.cnlink->sccp_user,
					 &g_hnbgw->sccp.local_addr,
					 remote_addr,
					 msg);
}
#endif

static int transmit_reset_ack(RANAP_CN_DomainIndicator_t domain,
			      const struct osmo_sccp_addr *remote_addr)
{
	struct msgb *msg;

	LOGP(DRANAP, LOGL_NOTICE, "Tx RESET ACK to %s %s\n",
	     domain == RANAP_CN_DomainIndicator_cs_domain ? "IuCS" : "IuPS",
	     osmo_sccp_inst_addr_name(g_hnbgw->sccp.cnlink->sccp, remote_addr));

	msg = ranap_new_msg_reset_ack(domain, NULL);

	return osmo_sccp_tx_unitdata_msg(g_hnbgw->sccp.cnlink->sccp_user,
					 &g_hnbgw->sccp.local_addr,
					 remote_addr,
					 msg);
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

	LOGP(DRANAP, LOGL_NOTICE, "Rx RESET from %s %s, returning ACK\n",
	     domain == RANAP_CN_DomainIndicator_cs_domain ? "IuCS" : "IuPS",
	     osmo_sccp_inst_addr_name(cnlink->sccp, &unitdata->calling_addr));

	/* FIXME: actually reset connections, if any */

	if (transmit_reset_ack(domain, &unitdata->calling_addr))
		LOGP(DRANAP, LOGL_ERROR, "Error: cannot send RESET ACK to %s %s\n",
		     domain == RANAP_CN_DomainIndicator_cs_domain ? "IuCS" : "IuPS",
		     osmo_sccp_inst_addr_name(cnlink->sccp, &unitdata->calling_addr));

	return rc;
}

static int cn_ranap_rx_reset_ack(struct hnbgw_cnlink *cnlink,
				 RANAP_SuccessfulOutcome_t *omsg)
{
	RANAP_ResetAcknowledgeIEs_t ies;
	int rc;

	rc = ranap_decode_resetacknowledgeies(&ies, &omsg->value);

	/* FUTURE: will do something useful in commit 'detect in/active CN links by RANAP RESET'
	 * Id3eefdea889a736fd5957b80280fa45b9547b792 */

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

static bool pc_and_ssn_match(const struct osmo_sccp_addr *a, const struct osmo_sccp_addr *b)
{
	return (a == b)
	       || ((a->pc == b->pc)
		   && (a->ssn == b->ssn));
}

static int classify_cn_remote_addr(const struct osmo_sccp_addr *cn_remote_addr,
				   bool *is_ps)
{
	if (pc_and_ssn_match(cn_remote_addr, &g_hnbgw->sccp.iucs_remote_addr)) {
		if (is_ps)
			*is_ps = false;
		return 0;
	}
	if (pc_and_ssn_match(cn_remote_addr, &g_hnbgw->sccp.iups_remote_addr)) {
		if (is_ps)
			*is_ps = true;
		return 0;
	}
	LOGP(DMAIN, LOGL_ERROR, "Unexpected remote address, matches neither CS nor PS address: %s\n",
	     osmo_sccp_addr_dump(cn_remote_addr));
	return -1;
}

static int handle_cn_unitdata(struct hnbgw_cnlink *cnlink,
			      const struct osmo_scu_unitdata_param *param,
			      struct osmo_prim_hdr *oph)
{
	if (param->called_addr.ssn != OSMO_SCCP_SSN_RANAP) {
		LOGP(DMAIN, LOGL_NOTICE, "N-UNITDATA.ind for unknown SSN %u\n",
			param->called_addr.ssn);
		return -1;
	}

	if (classify_cn_remote_addr(&param->calling_addr, NULL) < 0)
		return -1;

	return handle_cn_ranap(cnlink, param, msgb_l2(oph->msg), msgb_l2len(oph->msg));
}

static int handle_cn_conn_conf(struct hnbgw_cnlink *cnlink,
			       const struct osmo_scu_connect_param *param,
			       struct osmo_prim_hdr *oph)
{
	struct osmo_ss7_instance *ss7 = osmo_sccp_get_ss7(g_hnbgw->sccp.client);
	struct hnbgw_context_map *map;

	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_conn_conf() conn_id=%d, addrs: called=%s calling=%s responding=%s\n",
	     param->conn_id,
	     osmo_sccp_addr_to_str_c(OTC_SELECT, ss7, &param->called_addr),
	     osmo_sccp_addr_to_str_c(OTC_SELECT, ss7, &param->calling_addr),
	     osmo_sccp_addr_to_str_c(OTC_SELECT, ss7, &param->responding_addr));

	map = context_map_by_cn(cnlink, param->conn_id);
	if (!map) {
		/* We have no such SCCP connection. Ignore. */
		return 0;
	}

	map_sccp_dispatch(map, MAP_SCCP_EV_RX_CONNECTION_CONFIRM, oph->msg);
	return 0;
}

static int handle_cn_data_ind(struct hnbgw_cnlink *cnlink,
			      const struct osmo_scu_data_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	map = context_map_by_cn(cnlink, param->conn_id);
	if (!map) {
		/* We have no such SCCP connection. Ignore. */
		return 0;
	}

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_DATA_INDICATION, oph->msg);
}

static int handle_cn_disc_ind(struct hnbgw_cnlink *cnlink,
			      const struct osmo_scu_disconn_param *param,
			      struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_disc_ind() conn_id=%d originator=%d\n",
	     param->conn_id, param->originator);
	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_disc_ind() responding_addr=%s\n",
	     inet_ntoa(param->responding_addr.ip.v4));

	map = context_map_by_cn(cnlink, param->conn_id);
	if (!map) {
		/* We have no connection. Ignore. */
		return 0;
	}

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_RELEASED, oph->msg);
}

/* Entry point for primitives coming up from SCCP User SAP */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_sccp_user *scu = ctx;
	struct hnbgw_cnlink *cnlink;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	int rc = 0;

	LOGP(DMAIN, LOGL_DEBUG, "sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	if (!scu) {
		LOGP(DMAIN, LOGL_ERROR,
		     "sccp_sap_up(): NULL osmo_sccp_user, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	cnlink = osmo_sccp_user_get_priv(scu);
	if (!cnlink) {
		LOGP(DMAIN, LOGL_ERROR,
		     "sccp_sap_up(): NULL hnbgw_cnlink, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	talloc_steal(OTC_SELECT, oph->msg);

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		rc = handle_cn_unitdata(cnlink, &prim->u.unitdata, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		rc = handle_cn_conn_conf(cnlink, &prim->u.connect, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		rc = handle_cn_data_ind(cnlink, &prim->u.data, oph);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		rc = handle_cn_disc_ind(cnlink, &prim->u.disconnect, oph);
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
	struct osmo_ss7_instance *ss7_tmp;

	if (!addr_name) {
		osmo_sccp_make_addr_pc_ssn(dest, default_pc, OSMO_SCCP_SSN_RANAP);
		LOGP(DMAIN, LOGL_INFO, "%s remote addr not configured, using default: %s\n", label,
		     osmo_sccp_addr_name(*ss7, dest));
		return 0;
	}

	ss7_tmp = osmo_sccp_addr_by_name(dest, addr_name);
	if (!ss7_tmp) {
		LOGP(DMAIN, LOGL_ERROR, "%s remote addr: no such SCCP address book entry: '%s'\n",
			label, addr_name);
		return -1;
	}

	if (*ss7 && (*ss7 != ss7_tmp)) {
		LOGP(DMAIN, LOGL_ERROR, "IuCS and IuPS cannot be served from separate CS7 instances,"
		     " cs7 instance %d != %d\n", (*ss7)->cfg.id, ss7_tmp->cfg.id);
		return -1;
	}

	*ss7 = ss7_tmp;

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

int hnbgw_cnlink_init(const char *stp_host, uint16_t stp_port, const char *local_ip)
{
	struct hnbgw_cnlink *cnlink;
	struct osmo_ss7_instance *ss7;
	uint32_t local_pc;

	OSMO_ASSERT(!g_hnbgw->sccp.client);
	OSMO_ASSERT(!g_hnbgw->sccp.cnlink);

	ss7 = NULL;
	if (resolve_addr_name(&g_hnbgw->sccp.iucs_remote_addr, &ss7,
			      g_hnbgw->config.iucs_remote_addr_name, "IuCS", (23 << 3) + 1))
		return -1;
	if (resolve_addr_name(&g_hnbgw->sccp.iups_remote_addr, &ss7,
			      g_hnbgw->config.iups_remote_addr_name, "IuPS", (23 << 3) + 4))
		return -1;

	if (!ss7) {
		LOGP(DRANAP, LOGL_NOTICE, "No cs7 instance configured for IuCS nor IuPS,"
		     " creating default instance\n");
		ss7 = osmo_ss7_instance_find_or_create(g_hnbgw, 0);
		if (!ss7)
			return -1;
		ss7->cfg.primary_pc = (23 << 3) + 5;
	}

	if (!osmo_ss7_pc_is_valid(ss7->cfg.primary_pc)) {
		LOGP(DMAIN, LOGL_ERROR, "IuCS/IuPS uplink cannot be setup: CS7 instance %d has no point-code set\n",
		     ss7->cfg.id);
		return -1;
	}
	local_pc = ss7->cfg.primary_pc;

	osmo_sccp_make_addr_pc_ssn(&g_hnbgw->sccp.local_addr, local_pc, OSMO_SCCP_SSN_RANAP);
	LOGP(DRANAP, LOGL_NOTICE, "Local SCCP addr: %s\n", osmo_sccp_addr_name(ss7, &g_hnbgw->sccp.local_addr));

	g_hnbgw->sccp.client = osmo_sccp_simple_client_on_ss7_id(g_hnbgw, ss7->cfg.id, "OsmoHNBGW",
								 local_pc, OSMO_SS7_ASP_PROT_M3UA,
								 0, local_ip, stp_port, stp_host);
	if (!g_hnbgw->sccp.client) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to init SCCP Client\n");
		return -1;
	}

	cnlink = talloc_zero(g_hnbgw, struct hnbgw_cnlink);
	INIT_LLIST_HEAD(&cnlink->map_list);

	cnlink->sccp_user = osmo_sccp_user_bind_pc(g_hnbgw->sccp.client, "OsmoHNBGW", sccp_sap_up,
						   OSMO_SCCP_SSN_RANAP, g_hnbgw->sccp.local_addr.pc);
	if (!cnlink->sccp_user) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to init SCCP User\n");
		return -1;
	}

	LOGP(DRANAP, LOGL_NOTICE, "Remote SCCP addr: IuCS: %s\n",
	     osmo_sccp_addr_name(ss7, &g_hnbgw->sccp.iucs_remote_addr));
	LOGP(DRANAP, LOGL_NOTICE, "Remote SCCP addr: IuPS: %s\n",
	     osmo_sccp_addr_name(ss7, &g_hnbgw->sccp.iups_remote_addr));

	/* In sccp_sap_up() we expect the cnlink in the user's priv. */
	osmo_sccp_user_set_priv(cnlink->sccp_user, cnlink);

	g_hnbgw->sccp.cnlink = cnlink;

	return 0;
}

const struct osmo_sccp_addr *hnbgw_cn_get_remote_addr(bool is_ps)
{
	return is_ps ? &g_hnbgw->sccp.iups_remote_addr : &g_hnbgw->sccp.iucs_remote_addr;
}
