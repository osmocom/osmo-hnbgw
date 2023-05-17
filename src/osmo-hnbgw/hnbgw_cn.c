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
#include <osmocom/hnbgw/hnbgw_cn.h>
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

	if (!cnlink)
		return -1;

	if (!cnlink->hnbgw_sccp_user) {
		LOG_CNLINK(cnlink, DRANAP, LOGL_ERROR, "cannot send RANAP RESET: no CN link\n");
		return -1;
	}

	LOG_CNLINK(cnlink, DRANAP, LOGL_NOTICE, "Tx RANAP RESET to %s %s\n",
		   cnlink_is_cs(cnlink) ? "IuCS" : "IuPS",
		   osmo_sccp_inst_addr_name(cnlink->hnbgw_sccp_user->sccp, &cnlink->remote_addr));

	msg = ranap_new_msg_reset(cnlink->domain, &cause);

	return osmo_sccp_tx_unitdata_msg(cnlink->hnbgw_sccp_user->sccp_user,
					 &cnlink->local_addr,
					 &cnlink->remote_addr,
					 msg);
}
#endif

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
		   cnlink_sccp_addr_to_str(cnlink, &cnlink->hnbgw_sccp_user->local_addr),
		   cnlink_sccp_addr_to_str(cnlink, &cnlink->remote_addr));

	msg = ranap_new_msg_reset_ack(cnlink->domain, NULL);

	return osmo_sccp_tx_unitdata_msg(cnlink->hnbgw_sccp_user->sccp_user,
					 &cnlink->hnbgw_sccp_user->local_addr,
					 &cnlink->remote_addr,
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

static struct hnbgw_cnlink *cnlink_from_addr(struct hnbgw_sccp_user *hsu, const struct osmo_sccp_addr *calling_addr,
					     const struct osmo_prim_hdr *oph)
{
	struct hnbgw_cnlink *cnlink = NULL;
	cnlink = hnbgw_cnlink_find_by_addr(hsu, calling_addr);
	if (!cnlink) {
		LOG_HSI(hsu, DRANAP, LOGL_ERROR, "Rx from unknown SCCP peer: %s: %s\n",
			osmo_sccp_inst_addr_name(hsu->ss7->sccp, calling_addr),
			osmo_scu_prim_hdr_name_c(OTC_SELECT, oph));
		return NULL;
	}
	return cnlink;
}

static struct hnbgw_context_map *map_from_conn_id(struct hnbgw_sccp_user *hsu, uint32_t conn_id,
						  const struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;
	hash_for_each_possible(hsu->hnbgw_context_map_by_conn_id, map, hnbgw_sccp_user_entry, conn_id)
		return map;
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
		LOGP(DMAIN, LOGL_NOTICE, "N-UNITDATA.ind for unknown SSN %u\n",
			param->called_addr.ssn);
		return -1;
	}

	return handle_cn_ranap(cnlink, param, msgb_l2(oph->msg), msgb_l2len(oph->msg));
}

static int handle_cn_conn_conf(struct hnbgw_sccp_user *hsu,
			       const struct osmo_scu_connect_param *param,
			       struct osmo_prim_hdr *oph)
{
	struct hnbgw_context_map *map;

	map = map_from_conn_id(hsu, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_conn_conf() conn_id=%d, addrs: called=%s calling=%s responding=%s\n",
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

	map = map_from_conn_id(hsu, param->conn_id, oph);
	if (!map || !map->cnlink)
		return -ENOENT;

	LOGP(DMAIN, LOGL_DEBUG, "handle_cn_disc_ind() conn_id=%u responding_addr=%s\n",
	     param->conn_id,
	     cnlink_sccp_addr_to_str(map->cnlink, &param->responding_addr));

	return map_sccp_dispatch(map, MAP_SCCP_EV_RX_RELEASED, oph->msg);
}

/* Entry point for primitives coming up from SCCP User SAP */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_sccp_user *scu = ctx;
	struct hnbgw_sccp_user *hsu;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	int rc = 0;

	LOGP(DMAIN, LOGL_DEBUG, "sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	if (!scu) {
		LOGP(DMAIN, LOGL_ERROR,
		     "sccp_sap_up(): NULL osmo_sccp_user, cannot send prim (sap %u prim %u op %d)\n",
		     oph->sap, oph->primitive, oph->operation);
		return -1;
	}

	hsu = osmo_sccp_user_get_priv(scu);
	if (!hsu) {
		LOGP(DMAIN, LOGL_ERROR,
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

/* If not present yet, set up all of osmo_ss7_instance, osmo_sccp_instance and hnbgw_sccp_user for the given cnlink.
 * The cs7 instance nr to use is determined by cnlink->remote_addr_name, or cs7 instance 0 if that is not present.
 * Set cnlink->hnbgw_sccp_user to the new SCCP instance. Return 0 on success, negative on error. */
int cnlink_ensure_sccp(struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_instance *ss7 = NULL;
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *sccp_user;
	uint32_t local_pc;
	struct hnbgw_sccp_user *hsu;

	/* If a hnbgw_sccp_user has already been set up, use that. */
	if (cnlink->hnbgw_sccp_user) {
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "SCCP instance already set up, using %s\n",
			   cnlink->hnbgw_sccp_user->name);
		return 0;
	}
	LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "no SCCP instance selected yet\n");

	/* Figure out which cs7 instance to use. If cnlink->remote_addr_name is set, it points to an address book entry
	 * in a specific cs7 instance. If it is not set, leave ss7 == NULL to use cs7 instance 0. */
	if (cnlink->remote_addr_name) {
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "resolving 'remote-addr %s'\n", cnlink->remote_addr_name);
		if (resolve_addr_name(&cnlink->remote_addr, &ss7, cnlink->remote_addr_name, cnlink->name,
				      DEFAULT_PC_HNBGW)) {
			LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "cannot initialize SCCP: there is no SCCP address named '%s'\n",
				   cnlink->remote_addr_name);
			return -ENOENT;
		}

		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "remote-addr is '%s', using cs7 instance %u\n",
			   cnlink->remote_addr_name, ss7->cfg.id);
	} else {
		/* If no address is configured, use the default remote CN address, according to legacy behavior. */
		uint32_t remote_pc;
		switch (cnlink->domain) {
		case DOMAIN_CS:
			remote_pc = DEFAULT_PC_MSC;
			break;
		case DOMAIN_PS:
			remote_pc = DEFAULT_PC_SGSN;
			break;
		default:
			return -EINVAL;
		}
		osmo_sccp_make_addr_pc_ssn(&cnlink->remote_addr, remote_pc, OSMO_SCCP_SSN_RANAP);
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
			cnlink->hnbgw_sccp_user = hsu;
			LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "using existing SCCP instance %s on cs7 instance %u\n",
				   hsu->name, ss7->cfg.id);
			return 0;
		}
		/* else cnlink->hnbgw_sccp_user stays NULL and is set up below. */
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "cs7 instance %u has no SCCP instance yet\n", ss7->cfg.id);

		/* All SCCP instances should originate from this function. So if there is no hnbgw_sccp_user for the cs7
		 * instance, then the cs7 instance should not have an SCCP instance yet. */
		OSMO_ASSERT(!ss7->sccp);
	}

	/* No SCCP instance yet for this ss7. Create it. If no address name is given that resolves to a
	 * particular cs7 instance above, use 'cs7 instance 0'. */
	sccp = osmo_sccp_simple_client_on_ss7_id(g_hnbgw, ss7 ? ss7->cfg.id : 0, cnlink->name, DEFAULT_PC_HNBGW,
						 OSMO_SS7_ASP_PROT_M3UA, 0, "localhost", -1, "localhost");
	if (!sccp) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Failed to configure 'cs7 instance %u'\n", ss7->cfg.id);
		return -1;
	}
	ss7 = osmo_sccp_get_ss7(sccp);
	LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "created SCCP instance on cs7 instance %u\n", ss7->cfg.id);

	/* Bind the SCCP user, using the cs7 instance's default point-code if one is configured, or osmo-hnbgw's default
	 * local PC. */
	if (osmo_ss7_pc_is_valid(ss7->cfg.primary_pc))
		local_pc = ss7->cfg.primary_pc;
	else
		local_pc = DEFAULT_PC_HNBGW;

	LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "binding OsmoHNBGW user to cs7 instance %u, local PC %u = %s\n",
		   ss7->cfg.id, local_pc, osmo_ss7_pointcode_print(ss7, local_pc));

	sccp_user = osmo_sccp_user_bind_pc(sccp, "OsmoHNBGW", sccp_sap_up, OSMO_SCCP_SSN_RANAP, local_pc);
	if (!sccp_user) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to init SCCP User\n");
		return -1;
	}

	hsu = talloc_zero(cnlink, struct hnbgw_sccp_user);
	*hsu = (struct hnbgw_sccp_user){
		.name = talloc_asprintf(hsu, "cs7-%u.sccp", ss7->cfg.id),
		.ss7 = ss7,
		.sccp_user = sccp_user,
	};
	osmo_sccp_make_addr_pc_ssn(&hsu->local_addr, local_pc, OSMO_SCCP_SSN_RANAP);
	hash_init(hsu->hnbgw_context_map_by_conn_id);
	osmo_sccp_user_set_priv(sccp_user, hsu);

	llist_add_tail(&hsu->entry, &g_hnbgw->sccp.users);

	cnlink->hnbgw_sccp_user = hsu;
	return 0;
}

struct hnbgw_cnlink *hnbgw_cnlink_alloc(const char *remote_addr_name, RANAP_CN_DomainIndicator_t domain)
{
	struct hnbgw_cnlink *cnlink;

	cnlink = talloc_zero(g_hnbgw, struct hnbgw_cnlink);
	*cnlink = (struct hnbgw_cnlink){
		.name = (domain == DOMAIN_CS ? "msc-0" : "sgsn-0"),
		.domain = domain,
		.remote_addr_name = talloc_strdup(cnlink, remote_addr_name),
	};

	INIT_LLIST_HEAD(&cnlink->map_list);

	if (cnlink_ensure_sccp(cnlink)) {
		/* error logging already in cnlink_ensure_sccp() */
		talloc_free(cnlink);
		return NULL;
	}

	switch (domain) {
	case DOMAIN_CS:
		OSMO_ASSERT(!g_hnbgw->sccp.cnlink_iucs);
		g_hnbgw->sccp.cnlink_iucs = cnlink;
		break;
	case DOMAIN_PS:
		OSMO_ASSERT(!g_hnbgw->sccp.cnlink_iups);
		g_hnbgw->sccp.cnlink_iups = cnlink;
		break;
	default:
		OSMO_ASSERT(false);
	}

	return cnlink;
}

const struct osmo_sccp_addr *hnbgw_cn_get_remote_addr(bool is_ps)
{
	struct hnbgw_cnlink *cnlink = is_ps ? g_hnbgw->sccp.cnlink_iups : g_hnbgw->sccp.cnlink_iucs;
	if (!cnlink)
		return NULL;
	return &cnlink->remote_addr;
}

static bool cnlink_matches(const struct hnbgw_cnlink *cnlink, const struct hnbgw_sccp_user *hsu, const struct osmo_sccp_addr *remote_addr)
{
	if (cnlink->hnbgw_sccp_user != hsu)
		return false;
	if (osmo_sccp_addr_cmp(&cnlink->remote_addr, remote_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
		return false;
	return true;
}
struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_user *hsu,
					       const struct osmo_sccp_addr *remote_addr)
{
	/* FUTURE: loop over llist g_hnb_gw->sccp.cnpool */
	if (cnlink_matches(g_hnbgw->sccp.cnlink_iucs, hsu, remote_addr))
		return g_hnbgw->sccp.cnlink_iucs;
	if (cnlink_matches(g_hnbgw->sccp.cnlink_iups, hsu, remote_addr))
		return g_hnbgw->sccp.cnlink_iups;
	return NULL;
}

struct hnbgw_cnlink *hnbgw_cnlink_select(bool is_ps)
{
	/* FUTURE: soon we will pick one of many configurable CN peers from a pool. There will be more input arguments
	 * (MI, or TMSI, or NRI decoded from RANAP) and this function will do round robin for new subscribers. */
	if (is_ps)
		return g_hnbgw->sccp.cnlink_iups;
	return g_hnbgw->sccp.cnlink_iucs;
}

char *cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr)
{
	struct osmo_sccp_instance *sccp = cnlink_sccp(cnlink);
	if (!sccp)
		return osmo_sccp_addr_dump(addr);
	return osmo_sccp_inst_addr_to_str_c(OTC_SELECT, sccp, addr);
}
