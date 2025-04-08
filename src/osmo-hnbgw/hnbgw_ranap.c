/* hnb-gw specific code for RANAP, 3GPP TS 25.413 */

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

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "asn1helpers.h"

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_ran.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_cp_peer.h>
#endif

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/mgw_fsm.h>
#include <osmocom/hnbgw/ps_rab_ass_fsm.h>
#include <osmocom/hnbgw/kpi.h>

/*****************************************************************************
 * Processing of RANAP from the endpoint towards RAN (hNodeB), acting as CN
 *****************************************************************************/

static int ranap_tx_udt_dl_reset_ack(struct hnb_context *hnb, RANAP_CN_DomainIndicator_t domain)
{
	struct msgb *msg;
	int rc;

	msg = ranap_new_msg_reset_ack(domain, NULL);
	if (!msg)
		return -1;

	rc = rua_tx_udt(hnb, msg->data, msgb_length(msg));

	msgb_free(msg);

	return rc;
}

static int ranap_rx_udt_ul_init_reset(struct hnb_context *hnb, ANY_t *in)
{
	RANAP_ResetIEs_t ies;
	int rc, is_ps = 0;

	rc = ranap_decode_reseties(&ies, in);
	if (rc < 0)
		return rc;

	if (ies.cN_DomainIndicator == RANAP_CN_DomainIndicator_ps_domain)
		is_ps=1;

	LOGHNB(hnb, DRANAP, LOGL_INFO, "Rx RESET.req(%s,%s)\n", is_ps ? "ps" : "cs",
		ranap_cause_str(&ies.cause));
	HNBP_CTR_INC(hnb->persistent, is_ps ? HNB_CTR_RANAP_PS_RESET_REQ_UL : HNB_CTR_RANAP_CS_RESET_REQ_UL);

	/* FIXME: Actually we have to wait for some guard time? */
	/* FIXME: Reset all resources related to this HNB/RNC */
	ranap_tx_udt_dl_reset_ack(hnb, ies.cN_DomainIndicator);

	return 0;
}

static int ranap_rx_udt_ul_error_ind(struct hnb_context *hnb, ANY_t *in)
{
	RANAP_ErrorIndicationIEs_t ies;
	int rc;
	bool is_ps = false;

	rc = ranap_decode_errorindicationies(&ies, in);
	if (rc < 0)
		return rc;

	if (ies.cN_DomainIndicator == RANAP_CN_DomainIndicator_ps_domain)
		is_ps = true;

	if (ies.presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT) {
		LOGHNB(hnb, DRANAP, LOGL_ERROR, "Rx ERROR.ind(%s)\n", ranap_cause_str(&ies.cause));
	} else
		LOGHNB(hnb, DRANAP, LOGL_ERROR, "Rx ERROR.ind\n");
	HNBP_CTR_INC(hnb->persistent, is_ps ? HNB_CTR_RANAP_PS_ERR_IND_UL : HNB_CTR_RANAP_CS_ERR_IND_UL);

	return 0;
}

static int ranap_rx_udt_ul_initiating_msg(struct hnb_context *hnb, RANAP_InitiatingMessage_t *imsg)
{
	int rc = 0;

	/* according tot the spec, we can primarily receive Overload,
	 * Reset, Reset ACK, Error Indication, reset Resource, Reset
	 * Resurce Acknowledge as connecitonless RANAP.  There are some
	 * more messages regarding Information Transfer, Direct
	 * Information Transfer and Uplink Information Trnansfer that we
	 * can ignore.  In either case, it is RANAP that we need to
	 * decode... */
	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset:
		/* Reset request */
		rc = ranap_rx_udt_ul_init_reset(hnb, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_OverloadControl: /* Overload ind */
		break;
	case RANAP_ProcedureCode_id_ErrorIndication: /* Error ind */
		rc = ranap_rx_udt_ul_error_ind(hnb, &imsg->value);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* request */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		LOGHNB(hnb, DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
			"Procedure %lu from HNB, ignoring\n", imsg->procedureCode);
		break;
	default:
		LOGHNB(hnb, DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
			"Procedure %lu from HNB, ignoring\n", imsg->procedureCode);
		break;
	}

	return rc;
}

static int ranap_rx_udt_ul_successful_msg(struct hnb_context *hnb, RANAP_SuccessfulOutcome_t *imsg)
{
	/* according tot the spec, we can primarily receive Overload,
	 * Reset, Reset ACK, Error Indication, reset Resource, Reset
	 * Resurce Acknowledge as connecitonless RANAP.  There are some
	 * more messages regarding Information Transfer, Direct
	 * Information Transfer and Uplink Information Trnansfer that we
	 * can ignore.  In either case, it is RANAP that we need to
	 * decode... */
	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset: /* Reset acknowledge */
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* response */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		LOGHNB(hnb, DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
			"Procedure %lu from HNB, ignoring\n", imsg->procedureCode);
		break;
	default:
		LOGHNB(hnb, DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
			"Procedure %lu from HNB, ignoring\n", imsg->procedureCode);
		break;
	}

	return 0;
}



static int _hnbgw_ranap_rx_udt_ul(struct hnb_context *hnb, RANAP_RANAP_PDU_t *pdu)
{
	int rc = 0;

	switch (pdu->present) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		rc = ranap_rx_udt_ul_initiating_msg(hnb, &pdu->choice.initiatingMessage);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		rc = ranap_rx_udt_ul_successful_msg(hnb, &pdu->choice.successfulOutcome);
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
		LOGHNB(hnb, DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
			"unsuccessful outcome procedure %lu from HNB, ignoring\n",
			pdu->choice.unsuccessfulOutcome.procedureCode);
		break;
	default:
		LOGHNB(hnb, DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
			"presence %u from HNB, ignoring\n", pdu->present);
		break;
	}

	return rc;
}

/* receive a RNAAP Unit-Data message in uplink direction */
int hnbgw_ranap_rx_udt_ul(struct msgb *msg, uint8_t *data, size_t len)
{
	RANAP_RANAP_PDU_t _pdu, *pdu = &_pdu;
	struct hnb_context *hnb = msg->dst;
	asn_dec_rval_t dec_ret;
	int rc;

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL,&asn_DEF_RANAP_RANAP_PDU, (void **) &pdu,
			      data, len, 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGHNB(hnb, DRANAP, LOGL_ERROR, "Error in RANAP ASN.1 decode\n");
		return -1;
	}

	rc = _hnbgw_ranap_rx_udt_ul(hnb, pdu);

	return rc;
}

static int destruct_ranap_cn_rx_co_ies(ranap_message *ranap_message_p)
{
	ranap_cn_rx_co_free(ranap_message_p);
	return 0;
}

/* Decode UL RANAP message with convenient memory freeing: just talloc_free() the returned pointer..
 * Allocate a ranap_message from OTC_SELECT, decode RANAP msgb into it, attach a talloc destructor that calls
 * ranap_cn_rx_co_free() upon talloc_free(), and return the decoded ranap_message. */
ranap_message *hnbgw_decode_ranap_cn_co(struct msgb *ranap_msg)
{
	int rc;
	ranap_message *message;

	if (!msg_has_l2_data(ranap_msg))
		return NULL;
	message = talloc_zero(OTC_SELECT, ranap_message);
	rc = ranap_cn_rx_co_decode2(message, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));
	if (rc != 0) {
		talloc_free(message);
		return NULL;
	}
	talloc_set_destructor(message, destruct_ranap_cn_rx_co_ies);
	return message;
}

/* Process a received RANAP PDU through SCCP DATA.ind coming from CN (MSC/SGSN)
 * Takes ownership of ranap_msg? */
int hnbgw_ranap_rx_data_ul(struct hnbgw_context_map *map, struct msgb *ranap_msg)
{
	OSMO_ASSERT(map);
	OSMO_ASSERT(msg_has_l2_data(ranap_msg));

	ranap_message *message = hnbgw_decode_ranap_cn_co(ranap_msg);
	if (message) {
		LOG_MAP(map, DHNB, LOGL_DEBUG, "rx from RUA: RANAP %s\n",
			get_value_string(ranap_procedure_code_vals, message->procedureCode));

		kpi_ranap_process_ul(map, message);

		if (!map->is_ps) {
			/* See if it is a RAB Assignment Response message from RUA to SCCP, where we need to change the user plane
			 * information, for RTP mapping via MGW, or GTP mapping via UPF. */
			switch (message->procedureCode) {
			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* mgw_fsm_handle_rab_ass_resp() takes ownership of prim->oph and (ranap) message */
				return mgw_fsm_handle_cs_rab_ass_resp(map, ranap_msg, message);
			}
		} else {
#if ENABLE_PFCP
			if (hnb_gw_is_gtp_mapping_enabled()) {
				/* map->is_ps == true and PFCP is enabled in osmo-hnbgw.cfg */
				switch (message->procedureCode) {
				case RANAP_ProcedureCode_id_RAB_Assignment:
					/* ps_rab_ass_fsm takes ownership of prim->oph and RANAP message */
					return hnbgw_gtpmap_rx_rab_ass_resp(map, ranap_msg, message);
				}
			}
#endif
		}
	}

	/* It was not a RAB Assignment Response that needed to be intercepted. Forward as-is to SCCP. */
	return map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, ranap_msg);
}

/*****************************************************************************
 * Processing of RANAP from the endpoint towards CN (MSC/SGSN), acting as RAN
 *****************************************************************************/

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

	if (rc) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Rx RESET: cannot decode IEs\n");
		return -1;
	}

	if (cnlink->pool->domain != domain) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Rx RESET indicates domain %s, but this is %s on domain %s\n",
			   ranap_domain_name(domain), cnlink->name, ranap_domain_name(cnlink->pool->domain));
		return -1;
	}

	cnlink_rx_reset_cmd(cnlink);
	return 0;
}

static int cn_ranap_rx_paging_cmd(struct hnbgw_cnlink *cnlink,
				  RANAP_InitiatingMessage_t *imsg,
				  const uint8_t *data, unsigned int len)
{
	const char *errmsg;
	struct hnb_context *hnb;
	bool is_ps = cnlink->pool->domain == DOMAIN_PS;

	errmsg = cnlink_paging_add_ranap(cnlink, imsg);
	if (errmsg) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Rx Paging from CN: %s. Dropping paging record."
			   " Later on, the Paging Response may be forwarded to the wrong CN peer.\n",
			   errmsg);
		return -1;
	}

	/* FIXME: determine which HNBs to send this Paging command,
	 * rather than broadcasting to all HNBs */
	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (!hnb->hnb_registered)
			continue;
		if (is_ps)
			HNBP_CTR_INC(hnb->persistent, HNB_CTR_PS_PAGING_ATTEMPTED);
		else
			HNBP_CTR_INC(hnb->persistent, HNB_CTR_CS_PAGING_ATTEMPTED);
		rua_tx_udt(hnb, data, len);
	}

	return 0;
}

static int ranap_rx_udt_dl_initiating_msg(struct hnbgw_cnlink *cnlink,
					  const struct osmo_scu_unitdata_param *unitdata,
					  RANAP_InitiatingMessage_t *imsg,
					  const uint8_t *data, unsigned int len)
{
	switch (imsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset:
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_RESET);
		return cn_ranap_rx_reset_cmd(cnlink, unitdata, imsg);
	case RANAP_ProcedureCode_id_Paging:
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_PAGING);
		return cn_ranap_rx_paging_cmd(cnlink, imsg, data, len);
	case RANAP_ProcedureCode_id_OverloadControl: /* Overload ind */
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_OVERLOAD_IND);
		break;
	case RANAP_ProcedureCode_id_ErrorIndication: /* Error ind */
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_ERROR_IND);
		break;
	case RANAP_ProcedureCode_id_ResetResource: /* request */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_UNSUPPORTED);
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "Procedure %ld from CN, ignoring\n", imsg->procedureCode);
		break;
	default:
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_UNKNOWN);
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %ld from CN, ignoring\n", imsg->procedureCode);
		break;
	}
	return 0;
}

static int cn_ranap_rx_reset_ack(struct hnbgw_cnlink *cnlink,
				 RANAP_SuccessfulOutcome_t *omsg)
{
	RANAP_CN_DomainIndicator_t domain;
	RANAP_ResetAcknowledgeIEs_t ies;
	int rc;

	rc = ranap_decode_resetacknowledgeies(&ies, &omsg->value);
	domain = ies.cN_DomainIndicator;
	ranap_free_resetacknowledgeies(&ies);

	if (rc) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Rx RESET ACK: cannot decode IEs\n");
		return -1;
	}

	if (cnlink->pool->domain != domain) {
		LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "Rx RESET ACK indicates domain %s, but this is %s on domain %s\n",
			   ranap_domain_name(domain), cnlink->name, ranap_domain_name(cnlink->pool->domain));
		return -1;
	}

	cnlink_rx_reset_ack(cnlink);
	return 0;
}

static int ranap_rx_udt_dl_successful_msg(struct hnbgw_cnlink *cnlink,
					  RANAP_SuccessfulOutcome_t *omsg)
{
	switch (omsg->procedureCode) {
	case RANAP_ProcedureCode_id_Reset: /* Reset acknowledge */
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_RESET);
		return cn_ranap_rx_reset_ack(cnlink, omsg);
	case RANAP_ProcedureCode_id_ResetResource: /* response */
	case RANAP_ProcedureCode_id_InformationTransfer:
	case RANAP_ProcedureCode_id_DirectInformationTransfer:
	case RANAP_ProcedureCode_id_UplinkInformationExchange:
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_UNSUPPORTED);
		LOGP(DRANAP, LOGL_NOTICE, "Received unsupported RANAP "
		     "Procedure %ld from CN, ignoring\n", omsg->procedureCode);
		break;
	default:
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_RANAP_RX_UDT_UNKNOWN);
		LOGP(DRANAP, LOGL_NOTICE, "Received suspicious RANAP "
		     "Procedure %ld from CN, ignoring\n", omsg->procedureCode);
		break;
	}
	return 0;
}

static int _hnbgw_ranap_rx_udt_dl(struct hnbgw_cnlink *cnlink,
				 const struct osmo_scu_unitdata_param *unitdata,
				 RANAP_RANAP_PDU_t *pdu, const uint8_t *data, unsigned int len)
{
	int rc;

	switch (pdu->present) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		rc = ranap_rx_udt_dl_initiating_msg(cnlink, unitdata, &pdu->choice.initiatingMessage, data, len);
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		rc = ranap_rx_udt_dl_successful_msg(cnlink, &pdu->choice.successfulOutcome);
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

int hnbgw_ranap_rx_udt_dl(struct hnbgw_cnlink *cnlink, const struct osmo_scu_unitdata_param *unitdata,
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

	rc = _hnbgw_ranap_rx_udt_dl(cnlink, unitdata, pdu, data, len);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RANAP_PDU, pdu);

	return rc;
}

static int destruct_ranap_ran_rx_co_ies(ranap_message *ranap_message_p)
{
	ranap_ran_rx_co_free(ranap_message_p);
	return 0;
}

/* Decode DL RANAP message with convenient memory freeing: just talloc_free() the returned pointer..
 * Allocate a ranap_message from OTC_SELECT, decode RANAP msgb into it, attach a talloc destructor that calls
 * ranap_cn_rx_co_free() upon talloc_free(), and return the decoded ranap_message. */
static ranap_message *hnbgw_decode_ranap_ran_co(struct msgb *ranap_msg)
{
	int rc;
	ranap_message *message;

	if (!msg_has_l2_data(ranap_msg))
		return NULL;
	message = talloc_zero(OTC_SELECT, ranap_message);
	rc = ranap_ran_rx_co_decode(NULL, message, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));
	if (rc != 0) {
		talloc_free(message);
		return NULL;
	}
	talloc_set_destructor(message, destruct_ranap_ran_rx_co_ies);
	return message;
}

/* Process a received RANAP PDU through SCCP DATA.ind coming from CN (MSC/SGSN)
 * Takes ownership of ranap_msg? */
int hnbgw_ranap_rx_data_dl(struct hnbgw_context_map *map, struct msgb *ranap_msg)
{
	OSMO_ASSERT(map);
	OSMO_ASSERT(msg_has_l2_data(ranap_msg));

	/* See if it is a RAB Assignment Request message from SCCP to RUA, where we need to change the user plane
	 * information, for RTP mapping via MGW, or GTP mapping via UPF. */
	ranap_message *message = hnbgw_decode_ranap_ran_co(ranap_msg);
	if (message) {
		talloc_set_destructor(message, destruct_ranap_ran_rx_co_ies);

		LOG_MAP(map, DCN, LOGL_DEBUG, "rx from SCCP: RANAP %s\n",
			get_value_string(ranap_procedure_code_vals, message->procedureCode));

		kpi_ranap_process_dl(map, message);

		if (!map->is_ps) {
			/* Circuit-Switched. Set up mapping of RTP ports via MGW */
			switch (message->procedureCode) {
			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* mgw_fsm_alloc_and_handle_rab_ass_req() takes ownership of (ranap) message */
				return handle_cs_rab_ass_req(map, ranap_msg, message);
			case RANAP_ProcedureCode_id_Iu_Release:
				/* Any IU Release will terminate the MGW FSM, the message itsself is not passed to the
				 * FSM code. It is just forwarded normally by map_rua_tx_dt() below. */
				mgw_fsm_release(map);
				break;
			}
#if ENABLE_PFCP
		} else {
			switch (message->procedureCode) {
			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* If a UPF is configured, handle the RAB Assignment via ps_rab_ass_fsm, and replace the
				 * GTP F-TEIDs in the RAB Assignment message before passing it on to RUA. */
				if (hnb_gw_is_gtp_mapping_enabled()) {
					LOG_MAP(map, DCN, LOGL_DEBUG,
						"RAB Assignment: setting up GTP tunnel mapping via UPF %s\n",
						osmo_sockaddr_to_str_c(OTC_SELECT, osmo_pfcp_cp_peer_get_remote_addr(g_hnbgw->pfcp.cp_peer)));
					return hnbgw_gtpmap_rx_rab_ass_req(map, ranap_msg, message);
				}
				/* If no UPF is configured, directly forward the message as-is (no GTP mapping). */
				LOG_MAP(map, DCN, LOGL_DEBUG, "RAB Assignment: no UPF configured, forwarding as-is\n");
				break;

			case RANAP_ProcedureCode_id_Iu_Release:
				/* Any IU Release will terminate the MGW FSM, the message itsself is not passed to the
				 * FSM code. It is just forwarded normally by map_rua_tx_dt() below. */
				hnbgw_gtpmap_release(map);
				break;
			}
#endif
		}
	}

	/* It was not a RAB Assignment Request that needed to be intercepted. Forward as-is to RUA. */
	return map_rua_dispatch(map, MAP_RUA_EV_TX_DIRECT_TRANSFER, ranap_msg);
}

int hnbgw_ranap_init(void)
{
	return 0;
}
