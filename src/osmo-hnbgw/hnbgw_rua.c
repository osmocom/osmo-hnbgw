/* hnb-gw specific code for RUA (Ranap User Adaption), 3GPP TS 25.468 */

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

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "asn1helpers.h"

#include <osmocom/hnbgw/hnb.h>
#include <osmocom/hnbgw/hnb_persistent.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/hnbgw_ranap.h>
#include <osmocom/rua/rua_common.h>
#include <osmocom/rua/rua_ies_defs.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbap/HNBAP_CN-DomainIndicator.h>

static int hnbgw_rua_tx(struct hnb_context *ctx, struct msgb *msg)
{
	if (!msg)
		return -EINVAL;

	if (!ctx || !ctx->conn) {
		LOGHNB(ctx, DRUA, LOGL_ERROR, "RUA context to this HNB is not connected, cannot transmit message\n");
		return -ENOTCONN;
	}

	msgb_sctp_ppid(msg) = IUH_PPI_RUA;
	osmo_stream_srv_send(ctx->conn, msg);

	return 0;
}

int rua_tx_udt(struct hnb_context *hnb, const uint8_t *data, unsigned int len)
{
	RUA_ConnectionlessTransfer_t out;
	RUA_ConnectionlessTransferIEs_t ies;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	ies.ranaP_Message.buf = (uint8_t *) data;
	ies.ranaP_Message.size = len;

	/* FIXME: msgb_free(msg)? ownership not yet clear */

	memset(&out, 0, sizeof(out));
	rc = rua_encode_connectionlesstransferies(&out, &ies);
	if (rc < 0)
		return rc;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_ConnectionlessTransfer,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_ConnectionlessTransfer,
					      &out);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_ConnectionlessTransfer, &out);

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "transmitting RUA payload of %u bytes\n", msgb_length(msg));
	HNBP_CTR_INC(hnb->persistent, HNB_CTR_RUA_UDT_DL);

	return hnbgw_rua_tx(hnb, msg);
}

int rua_tx_dt(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	      const uint8_t *data, unsigned int len)
{
	RUA_DirectTransfer_t out;
	RUA_DirectTransferIEs_t ies;
	uint32_t ctxidbuf;
	struct msgb *msg;
	int rc;

	memset(&ies, 0, sizeof(ies));
	if (is_ps)
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_cs_domain;
	asn1_u24_to_bitstring(&ies.context_ID, &ctxidbuf, context_id);
	ies.ranaP_Message.buf = (uint8_t *) data;
	ies.ranaP_Message.size = len;

	/* FIXME: msgb_free(msg)? ownership not yet clear */

	memset(&out, 0, sizeof(out));
	rc = rua_encode_directtransferies(&out, &ies);
	if (rc < 0)
		return rc;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_DirectTransfer,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_DirectTransfer,
					      &out);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_DirectTransfer, &out);

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "transmitting RUA DirectTransfer (cn=%s) payload of %u bytes\n",
		is_ps ? "ps" : "cs", msgb_length(msg));
	HNBP_CTR_INC(hnb->persistent, is_ps ? HNB_CTR_RUA_PS_DT_DL : HNB_CTR_RUA_CS_DT_DL);

	return hnbgw_rua_tx(hnb, msg);
}

int rua_tx_disc(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	        const RUA_Cause_t *cause, const uint8_t *data, unsigned int len)
{
	RUA_Disconnect_t out;
	RUA_DisconnectIEs_t ies;
	struct msgb *msg;
	uint32_t ctxidbuf;
	int rc;

	memset(&ies, 0, sizeof(ies));
	if (is_ps)
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_ps_domain;
	else
		ies.cN_DomainIndicator = RUA_CN_DomainIndicator_cs_domain;
	asn1_u24_to_bitstring(&ies.context_ID, &ctxidbuf, context_id);
	memcpy(&ies.cause, cause, sizeof(ies.cause));
	if (data && len) {
		ies.presenceMask |= DISCONNECTIES_RUA_RANAP_MESSAGE_PRESENT;
		ies.ranaP_Message.buf = (uint8_t *) data;
		ies.ranaP_Message.size = len;
	}

	memset(&out, 0, sizeof(out));
	rc = rua_encode_disconnecties(&out, &ies);
	if (rc < 0)
		return rc;

	msg = rua_generate_initiating_message(RUA_ProcedureCode_id_Disconnect,
					      RUA_Criticality_reject,
					      &asn_DEF_RUA_Disconnect,
					      &out);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_Disconnect, &out);

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "transmitting RUA Disconnect (cn=%s) payload of %u bytes\n",
	       is_ps ? "ps" : "cs", msgb_length(msg));
	HNBP_CTR_INC(hnb->persistent, is_ps ? HNB_CTR_RUA_PS_DISCONNECT_DL : HNB_CTR_RUA_CS_DISCONNECT_DL);

	return hnbgw_rua_tx(hnb, msg);
}

/* Send Disconnect to RUA without RANAP data */
static void rua_tx_disc_conn_fail(struct hnb_context *hnb, bool is_ps, uint32_t context_id)
{
	RUA_Cause_t rua_cause = {
		.present = RUA_Cause_PR_radioNetwork,
		.choice.radioNetwork = RUA_CauseRadioNetwork_connect_failed,
	};

	LOG_HNBP(hnb->persistent, LOGL_INFO, "Tx RUA Disconnect\n");

	if (rua_tx_disc(hnb, is_ps, context_id, &rua_cause, NULL, 0))
		LOG_HNBP(hnb->persistent, LOGL_ERROR, "Failed to send Disconnect to RUA\n");
}

static struct value_string rua_procedure_code_names[] = {
	{ RUA_ProcedureCode_id_Connect, "Connect" },
	{ RUA_ProcedureCode_id_DirectTransfer, "DirectTransfer" },
	{ RUA_ProcedureCode_id_Disconnect, "Disconnect" },
	{ RUA_ProcedureCode_id_ConnectionlessTransfer, "ConnectionlessTransfer" },
	{ RUA_ProcedureCode_id_ErrorIndication, "ErrorIndication" },
	{ RUA_ProcedureCode_id_privateMessage, "PrivateMessage" },
	{}
};

static inline const char *rua_procedure_code_name(enum RUA_ProcedureCode val)
{
	return get_value_string(rua_procedure_code_names, val);
}

static struct hnbgw_context_map *create_context_map(struct hnb_context *hnb, uint32_t rua_ctx_id, bool is_ps,
						    struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map;
	struct hnbgw_cnlink *cnlink;

	/* Establish a new context map. From the RUA Connect, extract a mobile identity, if any, and select a CN link
	 * based on an NRI found in the mobile identity, if any. */

	/* Allocate a map for logging context */
	map = context_map_alloc(hnb, rua_ctx_id, is_ps);
	OSMO_ASSERT(map);

	if (hnbgw_peek_l3_ul(map, ranap_msg))
		LOGP(DCN, LOGL_NOTICE, "Failed to extract Mobile Identity from RUA Connect message's RANAP payload\n");
	/* map->l3 now contains all the interesting information from the NAS PDU, if any.
	 * If no useful information could be decoded, still continue to select a hopefully adequate link by round robin.
	 */

	cnlink = hnbgw_cnlink_select(map);
	if (!cnlink) {
		LOG_MAP(map, DCN, LOGL_ERROR, "Failed to select %s link\n", is_ps ? "IuPS" : "IuCS");
		context_map_free(map);
		return NULL;
	}

	if (context_map_set_cnlink(map, cnlink)) {
		LOG_MAP(map, DCN, LOGL_ERROR, "Failed to establish link to %s\n", cnlink->name);
		context_map_free(map);
		return NULL;
	}

	return map;
}

/* dispatch a RUA connection-oriented message received from a HNB to a context mapping's RUA FSM, so that it is
 * forwarded to the CN via SCCP connection-oriented messages.
 * Connectionless messages are handled in hnbgw_ranap_rx_udt_ul() instead, not here. */
static int rua_to_scu(struct hnb_context *hnb,
		      RUA_CN_DomainIndicator_t cN_DomainIndicator,
		      enum RUA_ProcedureCode rua_procedure,
		      uint32_t context_id, uint32_t cause,
		      const uint8_t *data, unsigned int len)
{
	struct msgb *ranap_msg = NULL;
	struct hnbgw_context_map *map = NULL;
	bool is_ps;

	switch (cN_DomainIndicator) {
	case RUA_CN_DomainIndicator_cs_domain:
		is_ps = false;
		break;
	case RUA_CN_DomainIndicator_ps_domain:
		is_ps = true;
		break;
	default:
		LOGHNB(hnb, DRUA, LOGL_ERROR, "Unsupported Domain %ld\n", cN_DomainIndicator);
		return -1;
	}

	/* If there is RANAP data, include it in the msgb. In RUA there is always data in practice, but theoretically it
	 * could be an empty Connect or Disconnect. */
	if (data && len) {
		/* According to API doc of map_rua_fsm_event: allocate msgb for RANAP data from OTC_SELECT, reserve
		 * headroom for an osmo_scu_prim. Point l2h at the RANAP data. */
		ranap_msg = hnbgw_ranap_msg_alloc("RANAP_from_RUA");
		ranap_msg->l2h = msgb_put(ranap_msg, len);
		memcpy(ranap_msg->l2h, data, len);
	}

	map = context_map_find_by_rua_ctx_id(hnb, context_id, is_ps);

	switch (rua_procedure) {
	case RUA_ProcedureCode_id_Connect:
		/* A Connect message can only be the first message for an unused RUA context */
		if (map) {
			/* Already established this RUA context. But then how can it be a Connect message. */
			LOGHNB(hnb, DRUA, LOGL_NOTICE, "rx RUA %s for already active RUA context %u\n",
			       rua_procedure_code_name(rua_procedure), context_id);
			return -EINVAL;
		}
		/* ok, this RUA context does not exist yet, so create one. */
		map = create_context_map(hnb, context_id, is_ps, ranap_msg);
		if (!map) {
			LOGHNB(hnb, DRUA, LOGL_ERROR,
			       "Failed to create context map for %s: rx RUA %s with %u bytes RANAP data\n",
			       is_ps ? "IuPS" : "IuCS", rua_procedure_code_name(rua_procedure), data ? len : 0);
			rua_tx_disc_conn_fail(hnb, is_ps, context_id);
			return -EINVAL;
		}
		break;

	case RUA_ProcedureCode_id_Disconnect:
		/* For RUA Disconnect, do not spam the ERROR log. It is just a stray Disconnect, no harm done.
		 * Context: some CN are known to rapidly tear down SCCP without waiting for RUA to disconnect gracefully
		 * (IU Release Complete). Such CN would cause ERROR logging for each and every released context map. */
		if (!map) {
			LOGHNB(hnb, DRUA, LOGL_DEBUG, "rx RUA %s for unknown RUA context %u\n",
			       rua_procedure_code_name(rua_procedure), context_id);
			return -EINVAL;
		}
		break;

	default:
		/* Any message other than Connect must have a valid RUA context */
		if (!map) {
			LOGHNB(hnb, DRUA, LOGL_NOTICE, "rx RUA %s for unknown RUA context %u\n",
			       rua_procedure_code_name(rua_procedure), context_id);
			rua_tx_disc_conn_fail(hnb, is_ps, context_id);
			return -EINVAL;
		}
		break;
	}

	LOG_MAP(map, DRUA, LOGL_DEBUG, "rx RUA %s with %u bytes RANAP data\n",
		rua_procedure_code_name(rua_procedure), data ? len : 0);

	switch (rua_procedure) {

	case RUA_ProcedureCode_id_Connect:
		return map_rua_dispatch(map, MAP_RUA_EV_RX_CONNECT, ranap_msg);

	case RUA_ProcedureCode_id_DirectTransfer:
		return map_rua_dispatch(map, MAP_RUA_EV_RX_DIRECT_TRANSFER, ranap_msg);

	case RUA_ProcedureCode_id_Disconnect:
		return map_rua_dispatch(map, MAP_RUA_EV_RX_DISCONNECT, ranap_msg);

	default:
		/* No caller may ever pass a different RUA procedure code */
		OSMO_ASSERT(false);
	}
}

static uint32_t rua_to_scu_cause(RUA_Cause_t *in)
{
	/* FIXME: Implement this! */
#if 0
	switch (in->present) {
	case RUA_Cause_PR_NOTHING:
		break;
	case RUA_Cause_PR_radioNetwork:
		switch (in->choice.radioNetwork) {
		case RUA_CauseRadioNetwork_normal:
		case RUA_CauseRadioNetwork_connect_failed:
		case RUA_CauseRadioNetwork_network_release:
		case RUA_CauseRadioNetwork_unspecified:
		}
		break;
	case RUA_Cause_PR_transport:
		switch (in->choice.transport) {
		case RUA_CauseTransport_transport_resource_unavailable:
			break;
		case RUA_CauseTransport_unspecified:
			break;
		}
		break;
	case RUA_Cause_PR_protocol:
		switch (in->choice.protocol) {
		case RUA_CauseProtocol_transfer_syntax_error:
			break;
		case RUA_CauseProtocol_abstract_syntax_error_reject:
			break;
		case RUA_CauseProtocol_abstract_syntax_error_ignore_and_notify:
			break;
		case RUA_CauseProtocol_message_not_compatible_with_receiver_state:
			break;
		case RUA_CauseProtocol_semantic_error:
			break;
		case RUA_CauseProtocol_unspecified:
			break;
		case RUA_CauseProtocol_abstract_syntax_error_falsely_constructed_message:
			break;
		}
		break;
	case RUA_Cause_PR_misc:
		switch (in->choice.misc) {
		case RUA_CauseMisc_processing_overload:
			break;
		case RUA_CauseMisc_hardware_failure:
			break;
		case RUA_CauseMisc_o_and_m_intervention:
			break;
		case RUA_CauseMisc_unspecified:
			break;
		}
		break;
	default:
		break;
	}
#else
	return 0;
#endif

}

static int rua_rx_init_connect(struct msgb *msg, ANY_t *in)
{
	RUA_ConnectIEs_t ies;
	struct hnb_context *hnb = msg->dst;
	uint32_t context_id;
	int rc;

	rc = rua_decode_connecties(&ies, in);
	if (rc < 0)
		return rc;

	context_id = asn1bitstr_to_u24(&ies.context_ID);

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "RUA %s Connect.req(ctx=0x%x, %s)\n",
		ranap_domain_name(ies.cN_DomainIndicator), context_id,
		ies.establishment_Cause == RUA_Establishment_Cause_emergency_call ? "emergency" : "normal");
	HNBP_CTR_INC(hnb->persistent, ies.cN_DomainIndicator == DOMAIN_PS ?
		     HNB_CTR_RUA_PS_CONNECT_UL : HNB_CTR_RUA_CS_CONNECT_UL);

	rc = rua_to_scu(hnb, ies.cN_DomainIndicator, RUA_ProcedureCode_id_Connect,
			context_id, 0, ies.ranaP_Message.buf,
			ies.ranaP_Message.size);

	rua_free_connecties(&ies);

	return rc;
}

static int rua_rx_init_disconnect(struct msgb *msg, ANY_t *in)
{
	RUA_DisconnectIEs_t ies;
	struct hnb_context *hnb = msg->dst;
	uint32_t context_id;
	uint32_t scu_cause;
	uint8_t *ranap_data = NULL;
	unsigned int ranap_len = 0;
	int rc;

	rc = rua_decode_disconnecties(&ies, in);
	if (rc < 0)
		return rc;

	context_id = asn1bitstr_to_u24(&ies.context_ID);
	scu_cause = rua_to_scu_cause(&ies.cause);

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "RUA Disconnect.req(ctx=0x%x,cause=%s)\n", context_id,
		rua_cause_str(&ies.cause));
	HNBP_CTR_INC(hnb->persistent, ies.cN_DomainIndicator == DOMAIN_PS ?
		     HNB_CTR_RUA_PS_DISCONNECT_UL : HNB_CTR_RUA_CS_DISCONNECT_UL);

	if (ies.presenceMask & DISCONNECTIES_RUA_RANAP_MESSAGE_PRESENT) {
		ranap_data = ies.ranaP_Message.buf;
		ranap_len = ies.ranaP_Message.size;
	}

	rc = rua_to_scu(hnb, ies.cN_DomainIndicator,
			RUA_ProcedureCode_id_Disconnect,
			context_id, scu_cause, ranap_data, ranap_len);

	rua_free_disconnecties(&ies);

	return rc;
}

static int rua_rx_init_dt(struct msgb *msg, ANY_t *in)
{
	RUA_DirectTransferIEs_t ies;
	struct hnb_context *hnb = msg->dst;
	uint32_t context_id;
	int rc;

	rc = rua_decode_directtransferies(&ies, in);
	if (rc < 0)
		return rc;

	context_id = asn1bitstr_to_u24(&ies.context_ID);

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "RUA Data.req(ctx=0x%x)\n", context_id);
	HNBP_CTR_INC(hnb->persistent, ies.cN_DomainIndicator == DOMAIN_PS ?
		     HNB_CTR_RUA_PS_DT_UL : HNB_CTR_RUA_CS_DT_UL);

	rc = rua_to_scu(hnb,
			ies.cN_DomainIndicator,
			RUA_ProcedureCode_id_DirectTransfer,
			context_id, 0, ies.ranaP_Message.buf,
			ies.ranaP_Message.size);

	rua_free_directtransferies(&ies);

	return rc;
}

static int rua_rx_init_udt(struct msgb *msg, ANY_t *in)
{
	RUA_ConnectionlessTransferIEs_t ies;
	struct hnb_context *hnb = msg->dst;
	int rc;

	rc = rua_decode_connectionlesstransferies(&ies, in);
	if (rc < 0)
		return rc;

	LOGHNB(hnb, DRUA, LOGL_DEBUG, "RUA UData.req()\n");
	HNBP_CTR_INC(hnb->persistent, HNB_CTR_RUA_UDT_UL);

	/* according tot the spec, we can primarily receive Overload,
	 * Reset, Reset ACK, Error Indication, reset Resource, Reset
	 * Resurce Acknowledge as connecitonless RANAP.  There are some
	 * more messages regarding Information Transfer, Direct
	 * Information Transfer and Uplink Information Trnansfer that we
	 * can ignore.  In either case, it is RANAP that we need to
	 * decode... */
	rc = hnbgw_ranap_rx_udt_ul(msg, ies.ranaP_Message.buf, ies.ranaP_Message.size);
	rua_free_connectionlesstransferies(&ies);

	return rc;
}


static int rua_rx_init_err_ind(struct msgb *msg, ANY_t *in)
{
	RUA_ErrorIndicationIEs_t ies;
	struct hnb_context *hnb = msg->dst;
	int rc;

	rc = rua_decode_errorindicationies(&ies, in);
	if (rc < 0)
		return rc;

	LOGHNB(hnb, DRUA, LOGL_ERROR, "RUA UData.ErrorInd(%s)\n", rua_cause_str(&ies.cause));
	HNBP_CTR_INC(hnb->persistent, HNB_CTR_RUA_ERR_IND);

	rua_free_errorindicationies(&ies);
	return rc;
}

static int rua_rx_initiating_msg(struct msgb *msg, RUA_InitiatingMessage_t *imsg)
{
	struct hnb_context *hnb = msg->dst;
	int rc;

	switch (imsg->procedureCode) {
	case RUA_ProcedureCode_id_Connect:
		rc = rua_rx_init_connect(msg, &imsg->value);
		break;
	case RUA_ProcedureCode_id_DirectTransfer:
		rc = rua_rx_init_dt(msg, &imsg->value);
		break;
	case RUA_ProcedureCode_id_Disconnect:
		rc = rua_rx_init_disconnect(msg, &imsg->value);
		break;
	case RUA_ProcedureCode_id_ConnectionlessTransfer:
		rc = rua_rx_init_udt(msg, &imsg->value);
		break;
	case RUA_ProcedureCode_id_ErrorIndication:
		rc = rua_rx_init_err_ind(msg, &imsg->value);
		break;
	case RUA_ProcedureCode_id_privateMessage:
		LOGHNB(hnb, DRUA, LOGL_NOTICE, "Unhandled: RUA Initiating Msg: Private Msg\n");
		rc = 0;
		break;
	default:
		LOGHNB(hnb, DRUA, LOGL_NOTICE, "Unknown RUA Procedure %lu\n", imsg->procedureCode);
		rc = -1;
	}

	return rc;
}

static int rua_rx_successful_outcome_msg(struct msgb *msg, RUA_SuccessfulOutcome_t *in)
{
	struct hnb_context *hnb = msg->dst;
	/* FIXME */
	LOGHNB(hnb, DRUA, LOGL_NOTICE, "Unexpected RUA Successful Outcome\n");
	return -1;
}

static int rua_rx_unsuccessful_outcome_msg(struct msgb *msg, RUA_UnsuccessfulOutcome_t *in)
{
	struct hnb_context *hnb = msg->dst;
	/* FIXME */
	LOGHNB(hnb, DRUA, LOGL_NOTICE, "Unexpected RUA Unsucessful Outcome\n");
	return -1;
}


static int _hnbgw_rua_rx(struct msgb *msg, RUA_RUA_PDU_t *pdu)
{
	struct hnb_context *hnb = msg->dst;
	int rc;

	/* it's a bit odd that we can't dispatch on procedure code, but
	 * that's not possible */
	switch (pdu->present) {
	case RUA_RUA_PDU_PR_initiatingMessage:
		rc = rua_rx_initiating_msg(msg, &pdu->choice.initiatingMessage);
		break;
	case RUA_RUA_PDU_PR_successfulOutcome:
		rc = rua_rx_successful_outcome_msg(msg, &pdu->choice.successfulOutcome);
		break;
	case RUA_RUA_PDU_PR_unsuccessfulOutcome:
		rc = rua_rx_unsuccessful_outcome_msg(msg, &pdu->choice.unsuccessfulOutcome);
		break;
	default:
		LOGHNB(hnb, DRUA, LOGL_NOTICE, "Unknown RUA presence %u\n", pdu->present);
		rc = -1;
	}

	return rc;
}

int hnbgw_rua_rx(struct hnb_context *hnb, struct msgb *msg)
{
	RUA_RUA_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	/* RUA is only processed after HNB registration, and as soon as the HNB is registered,
	 * it should have a persistent config associated with it */
	OSMO_ASSERT(hnb->persistent);

	/* decode and handle to _hnbgw_hnbap_rx() */

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_RUA_RUA_PDU, (void **) &pdu,
			      msg->data, msgb_length(msg), 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGHNB(hnb, DRUA, LOGL_ERROR, "Error in ASN.1 decode\n");
		return -1;
	}

	rc = _hnbgw_rua_rx(msg, pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RUA_RUA_PDU, pdu);

	return rc;
}
