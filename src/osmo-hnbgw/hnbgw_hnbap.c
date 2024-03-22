/* hnb-gw specific code for HNBAP */

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

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/netif/stream.h>

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "asn1helpers.h"
#include <osmocom/hnbap/hnbap_common.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbap/hnbap_ies_defs.h>

#define IU_MSG_NUM_IES		32
#define IU_MSG_NUM_EXT_IES	32

static int hnbgw_hnbap_tx(struct hnb_context *ctx, struct msgb *msg)
{
	if (!msg)
		return -EINVAL;

	msgb_sctp_ppid(msg) = IUH_PPI_HNBAP;
	osmo_stream_srv_send(ctx->conn, msg);

	return 0;
}

static int hnbgw_tx_error_ind(struct hnb_context *ctx, const HNBAP_Cause_t *cause,
			      HNBAP_ProcedureCode_t proc_code, HNBAP_Criticality_t criticality,
			      HNBAP_TriggeringMessage_t trig_msg)
{
	HNBAP_ErrorIndication_t err_ind;
	HNBAP_ErrorIndicationIEs_t err_ind_ies;
	struct msgb *msg;
	int rc;

	LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Tx ErrorIndication cause=%s\n", hnbap_cause_str(cause));

	err_ind_ies.presenceMask = 0;
	err_ind_ies.cause = *cause;

	if (proc_code != -1 || trig_msg != -1 || criticality != -1) {
		err_ind_ies.presenceMask |= ERRORINDICATIONIES_HNBAP_CRITICALITYDIAGNOSTICS_PRESENT;
		if (proc_code != -1)
			err_ind_ies.criticalityDiagnostics.procedureCode = &proc_code;
		if (trig_msg != -1)
			err_ind_ies.criticalityDiagnostics.triggeringMessage = &trig_msg;
		if (criticality != -1)
			err_ind_ies.criticalityDiagnostics.procedureCriticality = &criticality;
	}

	memset(&err_ind, 0, sizeof(err_ind));
	rc = hnbap_encode_errorindicationies(&err_ind, &err_ind_ies);
	if (rc < 0) {
		LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Failure to encode ERROR-INDICATION to %s: rc=%d\n",
			ctx->identity_info, rc);
		return rc;
	}

	msg = hnbap_generate_initiating_message(HNBAP_ProcedureCode_id_ErrorIndication,
						HNBAP_Criticality_ignore,
						&asn_DEF_HNBAP_ErrorIndication,
						&err_ind);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_ErrorIndication, &err_ind);

	return hnbgw_hnbap_tx(ctx, msg);
}

static int hnbgw_tx_hnb_register_rej(struct hnb_context *ctx, const HNBAP_Cause_t *cause)
{
	HNBAP_HNBRegisterReject_t reject_out;
	HNBAP_HNBRegisterRejectIEs_t reject;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(cause);

	LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Rejecting HNB Register Request cause=%s\n", hnbap_cause_str(cause));

	reject.presenceMask = 0;
	reject.cause = *cause;

	/* encode the Information Elements */
	memset(&reject_out, 0, sizeof(reject_out));
	rc = hnbap_encode_hnbregisterrejecties(&reject_out,  &reject);
	if (rc < 0) {
		LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Failure to encode HNB-REGISTER-REJECT to %s: rc=%d\n",
			ctx->identity_info, rc);
		return rc;
	}

	/* generate a unsuccessful outcome PDU */
	msg = hnbap_generate_unsuccessful_outcome(HNBAP_ProcedureCode_id_HNBRegister,
						  HNBAP_Criticality_reject,
						  &asn_DEF_HNBAP_HNBRegisterReject,
						  &reject_out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_HNBRegisterReject, &reject_out);

	rc = hnbgw_hnbap_tx(ctx, msg);
	if (rc == 0) {
		/* Tell libosmo-netif to destroy this connection when it is done
		 * sending our HNB-REGISTER-REJECT response. */
		osmo_stream_srv_set_flush_and_destroy(ctx->conn);
	} else {
		/* The message was not queued. Destroy the connection right away. */
		hnb_context_release(ctx);
		return rc;
	}

	return 0;
}

static int hnbgw_tx_hnb_register_acc(struct hnb_context *ctx)
{
	HNBAP_HNBRegisterAccept_t accept_out;
	struct msgb *msg;
	int rc;

	/* Single required response IE: RNC-ID */
	HNBAP_HNBRegisterAcceptIEs_t accept = {
		.rnc_id = g_hnbgw->config.rnc_id
	};

	/* encode the Information Elements */
	memset(&accept_out, 0, sizeof(accept_out));
	rc = hnbap_encode_hnbregisteraccepties(&accept_out,  &accept);
	if (rc < 0) {
		LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Failure to encode HNB-REGISTER-ACCEPT to %s: rc=%d\n",
			ctx->identity_info, rc);
		return rc;
	}

	/* generate a successful outcome PDU */
	msg = hnbap_generate_successful_outcome(HNBAP_ProcedureCode_id_HNBRegister,
					       HNBAP_Criticality_reject,
					       &asn_DEF_HNBAP_HNBRegisterAccept,
					       &accept_out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_HNBRegisterAccept, &accept_out);

	LOGHNB(ctx, DHNBAP, LOGL_NOTICE, "Accepting HNB-REGISTER-REQ\n");

	return hnbgw_hnbap_tx(ctx, msg);
}


static int hnbgw_tx_ue_register_acc(struct ue_context *ue)
{
	HNBAP_UERegisterAccept_t accept_out;
	HNBAP_UERegisterAcceptIEs_t accept;
	struct msgb *msg;
	uint8_t encoded_imsi[10];
	uint32_t ctx_id;
	size_t encoded_imsi_len;
	int rc;

	encoded_imsi_len = ranap_imsi_encode(encoded_imsi,
					  sizeof(encoded_imsi), ue->imsi);

	memset(&accept, 0, sizeof(accept));
	accept.uE_Identity.present = HNBAP_UE_Identity_PR_iMSI;
	OCTET_STRING_fromBuf(&accept.uE_Identity.choice.iMSI,
			     (const char *)encoded_imsi, encoded_imsi_len);
	asn1_u24_to_bitstring(&accept.context_ID, &ctx_id, ue->context_id);

	memset(&accept_out, 0, sizeof(accept_out));
	rc = hnbap_encode_ueregisteraccepties(&accept_out, &accept);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &accept.uE_Identity.choice.iMSI);
	if (rc < 0) {
		return rc;
	}

	msg = hnbap_generate_successful_outcome(HNBAP_ProcedureCode_id_UERegister,
						HNBAP_Criticality_reject,
						&asn_DEF_HNBAP_UERegisterAccept,
						&accept_out);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_UERegisterAccept, &accept_out);

	return hnbgw_hnbap_tx(ue->hnb, msg);
}

static int hnbgw_tx_ue_register_rej(struct hnb_context *hnb, HNBAP_UE_Identity_t *ue_id, const struct HNBAP_Cause *cause)
{
	HNBAP_UERegisterReject_t reject_out;
	HNBAP_UERegisterRejectIEs_t reject;
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(cause);

	memset(&reject, 0, sizeof(reject));
	reject.uE_Identity.present = ue_id->present;

	/* Copy the identity over to the reject message */
	switch (ue_id->present) {
	case HNBAP_UE_Identity_PR_tMSILAI:
		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id tMSI %d %s\n", ue_id->choice.tMSILAI.tMSI.size,
			osmo_hexdump(ue_id->choice.tMSILAI.tMSI.buf, ue_id->choice.tMSILAI.tMSI.size));

		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id pLMNID %d %s\n", ue_id->choice.tMSILAI.lAI.pLMNID.size,
			osmo_hexdump(ue_id->choice.tMSILAI.lAI.pLMNID.buf, ue_id->choice.tMSILAI.lAI.pLMNID.size));

		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id lAC %d %s\n", ue_id->choice.tMSILAI.lAI.lAC.size,
			osmo_hexdump(ue_id->choice.tMSILAI.lAI.lAC.buf, ue_id->choice.tMSILAI.lAI.lAC.size));

		BIT_STRING_fromBuf(&reject.uE_Identity.choice.tMSILAI.tMSI,
				   ue_id->choice.tMSILAI.tMSI.buf,
				   ue_id->choice.tMSILAI.tMSI.size * 8
				   - ue_id->choice.tMSILAI.tMSI.bits_unused);
		OCTET_STRING_fromBuf(&reject.uE_Identity.choice.tMSILAI.lAI.pLMNID,
				     (const char *)ue_id->choice.tMSILAI.lAI.pLMNID.buf,
				     ue_id->choice.tMSILAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&reject.uE_Identity.choice.tMSILAI.lAI.lAC,
				     (const char *)ue_id->choice.tMSILAI.lAI.lAC.buf,
				     ue_id->choice.tMSILAI.lAI.lAC.size);
		break;

	case HNBAP_UE_Identity_PR_pTMSIRAI:
		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id pTMSI %d %s\n", ue_id->choice.pTMSIRAI.pTMSI.size,
			osmo_hexdump(ue_id->choice.pTMSIRAI.pTMSI.buf, ue_id->choice.pTMSIRAI.pTMSI.size));

		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id pLMNID %d %s\n", ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size,
			osmo_hexdump(ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.buf, ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size));

		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id lAC %d %s\n", ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size,
			osmo_hexdump(ue_id->choice.pTMSIRAI.rAI.lAI.lAC.buf, ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size));

		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id rAC %d %s\n", ue_id->choice.pTMSIRAI.rAI.rAC.size,
			osmo_hexdump(ue_id->choice.pTMSIRAI.rAI.rAC.buf, ue_id->choice.pTMSIRAI.rAI.rAC.size));

		BIT_STRING_fromBuf(&reject.uE_Identity.choice.pTMSIRAI.pTMSI,
				   ue_id->choice.pTMSIRAI.pTMSI.buf,
				   ue_id->choice.pTMSIRAI.pTMSI.size * 8
				   - ue_id->choice.pTMSIRAI.pTMSI.bits_unused);
		OCTET_STRING_fromBuf(&reject.uE_Identity.choice.pTMSIRAI.rAI.lAI.pLMNID,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&reject.uE_Identity.choice.pTMSIRAI.rAI.lAI.lAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.lAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size);
		OCTET_STRING_fromBuf(&reject.uE_Identity.choice.pTMSIRAI.rAI.rAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.rAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.rAC.size);
		break;

	case HNBAP_UE_Identity_PR_iMSI:
		ranap_bcd_decode(imsi, sizeof(imsi), ue_id->choice.iMSI.buf, ue_id->choice.iMSI.size);
		LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "REJ UE_Id IMSI %s\n", imsi);

		OCTET_STRING_fromBuf(&reject.uE_Identity.choice.iMSI,
				     (const char *)ue_id->choice.iMSI.buf, ue_id->choice.iMSI.size);
		break;

	default:
		LOGHNB(hnb, DHNBAP, LOGL_ERROR, "Cannot compose UE Register Reject:"
		     " unsupported UE ID (present=%d)\n", ue_id->present);
		return -1;
	}

	LOGHNB(hnb, DHNBAP, LOGL_ERROR, "Rejecting UE Register Request cause=%s\n", hnbap_cause_str(cause));

	reject.cause = *cause;

	memset(&reject_out, 0, sizeof(reject_out));
	rc = hnbap_encode_ueregisterrejecties(&reject_out, &reject);
	if (rc < 0)
		return rc;

	msg = hnbap_generate_unsuccessful_outcome(HNBAP_ProcedureCode_id_UERegister,
						  HNBAP_Criticality_reject,
						  &asn_DEF_HNBAP_UERegisterReject,
						  &reject_out);

	/* Free copied identity IEs */
	switch (ue_id->present) {
	case HNBAP_UE_Identity_PR_tMSILAI:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_BIT_STRING,
					      &reject.uE_Identity.choice.tMSILAI.tMSI);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &reject.uE_Identity.choice.tMSILAI.lAI.pLMNID);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &reject.uE_Identity.choice.tMSILAI.lAI.lAC);
		break;

	case HNBAP_UE_Identity_PR_pTMSIRAI:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_BIT_STRING,
					      &reject.uE_Identity.choice.pTMSIRAI.pTMSI);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &reject.uE_Identity.choice.pTMSIRAI.rAI.lAI.pLMNID);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &reject.uE_Identity.choice.pTMSIRAI.rAI.lAI.lAC);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &reject.uE_Identity.choice.pTMSIRAI.rAI.rAC);
		break;
	case HNBAP_UE_Identity_PR_iMSI:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &reject.uE_Identity.choice.iMSI);

	default:
		/* should never happen after above switch() */
		break;
	}

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_UERegisterReject, &reject_out);

	return hnbgw_hnbap_tx(hnb, msg);
}

static int hnbgw_tx_ue_register_acc_tmsi(struct hnb_context *hnb, HNBAP_UE_Identity_t *ue_id)
{
	HNBAP_UERegisterAccept_t accept_out;
	HNBAP_UERegisterAcceptIEs_t accept;
	struct msgb *msg;
	uint32_t ctx_id;
	uint32_t tmsi = 0;
	struct ue_context *ue;
	struct ue_context *ue_allocated = NULL;
	int rc;

	memset(&accept, 0, sizeof(accept));
	accept.uE_Identity.present = ue_id->present;

	switch (ue_id->present) {
	case HNBAP_UE_Identity_PR_tMSILAI:
		BIT_STRING_fromBuf(&accept.uE_Identity.choice.tMSILAI.tMSI,
				   ue_id->choice.tMSILAI.tMSI.buf,
				   ue_id->choice.tMSILAI.tMSI.size * 8
				   - ue_id->choice.tMSILAI.tMSI.bits_unused);
		tmsi = *(uint32_t*)accept.uE_Identity.choice.tMSILAI.tMSI.buf;
		OCTET_STRING_fromBuf(&accept.uE_Identity.choice.tMSILAI.lAI.pLMNID,
				     (const char *)ue_id->choice.tMSILAI.lAI.pLMNID.buf,
				     ue_id->choice.tMSILAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&accept.uE_Identity.choice.tMSILAI.lAI.lAC,
				     (const char *)ue_id->choice.tMSILAI.lAI.lAC.buf,
				     ue_id->choice.tMSILAI.lAI.lAC.size);
		break;

	case HNBAP_UE_Identity_PR_pTMSIRAI:
		BIT_STRING_fromBuf(&accept.uE_Identity.choice.pTMSIRAI.pTMSI,
				   ue_id->choice.pTMSIRAI.pTMSI.buf,
				   ue_id->choice.pTMSIRAI.pTMSI.size * 8
				   - ue_id->choice.pTMSIRAI.pTMSI.bits_unused);
		tmsi = *(uint32_t*)accept.uE_Identity.choice.pTMSIRAI.pTMSI.buf;
		OCTET_STRING_fromBuf(&accept.uE_Identity.choice.pTMSIRAI.rAI.lAI.pLMNID,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.pLMNID.size);
		OCTET_STRING_fromBuf(&accept.uE_Identity.choice.pTMSIRAI.rAI.lAI.lAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.lAI.lAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.lAI.lAC.size);
		OCTET_STRING_fromBuf(&accept.uE_Identity.choice.pTMSIRAI.rAI.rAC,
				     (const char *)ue_id->choice.pTMSIRAI.rAI.rAC.buf,
				     ue_id->choice.pTMSIRAI.rAI.rAC.size);
		break;

	default:
		LOGHNB(hnb, DHNBAP, LOGL_ERROR, "Unsupported HNBAP UE Identity type (present=%d)\n", ue_id->present);
		return -1;
	}

	tmsi = ntohl(tmsi);
	LOGHNB(hnb, DHNBAP, LOGL_DEBUG, "HNBAP register with TMSI %x\n", tmsi);

	ue = ue_context_by_tmsi(tmsi);
	if (!ue)
		ue = ue_allocated = ue_context_alloc(hnb, NULL, tmsi);

	asn1_u24_to_bitstring(&accept.context_ID, &ctx_id, ue->context_id);

	memset(&accept_out, 0, sizeof(accept_out));
	rc = hnbap_encode_ueregisteraccepties(&accept_out, &accept);

	/* free 'accept', now encoded in 'accept_out' */
	switch (ue_id->present) {
	case HNBAP_UE_Identity_PR_tMSILAI:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_BIT_STRING,
					      &accept.uE_Identity.choice.tMSILAI.tMSI);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &accept.uE_Identity.choice.tMSILAI.lAI.pLMNID);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &accept.uE_Identity.choice.tMSILAI.lAI.lAC);
		break;

	case HNBAP_UE_Identity_PR_pTMSIRAI:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_BIT_STRING,
					      &accept.uE_Identity.choice.pTMSIRAI.pTMSI);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &accept.uE_Identity.choice.pTMSIRAI.rAI.lAI.pLMNID);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &accept.uE_Identity.choice.pTMSIRAI.rAI.lAI.lAC);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING,
					      &accept.uE_Identity.choice.pTMSIRAI.rAI.rAC);
		break;

	default:
		/* should never happen after above switch() */
		break;
	}

	if (rc < 0) {
		/* Encoding failed. Nothing in 'accept_out'. */
		/* If we allocated the UE context but the UE REGISTER fails, get rid of it again: there will likely
		 * never be a UE DE-REGISTER for this UE from the HNB, and the ue_context would linger forever. */
		if (ue_allocated)
			ue_context_free(ue_allocated);
		return rc;
	}

	/* Encoding successful, transmit, then free 'accept_out'. */
	msg = hnbap_generate_successful_outcome(HNBAP_ProcedureCode_id_UERegister,
						HNBAP_Criticality_reject,
						&asn_DEF_HNBAP_UERegisterAccept,
						&accept_out);
	rc = hnbgw_hnbap_tx(hnb, msg);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_UERegisterAccept, &accept_out);
	return rc;
}

static int hnbgw_rx_hnb_deregister(struct hnb_context *ctx, ANY_t *in)
{
	HNBAP_HNBDe_RegisterIEs_t ies;
	HNBAP_Cause_t cause;
	int rc;

	rc = hnbap_decode_hnbde_registeries(&ies, in);
	if (rc < 0) {
		cause.present = HNBAP_Cause_PR_protocol;
		cause.choice.radioNetwork = HNBAP_CauseProtocol_unspecified;
		return hnbgw_tx_error_ind(ctx, &cause, HNBAP_ProcedureCode_id_HNBDe_Register, HNBAP_Criticality_ignore,
					  HNBAP_TriggeringMessage_initiating_message);
	}

	LOGHNB(ctx, DHNBAP, LOGL_DEBUG, "HNB-DE-REGISTER cause=%s\n", hnbap_cause_str(&ies.cause));

	hnbap_free_hnbde_registeries(&ies);
	ctx->hnb_registered = false;

	return 0;
}

static int hnbgw_rx_hnb_register_req(struct hnb_context *ctx, ANY_t *in)
{
	struct hnb_persistent *hnbp;
	struct hnb_context *hnb, *tmp;
	HNBAP_HNBRegisterRequestIEs_t ies;
	int rc;
	struct osmo_plmn_id plmn;
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(ctx->conn);
	char identity_str[256];
	const char *cell_id_str;
	struct timespec tp;
	HNBAP_Cause_t cause;
	struct osmo_sockaddr cur_osa = {};
	socklen_t len = sizeof(cur_osa);

	rc = hnbap_decode_hnbregisterrequesties(&ies, in);
	if (rc < 0) {
		LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Failure to decode HNB-REGISTER-REQ: rc=%d\n", rc);
		cause.present = HNBAP_Cause_PR_protocol;
		cause.choice.radioNetwork = HNBAP_CauseProtocol_unspecified;
		return hnbgw_tx_hnb_register_rej(ctx, &cause);
	}
	asn1_strncpy(identity_str, &ies.hnB_Identity.hNB_Identity_Info, sizeof(identity_str));

	/* copy all identity parameters from the message to ctx */
	OSMO_STRLCPY_ARRAY(ctx->identity_info, identity_str);
	ctx->id.lac = asn1str_to_u16(&ies.lac);
	ctx->id.sac = asn1str_to_u16(&ies.sac);
	ctx->id.rac = asn1str_to_u8(&ies.rac);
	ctx->id.cid = asn1bitstr_to_u28(&ies.cellIdentity);
	osmo_plmn_from_bcd(ies.plmNidentity.buf, &plmn);
	ctx->id.mcc = plmn.mcc;
	ctx->id.mnc = plmn.mnc;
	cell_id_str = umts_cell_id_name(&ctx->id);

	if (getpeername(ofd->fd, &cur_osa.u.sa, &len) < 0) {
		LOGHNB(ctx, DHNBAP, LOGL_ERROR, "HNB-REGISTER-REQ %s: rejecting due to getpeername() error: %s\n",
		       cell_id_str, strerror(errno));
		hnbap_free_hnbregisterrequesties(&ies);
		cause.present = HNBAP_Cause_PR_radioNetwork;
		cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_hNB_parameter_mismatch;
		return hnbgw_tx_hnb_register_rej(ctx, &cause);
	}

	hnbp = hnb_persistent_find_by_id(&ctx->id);
	if (!hnbp && g_hnbgw->config.accept_all_hnb)
		hnbp = hnb_persistent_alloc(&ctx->id);

	if (!hnbp) {
		LOGHNB(ctx, DHNBAP, LOGL_NOTICE, "Rejecting unknonwn HNB with identity %s\n", identity_str);
		hnbap_free_hnbregisterrequesties(&ies);
		cause.present = HNBAP_Cause_PR_radioNetwork;
		cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_unauthorised_HNB;
		return hnbgw_tx_hnb_register_rej(ctx, &cause);
	}

	ctx->persistent = hnbp;
	hnbp->ctx = ctx;

	HNBP_CTR_INC(hnbp, HNB_CTR_IUH_ESTABLISHED);
	rc = osmo_clock_gettime(CLOCK_MONOTONIC, &tp);
	hnbp->updowntime = (rc < 0) ? 0 : tp.tv_sec;

	llist_for_each_entry_safe(hnb, tmp, &g_hnbgw->hnb_list, list) {
		if (hnb->hnb_registered && ctx != hnb && memcmp(&ctx->id, &hnb->id, sizeof(ctx->id)) == 0) {
			/* If it's coming from the same remote IP addr+port, then it must be our internal
			 * fault (bug), and we release the old context to keep going... */
			struct osmo_fd *other_fd = osmo_stream_srv_get_ofd(hnb->conn);
			struct osmo_sockaddr other_osa = {};
			socklen_t len = sizeof(other_osa);
			if (getpeername(other_fd->fd, &other_osa.u.sa, &len) < 0) {
				LOGHNB(ctx, DHNBAP, LOGL_ERROR, "BUG! Found old registered HNB with invalid socket, releasing it\n");
				hnb_context_release(hnb);
				continue;
			}
			if (osmo_sockaddr_cmp(&cur_osa, &other_osa) == 0) {
				LOGHNB(ctx, DHNBAP, LOGL_ERROR, "BUG! Found old registered HNB with same remote address, releasing it\n");
				hnb_context_release(hnb);
				continue;
			} /* else: addresses are different, we continue below */

			/* If new conn registering same HNB is from anoter remote addr+port, let's reject it to avoid
			 * misconfigurations or someone trying to impersonate an already working HNB: */
			LOGHNB(ctx, DHNBAP, LOGL_ERROR, "rejecting HNB-REGISTER-REQ with duplicate cell identity %s\n", cell_id_str);
			hnbap_free_hnbregisterrequesties(&ies);
			cause.present = HNBAP_Cause_PR_radioNetwork;
			cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_hNB_parameter_mismatch;
			return hnbgw_tx_hnb_register_rej(ctx, &cause);
		}
	}

	LOGHNB(ctx, DHNBAP, LOGL_DEBUG, "HNB-REGISTER-REQ %s %s%s\n",
	       ctx->identity_info, cell_id_str, ctx->hnb_registered ? " (re-connecting)" : "");

	/* The HNB is already registered, and we are seeing a new HNB Register Request. The HNB has restarted
	 * without us noticing. Clearly, the HNB does not expect any UE state to be active here, so discard any
	 * UE contexts and SCCP connections associated with this HNB. */
	LOGHNB(ctx, DHNBAP, LOGL_NOTICE, "HNB (re)connecting, discarding all previous UE state\n");
	hnb_context_release_ue_state(ctx);

	ctx->hnb_registered = true;

	hnb_persistent_registered(ctx->persistent);

	/* Send HNBRegisterAccept */
	rc = hnbgw_tx_hnb_register_acc(ctx);
	hnbap_free_hnbregisterrequesties(&ies);
	return rc;
}

static int hnbgw_rx_ue_register_req(struct hnb_context *ctx, ANY_t *in)
{
	HNBAP_UERegisterRequestIEs_t ies;
	HNBAP_Cause_t cause;
	struct ue_context *ue;
	struct ue_context *ue_allocated = NULL;
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	int rc;

	rc = hnbap_decode_ueregisterrequesties(&ies, in);
	if (rc < 0) {
		LOGHNB(ctx, DHNBAP, LOGL_ERROR, "Failure to decode UE-REGISTER-REQ: rc=%d\n", rc);
		cause.present = HNBAP_Cause_PR_protocol;
		cause.choice.radioNetwork = HNBAP_CauseProtocol_unspecified;
		return hnbgw_tx_error_ind(ctx, &cause, HNBAP_ProcedureCode_id_UERegister, HNBAP_Criticality_reject,
					  HNBAP_TriggeringMessage_initiating_message);
	}

	if (!ctx->hnb_registered) {
		/* UE registration requires prior HNB registration; reject with proper cause */
		cause.present = HNBAP_Cause_PR_radioNetwork;
		cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_hNB_not_registered;
		rc = hnbgw_tx_ue_register_rej(ctx, &ies.uE_Identity, &cause);
		goto free_and_return_rc;
	}

	switch (ies.uE_Identity.present) {
	case HNBAP_UE_Identity_PR_iMSI:
		ranap_bcd_decode(imsi, sizeof(imsi), ies.uE_Identity.choice.iMSI.buf,
			      ies.uE_Identity.choice.iMSI.size);
		break;
	case HNBAP_UE_Identity_PR_iMSIDS41:
		ranap_bcd_decode(imsi, sizeof(imsi), ies.uE_Identity.choice.iMSIDS41.buf,
			      ies.uE_Identity.choice.iMSIDS41.size);
		break;
	case HNBAP_UE_Identity_PR_iMSIESN:
		ranap_bcd_decode(imsi, sizeof(imsi), ies.uE_Identity.choice.iMSIESN.iMSIDS41.buf,
			      ies.uE_Identity.choice.iMSIESN.iMSIDS41.size);
		break;
	case HNBAP_UE_Identity_PR_tMSILAI:
	case HNBAP_UE_Identity_PR_pTMSIRAI:
		if (g_hnbgw->config.hnbap_allow_tmsi) {
			rc = hnbgw_tx_ue_register_acc_tmsi(ctx, &ies.uE_Identity);
		} else {
			cause.present = HNBAP_Cause_PR_radioNetwork;
			cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_invalid_UE_identity;
			rc = hnbgw_tx_ue_register_rej(ctx, &ies.uE_Identity, &cause);
		}
		/* all has been handled by TMSI, skip the IMSI code below */
		goto free_and_return_rc;
	default:
		LOGHNB(ctx, DHNBAP, LOGL_NOTICE, "UE-REGISTER-REQ with unsupported UE Id type %d\n",
			ies.uE_Identity.present);
		cause.present = HNBAP_Cause_PR_radioNetwork;
		cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_invalid_UE_identity;
		rc = hnbgw_tx_ue_register_rej(ctx, &ies.uE_Identity, &cause);
		goto free_and_return_rc;
	}

	LOGHNB(ctx, DHNBAP, LOGL_DEBUG, "UE-REGISTER-REQ ID_type=%d imsi=%s cause=%ld\n",
		ies.uE_Identity.present, imsi, ies.registration_Cause);

	ue = ue_context_by_imsi(imsi);
	if (!ue)
		ue = ue_allocated = ue_context_alloc(ctx, imsi, 0);

	/* Send UERegisterAccept */
	rc = hnbgw_tx_ue_register_acc(ue);
	if (rc < 0) {
		/* If we allocated the UE context but the UE REGISTER fails, get rid of it again: there will likely
		 * never be a UE DE-REGISTER for this UE from the HNB, and the ue_context would linger forever. */
		if (ue_allocated)
			ue_context_free(ue_allocated);
	}
free_and_return_rc:
	hnbap_free_ueregisterrequesties(&ies);
	return rc;
}

static int hnbgw_rx_ue_deregister(struct hnb_context *ctx, ANY_t *in)
{
	HNBAP_UEDe_RegisterIEs_t ies;
	HNBAP_Cause_t cause;
	struct ue_context *ue;
	int rc;
	uint32_t ctxid;

	rc = hnbap_decode_uede_registeries(&ies, in);
	if (rc < 0) {
		cause.present = HNBAP_Cause_PR_protocol;
		cause.choice.protocol = HNBAP_CauseProtocol_unspecified;
		return hnbgw_tx_error_ind(ctx, &cause, HNBAP_ProcedureCode_id_UEDe_Register,
					  HNBAP_Criticality_ignore, HNBAP_TriggeringMessage_initiating_message);
	}

	ctxid = asn1bitstr_to_u24(&ies.context_ID);

	if (!ctx->hnb_registered) {
		LOGHNB(ctx, DHNBAP, LOGL_NOTICE, "UE-DE-REGISTER context=%u cause=%s not permitted; HNB not registered\n",
			ctxid, hnbap_cause_str(&ies.cause));
		cause.present = HNBAP_Cause_PR_radioNetwork;
		cause.choice.radioNetwork = HNBAP_CauseRadioNetwork_hNB_not_registered;
		hnbgw_tx_error_ind(ctx, &cause, HNBAP_ProcedureCode_id_UEDe_Register,
				   HNBAP_Criticality_ignore, HNBAP_TriggeringMessage_initiating_message);
	} else {
		LOGHNB(ctx, DHNBAP, LOGL_DEBUG, "UE-DE-REGISTER context=%u cause=%s\n", ctxid, hnbap_cause_str(&ies.cause));
		ue = ue_context_by_id(ctxid);
		if (ue)
			ue_context_free(ue);
	}

	hnbap_free_uede_registeries(&ies);
	return 0;
}

static int hnbgw_rx_err_ind(struct hnb_context *hnb, ANY_t *in)
{
	HNBAP_ErrorIndicationIEs_t ies;
	int rc;

	rc = hnbap_decode_errorindicationies(&ies, in);
	if (rc < 0)
		return rc;

	LOGHNB(hnb, DHNBAP, LOGL_NOTICE, "HNBAP ERROR.ind, cause: %s\n", hnbap_cause_str(&ies.cause));

	hnbap_free_errorindicationies(&ies);
	return 0;
}

static int hnbgw_rx_initiating_msg(struct hnb_context *hnb, HNBAP_InitiatingMessage_t *imsg)
{
	HNBAP_Cause_t cause = {
		.present = HNBAP_Cause_PR_protocol,
		.choice.protocol = HNBAP_CauseProtocol_unspecified,
	};
	int rc = 0;

	switch (imsg->procedureCode) {
	case HNBAP_ProcedureCode_id_HNBRegister:	/* 8.2 */
		rc = hnbgw_rx_hnb_register_req(hnb, &imsg->value);
		break;
	case HNBAP_ProcedureCode_id_HNBDe_Register:	/* 8.3 */
		rc = hnbgw_rx_hnb_deregister(hnb, &imsg->value);
		break;
	case HNBAP_ProcedureCode_id_UERegister:		/* 8.4 */
		rc = hnbgw_rx_ue_register_req(hnb, &imsg->value);
		break;
	case HNBAP_ProcedureCode_id_UEDe_Register:	/* 8.5 */
		rc = hnbgw_rx_ue_deregister(hnb, &imsg->value);
		break;
	case HNBAP_ProcedureCode_id_ErrorIndication:	/* 8.6 */
		rc = hnbgw_rx_err_ind(hnb, &imsg->value);
		break;
	case HNBAP_ProcedureCode_id_TNLUpdate:		/* 8.9 */
	case HNBAP_ProcedureCode_id_HNBConfigTransfer:	/* 8.10 */
	case HNBAP_ProcedureCode_id_RelocationComplete:	/* 8.11 */
	case HNBAP_ProcedureCode_id_U_RNTIQuery:	/* 8.12 */
	case HNBAP_ProcedureCode_id_privateMessage:
		LOGHNB(hnb, DHNBAP, LOGL_NOTICE, "Unimplemented HNBAP Procedure %ld\n", imsg->procedureCode);
		rc = hnbgw_tx_error_ind(hnb, &cause, imsg->procedureCode, -1, HNBAP_TriggeringMessage_initiating_message);
		break;
	default:
		LOGHNB(hnb, DHNBAP, LOGL_NOTICE, "Unknown HNBAP Procedure %ld\n", imsg->procedureCode);
		rc = hnbgw_tx_error_ind(hnb, &cause, imsg->procedureCode, -1, HNBAP_TriggeringMessage_initiating_message);
		break;
	}

	return rc;
}

static int hnbgw_rx_successful_outcome_msg(struct hnb_context *hnb, HNBAP_SuccessfulOutcome_t *msg)
{
	/* We don't care much about HNBAP */
	return 0;
}

static int hnbgw_rx_unsuccessful_outcome_msg(struct hnb_context *hnb, HNBAP_UnsuccessfulOutcome_t *msg)
{
	/* We don't care much about HNBAP */
	LOGHNB(hnb, DHNBAP, LOGL_ERROR, "Received Unsuccessful Outcome, procedureCode %ld, criticality %ld,"
		" cell mcc %u mnc %u lac %u rac %u sac %u cid %u\n", msg->procedureCode, msg->criticality,
		hnb->id.mcc, hnb->id.mnc, hnb->id.lac, hnb->id.rac, hnb->id.sac, hnb->id.cid);
	return 0;
}


static int _hnbgw_hnbap_rx(struct hnb_context *hnb, HNBAP_HNBAP_PDU_t *pdu)
{
	int rc = 0;

	/* it's a bit odd that we can't dispatch on procedure code, but
	 * that's not possible */
	switch (pdu->present) {
	case HNBAP_HNBAP_PDU_PR_initiatingMessage:
		rc = hnbgw_rx_initiating_msg(hnb, &pdu->choice.initiatingMessage);
		break;
	case HNBAP_HNBAP_PDU_PR_successfulOutcome:
		rc = hnbgw_rx_successful_outcome_msg(hnb, &pdu->choice.successfulOutcome);
		break;
	case HNBAP_HNBAP_PDU_PR_unsuccessfulOutcome:
		rc = hnbgw_rx_unsuccessful_outcome_msg(hnb, &pdu->choice.unsuccessfulOutcome);
		break;
	default:
		LOGHNB(hnb, DHNBAP, LOGL_NOTICE, "Unknown HNBAP Presence %u\n", pdu->present);
		rc = -1;
	}

	return rc;
}

int hnbgw_hnbap_rx(struct hnb_context *hnb, struct msgb *msg)
{
	HNBAP_HNBAP_PDU_t _pdu, *pdu = &_pdu;
	asn_dec_rval_t dec_ret;
	int rc;

	/* decode and handle to _hnbgw_hnbap_rx() */

	memset(pdu, 0, sizeof(*pdu));
	dec_ret = aper_decode(NULL, &asn_DEF_HNBAP_HNBAP_PDU, (void **) &pdu,
			      msg->data, msgb_length(msg), 0, 0);
	if (dec_ret.code != RC_OK) {
		LOGHNB(hnb, DHNBAP, LOGL_ERROR, "Error in ASN.1 decode\n");
		return -1;
	}

	rc = _hnbgw_hnbap_rx(hnb, pdu);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_HNBAP_HNBAP_PDU, pdu);

	return rc;
}


int hnbgw_hnbap_init(void)
{
	return 0;
}
