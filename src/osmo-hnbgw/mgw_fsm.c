/* (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/prim.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/byteswap.h>
#include <arpa/inet.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_common_ran.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/iu_helpers.h>
#include <asn1c/asn1helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/ranap_rab_ass.h>

#include <osmocom/hnbgw/hnbgw_rua.h>

#include <osmocom/core/tdef.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

/* NOTE: This implementation can only handle one RAB per hnbgw context. This simplification was made because usually
 * a voice call will require only one RAB at a time. An exception may be corner cases like video calls, which we
 * do not support at the moment. */

/* Send Iu Release Request, this is done in erroneous cases from which we cannot recover */
static void tx_release_req(struct hnbgw_context_map *map)
{
	struct hnb_context *hnb = map->hnb_ctx;
	struct hnbgw_cnlink *cn = hnb->gw->sccp.cnlink;
	struct msgb *msg;
	struct osmo_scu_prim *prim;
	static const struct RANAP_Cause cause = {
		.present = RANAP_Cause_PR_transmissionNetwork,
		.choice.transmissionNetwork =
		    RANAP_CauseTransmissionNetwork_iu_transport_connection_failed_to_establish,
	};

	msg = ranap_new_msg_iu_rel_req(&cause);
	msg->l2h = msg->data;

	prim = (struct osmo_scu_prim *)msgb_push(msg, sizeof(*prim));
	prim->u.data.conn_id = map->scu_conn_id;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST, msg);
	osmo_sccp_user_sap_down(cn->sccp_user, &prim->oph);
}

#define S(x)	(1 << (x))

extern int asn1_xer_print;

enum mgw_fsm_event {
	MGW_EV_MGCP_OK,
	MGW_EV_MGCP_FAIL,
	MGW_EV_MGCP_TERM,
	MGW_EV_RAB_ASS_RESP,
	MGW_EV_RELEASE,
};

static const struct value_string mgw_fsm_event_names[] = {
	OSMO_VALUE_STRING(MGW_EV_MGCP_OK),
	OSMO_VALUE_STRING(MGW_EV_MGCP_FAIL),
	OSMO_VALUE_STRING(MGW_EV_MGCP_TERM),
	OSMO_VALUE_STRING(MGW_EV_RAB_ASS_RESP),
	OSMO_VALUE_STRING(MGW_EV_RELEASE),
	{}
};

enum mgw_fsm_state {
	MGW_ST_CRCX_HNB,
	MGW_ST_ASSIGN,
	MGW_ST_MDCX_HNB,
	MGW_ST_CRCX_MSC,
	MGW_ST_ESTABLISHED,
	MGW_ST_RELEASE,
	MGW_ST_FAILURE,
};

struct mgw_fsm_priv {
	/* Backpointer to HNBGW context */
	struct hnbgw_context_map *map;

	/* RAB-ID from RANAP RAB AssignmentRequest message */
	uint8_t rab_id;

	/* Pointers to messages and prim header we take ownership of */
	ranap_message *ranap_rab_ass_req_message;
	ranap_message *ranap_rab_ass_resp_message;
	struct osmo_prim_hdr *ranap_rab_ass_resp_oph;

	/* MGW context */
	struct osmo_mgcpc_ep *mgcpc_ep;
	struct osmo_mgcpc_ep_ci *mgcpc_ep_ci_hnb;
	struct osmo_mgcpc_ep_ci *mgcpc_ep_ci_msc;
	char msc_rtp_addr[INET6_ADDRSTRLEN];
	uint16_t msc_rtp_port;
};

static const struct osmo_tdef mgw_tdefs[] = {
	{.T = -2427, .default_val = 5, .desc = "timeout for MGCP response from MGW" },
	{ }
};

static const struct osmo_tdef_state_timeout mgw_fsm_timeouts[32] = {
	[MGW_ST_CRCX_HNB] = {.T = -1001 },
	[MGW_ST_ASSIGN] = {.T = -1002 },
	[MGW_ST_MDCX_HNB] = {.T = -1003 },
	[MGW_ST_CRCX_MSC] = {.T = -1004 },
};

#define mgw_fsm_state_chg(fi, state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, mgw_fsm_timeouts, mgw_fsm_T_defs, -1)

static void mgw_fsm_crcx_hnb_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;
	const char *epname;
	struct mgcp_conn_peer mgw_info;

	LOGPFSML(fi, LOGL_DEBUG, "RAB-AssignmentRequest received, creating HNB side call-leg on MGW...\n");

	mgw_info = (struct mgcp_conn_peer) {
		.call_id = (map->rua_ctx_id << 8) | mgw_fsm_priv->rab_id,
		.ptime = 20,
		.conn_mode = MGCP_CONN_LOOPBACK,
	};
	mgw_info.codecs[0] = CODEC_IUFP;
	mgw_info.codecs_len = 1;

	epname = mgcp_client_rtpbridge_wildcard(map->hnb_ctx->gw->mgcp_client);
	mgw_fsm_priv->mgcpc_ep =
	    osmo_mgcpc_ep_alloc(fi, MGW_EV_MGCP_TERM, map->hnb_ctx->gw->mgcp_client, mgw_tdefs, fi->id, "%s", epname);
	mgw_fsm_priv->mgcpc_ep_ci_hnb = osmo_mgcpc_ep_ci_add(mgw_fsm_priv->mgcpc_ep, "to-HNB");

	osmo_mgcpc_ep_ci_request(mgw_fsm_priv->mgcpc_ep_ci_hnb, MGCP_VERB_CRCX, &mgw_info, fi, MGW_EV_MGCP_OK,
				 MGW_EV_MGCP_FAIL, NULL);
}

static void mgw_fsm_crcx_hnb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	const struct mgcp_conn_peer *mgw_info;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	int rc;

	switch (event) {
	case MGW_EV_MGCP_OK:
		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(mgw_fsm_priv->mgcpc_ep_ci_hnb);
		if (!mgw_info) {
			LOGPFSML(fi, LOGL_ERROR, "Got no RTP info response from MGW\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		if (strchr(mgw_info->addr, '.'))
			addr_str.af = AF_INET;
		else
			addr_str.af = AF_INET6;
		addr_str.port = mgw_info->port;
		osmo_strlcpy(addr_str.ip, mgw_info->addr, sizeof(addr_str.ip));
		rc = osmo_sockaddr_str_to_sockaddr(&addr_str, &addr.u.sas);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to convert RTP IP-address (%s) and Port (%u) to its binary representation\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		ies = &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
		rc = ranap_rab_ass_req_ies_replace_inet_addr(ies, &addr, mgw_fsm_priv->rab_id);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to replace RTP IP-address (%s) and Port (%u) in RAB-AssignmentRequest\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		mgw_fsm_state_chg(fi, MGW_ST_ASSIGN);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static void mgw_fsm_assign_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;
	uint8_t encoded[IUH_MSGB_SIZE];
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	int rc;

	ies = &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
	rc = ranap_rab_ass_req_encode(encoded, sizeof(encoded), ies);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_ERROR, "failed to re-encode RAB-AssignmentRequest message\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG, "forwarding modified RAB-AssignmentRequest to HNB\n");
	rua_tx_dt(map->hnb_ctx, map->is_ps, map->rua_ctx_id, encoded, rc);
}

static void mgw_fsm_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case MGW_EV_RAB_ASS_RESP:
		mgw_fsm_state_chg(fi, MGW_ST_MDCX_HNB);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static void mgw_fsm_mdcx_hnb_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;
	struct hnb_context *hnb = map->hnb_ctx;
	struct hnbgw_cnlink *cn = hnb->gw->sccp.cnlink;
	struct mgcp_conn_peer mgw_info;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	RANAP_RAB_AssignmentResponseIEs_t *ies;
	int rc;
	bool rab_failed_at_hnb;

	LOGPFSML(fi, LOGL_DEBUG, "RAB-AssignmentResponse received, completing HNB side call-leg on MGW...\n");

	mgw_info = (struct mgcp_conn_peer) {
		.call_id = map->rua_ctx_id,
		.ptime = 20,
		.conn_mode = MGCP_CONN_RECV_SEND,
	};
	mgw_info.codecs[0] = CODEC_IUFP;
	mgw_info.codecs_len = 1;

	ies = &mgw_fsm_priv->ranap_rab_ass_resp_message->msg.raB_AssignmentResponseIEs;
	rc = ranap_rab_ass_resp_ies_extract_inet_addr(&addr, ies, mgw_fsm_priv->rab_id);
	if (rc < 0) {
		rab_failed_at_hnb = ranap_rab_ass_resp_ies_check_failure(ies, mgw_fsm_priv->rab_id);
		if (rab_failed_at_hnb) {
			LOGPFSML(fi, LOGL_ERROR,
				 "The RAB-AssignmentResponse contains a RAB-FailedList, RAB-Assignment (%u) failed.\n",
				 mgw_fsm_priv->rab_id);

			/* Forward the RAB-AssignmentResponse transparently. This will ensure that the MSC is informed
			 * about the problem. */
			LOGPFSML(fi, LOGL_DEBUG, "forwarding unmodified RAB-AssignmentResponse to MSC\n");
			rc = osmo_sccp_user_sap_down(cn->sccp_user, mgw_fsm_priv->ranap_rab_ass_resp_oph);
			mgw_fsm_priv->ranap_rab_ass_resp_oph = NULL;
			if (rc < 0) {
				LOGPFSML(fi, LOGL_DEBUG, "failed to forward RAB-AssignmentResponse message\n");
				osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			}

			/* Even though this is a failure situation, we still release normally as the error is located
			 * at the HNB. */
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
			return;
		}

		/* The RAB-ID we are dealing with is not on an FailedList and we were unable to parse the response
		 * normally. This is a situation we cannot recover from. */
		LOGPFSML(fi, LOGL_ERROR, "Failed to extract RTP IP-address and Port from RAB-AssignmentResponse\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}

	rc = osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_ERROR, "Invalid RTP IP-address or Port in RAB-AssignmentResponse\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}
	osmo_strlcpy(mgw_info.addr, addr_str.ip, sizeof(mgw_info.addr));
	mgw_info.port = addr_str.port;

	osmo_mgcpc_ep_ci_request(mgw_fsm_priv->mgcpc_ep_ci_hnb, MGCP_VERB_MDCX, &mgw_info, fi, MGW_EV_MGCP_OK,
				 MGW_EV_MGCP_FAIL, NULL);
}

static void mgw_fsm_mdcx_hnb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	const struct mgcp_conn_peer *mgw_info;

	switch (event) {
	case MGW_EV_MGCP_OK:
		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(mgw_fsm_priv->mgcpc_ep_ci_hnb);
		if (!mgw_info) {
			LOGPFSML(fi, LOGL_ERROR, "Got no RTP info response from MGW\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}
		mgw_fsm_state_chg(fi, MGW_ST_CRCX_MSC);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static void mgw_fsm_crcx_msc_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;
	struct mgcp_conn_peer mgw_info;

	LOGPFSML(fi, LOGL_DEBUG, "creating MSC side call-leg on MGW...\n");

	mgw_info = (struct mgcp_conn_peer) {
		.call_id = (map->rua_ctx_id << 8) | mgw_fsm_priv->rab_id,
		.ptime = 20,
		.port = mgw_fsm_priv->msc_rtp_port,
	};

	osmo_strlcpy(mgw_info.addr, mgw_fsm_priv->msc_rtp_addr, sizeof(mgw_info.addr));
	mgw_info.codecs[0] = CODEC_IUFP;
	mgw_info.codecs_len = 1;

	mgw_fsm_priv->mgcpc_ep_ci_msc = osmo_mgcpc_ep_ci_add(mgw_fsm_priv->mgcpc_ep, "to-MSC");
	osmo_mgcpc_ep_ci_request(mgw_fsm_priv->mgcpc_ep_ci_msc, MGCP_VERB_CRCX, &mgw_info, fi, MGW_EV_MGCP_OK,
				 MGW_EV_MGCP_FAIL, NULL);
}

static void mgw_fsm_crcx_msc(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	const struct mgcp_conn_peer *mgw_info;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	int rc;
	int msg_max_len;
	RANAP_RAB_AssignmentResponseIEs_t *ies;

	switch (event) {
	case MGW_EV_MGCP_OK:
		ies = &mgw_fsm_priv->ranap_rab_ass_resp_message->msg.raB_AssignmentResponseIEs;

		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(mgw_fsm_priv->mgcpc_ep_ci_msc);
		if (!mgw_info) {
			LOGPFSML(fi, LOGL_ERROR, "Got no response from MGW\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		/* Replace RTP IP-Address/Port in ranap message container */
		if (strchr(mgw_info->addr, '.'))
			addr_str.af = AF_INET;
		else
			addr_str.af = AF_INET6;
		addr_str.port = mgw_info->port;
		osmo_strlcpy(addr_str.ip, mgw_info->addr, sizeof(addr_str.ip));
		rc = osmo_sockaddr_str_to_sockaddr(&addr_str, &addr.u.sas);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to convert RTP IP-address (%s) and Port (%u) to its binary representation\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		rc = ranap_rab_ass_resp_ies_replace_inet_addr(ies, &addr, mgw_fsm_priv->rab_id);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to replace RTP IP-address (%s) and Port (%u) in RAB-AssignmentResponse\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		/* When the modified ranap message container is re-encoded, the resulting message might be larger then
		 * the original message. Ensure that there is enough room in l2h to grow. (The current implementation
		 * should yield a message with the same size, but there is no guarantee for that) */
		msg_max_len =
		    msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg) +
		    msgb_tailroom(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg);
		rc = msgb_resize_area(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg,
				      mgw_fsm_priv->ranap_rab_ass_resp_oph->msg->l2h,
				      msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg), msg_max_len);
		OSMO_ASSERT(rc == 0);

		rc = ranap_rab_ass_resp_encode(msgb_l2(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg),
					       msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg), ies);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "failed to re-encode RAB-AssignmentResponse message\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		/* Resize l2h back to the actual message length */
		rc = msgb_resize_area(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg,
				      mgw_fsm_priv->ranap_rab_ass_resp_oph->msg->l2h,
				      msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg), rc);
		OSMO_ASSERT(rc == 0);

		/* When the established state is entered, the modified RAB AssignmentResponse is forwarded to the MSC.
		 * The call is then established any way may stay for an indefinate amount of time in this state until
		 * there is an IU Release happening. */
		osmo_fsm_inst_state_chg(fi, MGW_ST_ESTABLISHED, 0, 0);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static void mgw_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;
	struct osmo_prim_hdr *oph = mgw_fsm_priv->ranap_rab_ass_resp_oph;
	struct hnb_context *hnb = map->hnb_ctx;
	struct hnbgw_cnlink *cn = hnb->gw->sccp.cnlink;
	int rc;

	LOGPFSML(fi, LOGL_DEBUG, "forwarding modified RAB-AssignmentResponse to MSC\n");
	rc = osmo_sccp_user_sap_down(cn->sccp_user, oph);
	mgw_fsm_priv->ranap_rab_ass_resp_oph = NULL;
	if (rc < 0) {
		LOGPFSML(fi, LOGL_DEBUG, "failed to forward RAB-AssignmentResponse message\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
	}

	LOGPFSML(fi, LOGL_DEBUG, "HNB and MSC side call-legs completed!\n");
}

static void mgw_fsm_release_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void mgw_fsm_failure_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	tx_release_req(mgw_fsm_priv->map);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
}

static void mgw_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;

	switch (event) {
	case MGW_EV_MGCP_TERM:
		mgw_fsm_priv->mgcpc_ep = NULL;
		LOGPFSML(fi, LOGL_ERROR, "Media gateway failed\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	case MGW_EV_MGCP_FAIL:
		LOGPFSML(fi, LOGL_ERROR, "Media gateway failed to switch RTP streams\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	case MGW_EV_RELEASE:
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static int mgw_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
	return 0;
}

static void mgw_fsm_priv_cleanup(struct mgw_fsm_priv *mgw_fsm_priv)
{
	struct osmo_scu_prim *scu_prim;
	struct msgb *scu_msg;

	if (mgw_fsm_priv->ranap_rab_ass_req_message) {
		ranap_ran_rx_co_free(mgw_fsm_priv->ranap_rab_ass_req_message);
		talloc_free(mgw_fsm_priv->ranap_rab_ass_req_message);
		mgw_fsm_priv->ranap_rab_ass_req_message = NULL;
	}

	if (mgw_fsm_priv->ranap_rab_ass_resp_message) {
		ranap_cn_rx_co_free(mgw_fsm_priv->ranap_rab_ass_resp_message);
		talloc_free(mgw_fsm_priv->ranap_rab_ass_resp_message);
		mgw_fsm_priv->ranap_rab_ass_resp_message = NULL;
	}

	if (mgw_fsm_priv->ranap_rab_ass_resp_oph) {
		scu_prim = (struct osmo_scu_prim *)mgw_fsm_priv->ranap_rab_ass_resp_oph;
		scu_msg = scu_prim->oph.msg;
		msgb_free(scu_msg);
		mgw_fsm_priv->ranap_rab_ass_resp_oph = NULL;
	}

	talloc_free(mgw_fsm_priv);
}

static void mgw_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	mgw_fsm_priv_cleanup(mgw_fsm_priv);
}

static void mgw_fsm_pre_term(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;

	if (mgw_fsm_priv->mgcpc_ep) {
		osmo_mgcpc_ep_clear(mgw_fsm_priv->mgcpc_ep);
		mgw_fsm_priv->mgcpc_ep = NULL;
	}

	/* Remove FSM from the context map. This will make this FSM unreachable for events coming from outside */
	map->mgw_fi = NULL;
}

static const struct osmo_fsm_state mgw_fsm_states[] = {
	[MGW_ST_CRCX_HNB] = {
		.name = "MGW_ST_CRCX_HNB",
		.onenter = mgw_fsm_crcx_hnb_onenter,
		.action = mgw_fsm_crcx_hnb,
		.in_event_mask =
			S(MGW_EV_MGCP_OK),
		.out_state_mask =
			S(MGW_ST_ASSIGN) |
			S(MGW_ST_FAILURE) |
			S(MGW_ST_RELEASE) |
			S(MGW_ST_CRCX_HNB),
	},
	[MGW_ST_ASSIGN] = {
		.name = "MGW_ST_ASSIGN",
		.onenter = mgw_fsm_assign_onenter,
		.action = mgw_fsm_assign,
		.in_event_mask = S(MGW_EV_RAB_ASS_RESP),
		.out_state_mask =
			S(MGW_ST_MDCX_HNB) |
			S(MGW_ST_FAILURE) |
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_MDCX_HNB] = {
		.name = "MGW_ST_MDCX_HNB",
		.onenter = mgw_fsm_mdcx_hnb_onenter,
		.action = mgw_fsm_mdcx_hnb,
		.in_event_mask =
			S(MGW_EV_MGCP_OK),
		.out_state_mask =
			S(MGW_ST_CRCX_MSC) |
			S(MGW_ST_FAILURE) |
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_CRCX_MSC] = {
		.name = "MGW_ST_CRCX_MSC",
		.onenter = mgw_fsm_crcx_msc_onenter,
		.action = mgw_fsm_crcx_msc,
		.in_event_mask =
			S(MGW_EV_MGCP_OK),
		.out_state_mask =
			S(MGW_ST_ESTABLISHED) |
			S(MGW_ST_FAILURE) |
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_ESTABLISHED] = {
		.name = "MGW_ST_ESTABLISHED",
		.onenter = mgw_fsm_established_onenter,
		.in_event_mask = 0,
		.out_state_mask =
			S(MGW_ST_FAILURE) |
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_RELEASE] = {
		.name = "MGW_ST_RELEASE",
		.onenter = mgw_fsm_release_onenter,
		.in_event_mask = 0,
		.out_state_mask = 0,
	},
	[MGW_ST_FAILURE] = {
		.name = "MGW_ST_FAILURE",
		.onenter = mgw_fsm_failure_onenter,
		.in_event_mask = 0,
		.out_state_mask = 0,
	},
};

static struct osmo_fsm mgw_fsm = {
	.name = "mgw",
	.states = mgw_fsm_states,
	.num_states = ARRAY_SIZE(mgw_fsm_states),
	.log_subsys = DMGW,
	.event_names = mgw_fsm_event_names,
	.allstate_action = mgw_fsm_allstate_action,
	.allstate_event_mask = S(MGW_EV_MGCP_TERM) | S(MGW_EV_RELEASE) | S(MGW_EV_MGCP_FAIL),
	.timer_cb = mgw_fsm_timer_cb,
	.cleanup = mgw_fsm_cleanup,
	.pre_term = mgw_fsm_pre_term,
};

/* The MSC may ask to release a specific RAB within a RAB-AssignmentRequest */
static int handle_rab_release(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message)
{
	bool rab_release_req;
	struct osmo_fsm_inst *fi = map->mgw_fi;
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	int rc;

	/* Check if the RAB that is handled by this FSM is addressed by the release request */
	rab_release_req = ranap_rab_ass_req_ies_check_release(&message->msg.raB_AssignmentRequestIEs,
							      mgw_fsm_priv->rab_id);
	if (!rab_release_req)
		return -EINVAL;

	LOGPFSML(map->mgw_fi, LOGL_NOTICE, "MSC asked to release RAB-ID %u\n", mgw_fsm_priv->rab_id);

	/* Forward the unmodifed RAB-AssignmentRequest to HNB, so that the HNB is informed about the RAB release as
	 * well */
	LOGPFSML(fi, LOGL_DEBUG, "forwarding unmodified RAB-AssignmentRequest to HNB\n");
	rc = rua_tx_dt(map->hnb_ctx, map->is_ps, map->rua_ctx_id, msgb_l2(oph->msg), msgb_l2len(oph->msg));

	/* Release the FSM normally */
	osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);

	return rc;
}

/*! Allocate MGW FSM and handle RANAP RAB AssignmentRequest).
 *  \ptmap[in] map hanbgw context map that is responsible for this call.
 *  \ptmap[in] oph osmo prim header with RANAP RAB AssignmentResponse (function takes no ownership).
 *  \ptmap[in] message ranap message container (function takes ownership).
 *  \returns 0 on success; negative on error. */
int handle_rab_ass_req(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message)
{
	static bool initialized = false;
	struct osmo_fsm_inst *fi;
	struct mgw_fsm_priv *mgw_fsm_priv;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	int rc;
	char fsm_name[255];

	/* Initialize FSM if not done yet */
	if (!initialized) {
		OSMO_ASSERT(osmo_fsm_register(&mgw_fsm) == 0);
		initialized = true;
	}

	/* The RTP stream negotiation usually begins with a RAB-AssignmentRequest and ends with an IU-Release, however
	 * it may also be thet the MSC decides to release the RAB with a dedicated RAB-AssignmentRequest that contains
	 * a ReleaseList. In this case an FSM will already be present. */
	if (map->mgw_fi) {
		/* A RAB Release might be in progress, handle it */
		rc = handle_rab_release(map, oph, message);
		if (rc >= 0)
			return rc;

		LOGPFSML(map->mgw_fi, LOGL_ERROR,
			 "mgw_fsm_alloc_and_handle_rab_ass_req() unable to handle RAB-AssignmentRequest!\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
	}

	mgw_fsm_priv = talloc_zero(map, struct mgw_fsm_priv);
	mgw_fsm_priv->ranap_rab_ass_req_message = message;

	/* This FSM only supports RAB assignments with a single RAB assignment only. This limitation has been taken
	 * into account under the assumption that voice calls typically require a single RAB only. Nevertheless, we
	 * will block all incoming RAB assignments that try to assign more (or less) than one RAB. */
	if (ranap_rab_ass_req_ies_get_count(&message->msg.raB_AssignmentRequestIEs) != 1) {
		LOGP(DMGW, LOGL_ERROR,
		     "mgw_fsm_alloc_and_handle_rab_ass_req() rua_ctx_id=%d, RAB-AssignmentRequest with more than one RAB assignment -- abort!\n",
		     map->rua_ctx_id);
		goto error;
	}

	/* Parse the RAB Assignment Request now, if it is bad for some reason we will exit early and not bother with
	 * creating an FSM etc. */
	ies = &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
	rc = ranap_rab_ass_req_ies_extract_inet_addr(&addr, &mgw_fsm_priv->rab_id, ies, 0);
	if (rc < 0) {
		LOGP(DMGW, LOGL_ERROR,
		     "mgw_fsm_alloc_and_handle_rab_ass_req() rua_ctx_id=%d, invalid RAB-AssignmentRequest -- abort!\n",
		     map->rua_ctx_id);
		goto error;
	}

	rc = osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	if (rc < 0) {
		LOGP(DMGW, LOGL_ERROR,
		     "mgw_fsm_alloc_and_handle_rab_ass_req() rua_ctx_id=%d, Invalid RTP IP-address or Port in RAB-AssignmentRequest -- abort\n",
		     map->rua_ctx_id);
		goto error;
	}
	osmo_strlcpy(mgw_fsm_priv->msc_rtp_addr, addr_str.ip, sizeof(mgw_fsm_priv->msc_rtp_addr));
	mgw_fsm_priv->msc_rtp_port = addr_str.port;

	/* Allocate the FSM and start it. */
	mgw_fsm_priv->map = map;
	snprintf(fsm_name, sizeof(fsm_name), "mgw-fsm-%u-%u", map->rua_ctx_id, mgw_fsm_priv->rab_id);
	fi = osmo_fsm_inst_alloc(&mgw_fsm, map, mgw_fsm_priv, LOGL_DEBUG, fsm_name);
	map->mgw_fi = fi;
	mgw_fsm_state_chg(fi, MGW_ST_CRCX_HNB);

	return 0;
error:
	/* Cleanup context and make sure that the call is cleared. */
	mgw_fsm_priv_cleanup(mgw_fsm_priv);
	tx_release_req(map);
	return -EINVAL;
}

/*! Handlie RANAP RAB AssignmentResponse (deliver message, complete RTP stream switching).
 *  \ptmap[in] map hanbgw context map that is responsible for this call.
 *  \ptmap[in] oph osmo prim header with RANAP RAB AssignmentResponse (function takes ownership).
 *  \ptmap[in] message ranap message container with decoded ranap message (function takes ownership).
 *  \returns 0 on success; negative on error. */
int mgw_fsm_handle_rab_ass_resp(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message)
{
	struct mgw_fsm_priv *mgw_fsm_priv;
	struct osmo_scu_prim *prim;
	struct msgb *msg;

	OSMO_ASSERT(oph);

	if (!map->mgw_fi) {
		/* NOTE: This situation is a corner-case. We may end up here when the co-located MGW caused a problem
		 * on the way between RANAP RAB Assignment Request and RANAP RAB Assignment Response. */

		LOGP(DMGW, LOGL_ERROR,
		     "mgw_fsm_handle_rab_ass_resp() rua_ctx_id=%d, no MGW fsm -- sending Iu-Release-Request!\n",
		     map->rua_ctx_id);

		/* Cleanup ranap message */
		ranap_cn_rx_co_free(message);
		talloc_free(message);

		/* Toss RAB-AssignmentResponse */
		prim = (struct osmo_scu_prim *)oph;
		msg = prim->oph.msg;
		msgb_free(msg);

		/* Send a release request, to make sure that the MSC is aware of the problem. */
		tx_release_req(map);
		return -1;
	}

	mgw_fsm_priv = map->mgw_fi->priv;
	mgw_fsm_priv->ranap_rab_ass_resp_oph = oph;
	mgw_fsm_priv->ranap_rab_ass_resp_message = message;
	osmo_fsm_inst_dispatch(map->mgw_fi, MGW_EV_RAB_ASS_RESP, NULL);
	return 0;
}

/*! Release the FSM and clear its associated RTP streams.
 *  \ptmap[in] map hanbgw context map that is responsible for this call.
 *  \returns 0 on success; negative on error. */
int mgw_fsm_release(struct hnbgw_context_map *map)
{
	if (!map->mgw_fi) {
		LOGP(DMGW, LOGL_ERROR, "mgw_fsm_release() rua_ctx_id=%d, no MGW fsm -- ignored!\n", map->rua_ctx_id);
		return -EINVAL;
	}

	osmo_fsm_inst_dispatch(map->mgw_fi, MGW_EV_RELEASE, NULL);
	return 0;
}
