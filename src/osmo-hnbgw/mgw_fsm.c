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
	struct msgb *msg;
	static const struct RANAP_Cause cause = {
		.present = RANAP_Cause_PR_transmissionNetwork,
		.choice.transmissionNetwork =
		    RANAP_CauseTransmissionNetwork_iu_transport_connection_failed_to_establish,
	};

	msg = ranap_new_msg_iu_rel_req(&cause);
	msg->l2h = msg->data;
	talloc_steal(OTC_SELECT, msg);
	map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, msg);
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
	struct msgb *ranap_rab_ass_resp_msgb;

	/* MGW context */
	struct mgcp_client *mgcpc;
	struct osmo_mgcpc_ep *mgcpc_ep;
	struct osmo_mgcpc_ep_ci *mgcpc_ep_ci_hnb;
	struct osmo_mgcpc_ep_ci *mgcpc_ep_ci_msc;
	struct osmo_sockaddr ci_hnb_crcx_ack_addr;
	char msc_rtp_addr[INET6_ADDRSTRLEN];
	uint16_t msc_rtp_port;
};

struct osmo_tdef_state_timeout mgw_fsm_timeouts[32] = {
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
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	const char *epname;
	struct mgcp_conn_peer mgw_info;
	int rc;

	LOGPFSML(fi, LOGL_DEBUG, "RAB-AssignmentRequest received, creating HNB side call-leg on MGW...\n");

	/* Parse the RAB Assignment Request now */
	ies = &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
	rc = ranap_rab_ass_req_ies_extract_inet_addr(&addr, &mgw_fsm_priv->rab_id, ies, 0);
	if (rc < 0) {
		LOGPFSML(fi,  LOGL_ERROR, "Invalid RAB-AssignmentRequest -- abort\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}

	rc = osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_ERROR,
			"Invalid RTP IP-address or port in RAB-AssignmentRequest -- abort\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}
	osmo_strlcpy(mgw_fsm_priv->msc_rtp_addr, addr_str.ip, sizeof(mgw_fsm_priv->msc_rtp_addr));
	mgw_fsm_priv->msc_rtp_port = addr_str.port;

	mgw_info = (struct mgcp_conn_peer) {
		.call_id = (map->rua_ctx_id << 8) | mgw_fsm_priv->rab_id,
		.ptime = 20,
		.conn_mode = MGCP_CONN_LOOPBACK,
	};
	mgw_info.codecs[0] = CODEC_IUFP;
	mgw_info.codecs_len = 1;

	mgw_fsm_priv->mgcpc = mgcp_client_pool_get(g_hnbgw->mgw_pool);
	if (!mgw_fsm_priv->mgcpc) {
		LOGPFSML(fi, LOGL_ERROR,
			 "cannot ensure MGW endpoint -- no MGW configured, check configuration!\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}
	epname = mgcp_client_rtpbridge_wildcard(mgw_fsm_priv->mgcpc);
	mgw_fsm_priv->mgcpc_ep =
	    osmo_mgcpc_ep_alloc(fi, MGW_EV_MGCP_TERM, mgw_fsm_priv->mgcpc, mgw_fsm_T_defs, fi->id, "%s", epname);
	mgw_fsm_priv->mgcpc_ep_ci_hnb = osmo_mgcpc_ep_ci_add(mgw_fsm_priv->mgcpc_ep, "to-HNB");

	osmo_mgcpc_ep_ci_request(mgw_fsm_priv->mgcpc_ep_ci_hnb, MGCP_VERB_CRCX, &mgw_info, fi, MGW_EV_MGCP_OK,
				 MGW_EV_MGCP_FAIL, NULL);
}

static void mgw_fsm_crcx_hnb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	const struct mgcp_conn_peer *mgw_info;
	struct osmo_sockaddr_str addr_str;
	struct osmo_sockaddr *addr = &mgw_fsm_priv->ci_hnb_crcx_ack_addr;
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
		rc = osmo_sockaddr_str_to_sockaddr(&addr_str, &addr->u.sas);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to convert RTP IP-address (%s) and Port (%u) to its binary representation\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		ies = &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
		rc = ranap_rab_ass_req_ies_replace_inet_addr(ies, addr, mgw_fsm_priv->rab_id);
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
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	struct msgb *msg;

	ies = &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
	msg = ranap_rab_ass_req_encode(ies);
	if (!msg) {
		LOGPFSML(fi, LOGL_ERROR, "failed to re-encode RAB-AssignmentRequest message\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG, "forwarding modified RAB-AssignmentRequest to HNB\n");
	msg->l2h = msg->data;
	talloc_steal(OTC_SELECT, msg);
	map_rua_dispatch(map, MAP_RUA_EV_TX_DIRECT_TRANSFER, msg);
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
			struct msgb *msg;

			LOGPFSML(fi, LOGL_ERROR,
				 "The RAB-AssignmentResponse contains a RAB-FailedList, RAB-Assignment (%u) failed.\n",
				 mgw_fsm_priv->rab_id);

			/* Forward the RAB-AssignmentResponse transparently. This will ensure that the MSC is informed
			 * about the problem. */
			LOGPFSML(fi, LOGL_DEBUG, "forwarding unmodified RAB-AssignmentResponse to MSC\n");

			msg = mgw_fsm_priv->ranap_rab_ass_resp_msgb;
			mgw_fsm_priv->ranap_rab_ass_resp_msgb = NULL;
			talloc_steal(OTC_SELECT, msg);

			rc = map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, msg);
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
	struct osmo_sockaddr_str addr_str;
	struct osmo_sockaddr addr;
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

		if (osmo_sockaddr_cmp(&mgw_fsm_priv->ci_hnb_crcx_ack_addr, &addr) != 0) {
			/* FIXME: Send RAB Modify Req to HNB. See OS#6127 */
			char addr_buf[INET6_ADDRSTRLEN + 8];
			LOGPFSML(fi, LOGL_ERROR, "Local MGW IuUP IP address %s changed to %s during MDCX."
				 " This is so far unsupported, adapt your osmo-mgw config!\n",
				 osmo_sockaddr_to_str(&mgw_fsm_priv->ci_hnb_crcx_ack_addr),
				 osmo_sockaddr_to_str_buf(addr_buf, sizeof(addr_buf), &addr));
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
		    msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_msgb) +
		    msgb_tailroom(mgw_fsm_priv->ranap_rab_ass_resp_msgb);
		rc = msgb_resize_area(mgw_fsm_priv->ranap_rab_ass_resp_msgb,
				      mgw_fsm_priv->ranap_rab_ass_resp_msgb->l2h,
				      msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_msgb), msg_max_len);
		OSMO_ASSERT(rc == 0);

		rc = ranap_rab_ass_resp_encode(msgb_l2(mgw_fsm_priv->ranap_rab_ass_resp_msgb),
					       msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_msgb), ies);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "failed to re-encode RAB-AssignmentResponse message\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_FAILURE, 0, 0);
			return;
		}

		/* Resize l2h back to the actual message length */
		rc = msgb_resize_area(mgw_fsm_priv->ranap_rab_ass_resp_msgb,
				      mgw_fsm_priv->ranap_rab_ass_resp_msgb->l2h,
				      msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_msgb), rc);
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
	struct msgb *ranap_msg;
	int rc;

	LOGPFSML(fi, LOGL_DEBUG, "forwarding modified RAB-AssignmentResponse to MSC\n");

	ranap_msg = mgw_fsm_priv->ranap_rab_ass_resp_msgb;
	mgw_fsm_priv->ranap_rab_ass_resp_msgb = NULL;
	talloc_steal(OTC_SELECT, ranap_msg);

	rc = map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, ranap_msg);
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
		/* Put MGCP client back into MGW pool */
		if (mgw_fsm_priv->mgcpc) {
			mgcp_client_pool_put(mgw_fsm_priv->mgcpc);
			mgw_fsm_priv->mgcpc = NULL;
		}
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

static void mgw_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	talloc_free(mgw_fsm_priv);
}

static void mgw_fsm_pre_term(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;
	struct hnbgw_context_map *map = mgw_fsm_priv->map;

	if (mgw_fsm_priv->mgcpc_ep) {
		/* Put MGCP client back into MGW pool */
		struct mgcp_client *mgcp_client = osmo_mgcpc_ep_client(mgw_fsm_priv->mgcpc_ep);
		mgcp_client_pool_put(mgcp_client);

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
static int release_mgw_fsm(struct hnbgw_context_map *map, struct msgb *ranap_msg)
{
	struct osmo_fsm_inst *fi = map->mgw_fi;
	int rc;

	/* Forward the unmodifed RAB-AssignmentRequest to HNB, so that the HNB is informed about the RAB release as
	 * well */
	LOGPFSML(fi, LOGL_DEBUG, "forwarding unmodified RAB-AssignmentRequest to HNB\n");
	rc = map_rua_dispatch(map, MAP_RUA_EV_TX_DIRECT_TRANSFER, ranap_msg);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_DEBUG, "cannot forward RAB-AssignmentRequest to HNB\n");
		return -EINVAL;
	}

	/* Release the FSM normally */
	osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
	return 0;
}

static bool is_rab_ass_without_tli(struct hnbgw_context_map *map, ranap_message *message)
{
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	RANAP_ProtocolIE_ContainerPair_t *protocol_ie_container_pair;
	RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;
	RANAP_RAB_SetupOrModifyItemFirst_t _rab_setup_or_modify_item_first = { 0 };
	RANAP_RAB_SetupOrModifyItemFirst_t *rab_setup_or_modify_item_first = &_rab_setup_or_modify_item_first;
	int rc;
	bool ret;

	ies = &message->msg.raB_AssignmentRequestIEs;

	if (!(ies->presenceMask & RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_SETUPORMODIFYLIST_PRESENT))
		return false;

	/* Detect the end of the list */
	if (ies->raB_SetupOrModifyList.list.count < 1)
		return false;

	protocol_ie_container_pair = ies->raB_SetupOrModifyList.list.array[0];
	protocol_ie_field_pair = protocol_ie_container_pair->list.array[0];

	if (!protocol_ie_field_pair)
		return false;

	if (protocol_ie_field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem) {
		RANAP_DEBUG
		    ("Decoding failed, the protocol IE field-pair is not of type RANAP RAB setup-or-modify-item!\n");
		return false;
	}

	rc = ranap_decode_rab_setupormodifyitemfirst(rab_setup_or_modify_item_first,
						     &protocol_ie_field_pair->firstValue);
	if (rc < 0)
		return false;

	ret = rab_setup_or_modify_item_first->transportLayerInformation == NULL;
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, rab_setup_or_modify_item_first);
	return ret;
}

/* Check if the message contains a RAB-ReleaseItem that matches the RAB-ID that is managed by the given context map */
static bool is_our_rab_release(struct hnbgw_context_map *map, ranap_message *message)
{
	bool rab_release_req;
	struct osmo_fsm_inst *fi = map->mgw_fi;
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;

	/* Check if the RAB that is handled by this FSM is addressed by the release request */
	rab_release_req = ranap_rab_ass_req_ies_check_release(&message->msg.raB_AssignmentRequestIEs,
							      mgw_fsm_priv->rab_id);
	if (!rab_release_req) {
		LOGPFSML(map->mgw_fi, LOGL_ERROR, "RAB-AssignmentRequest does not contain any RAB-RelaseItem with RAB-ID %u\n", mgw_fsm_priv->rab_id);
		return false;
	}
	LOGPFSML(map->mgw_fi, LOGL_NOTICE, "MSC asked to release RAB-ID %u\n", mgw_fsm_priv->rab_id);

	return true;
}

/*! Allocate MGW FSM and handle RANAP RAB AssignmentRequest.
 *  \param[in] map hnbgw context map that is responsible for this call.
 *  \param[in] ranap_msg msgb containing RANAP RAB AssignmentRequest at msgb_l2(), allocated in OTC_SELECT.
 *                       This function may talloc_steal(ranap_msg) to keep it for later.
 *  \param[in] message decoded RANAP message container, allocated in OTC_SELECT.
 *                     This function may talloc_steal(message) to keep it for later.
 *  \returns 0 on success; negative on error. */
int handle_rab_ass_req(struct hnbgw_context_map *map, struct msgb *ranap_msg, ranap_message *message)
{
	static bool initialized = false;
	struct mgw_fsm_priv *mgw_fsm_priv;
	char fsm_name[255];

	/* Initialize FSM if not done yet */
	if (!initialized) {
		OSMO_ASSERT(osmo_fsm_register(&mgw_fsm) == 0);
		initialized = true;
	}

	/* After a normal RAB Assignment, another RAB Assigment may follow, modifying some RAB parameters. This second
	 * RAB Assignment may omit transportLayerInformation (remains unchanged). Simply forward this to RUA, without
	 * the need to adjust anything here. Allow this only when there already is an mgw_fsm with proper address. */
	if (map->mgw_fi && is_rab_ass_without_tli(map, message)) {
		LOG_MAP(map, DCN, LOGL_INFO, "Rx secondary RAB Assignment Request, forwarding as-is\n");
		return map_rua_dispatch(map, MAP_RUA_EV_TX_DIRECT_TRANSFER, ranap_msg);
	}

	/* The RTP stream negotiation usually begins with a RAB-AssignmentRequest and ends with an IU-Release, however
	 * it may also be that the MSC decides to release the RAB with a dedicated RAB-AssignmentRequest that contains
	 * a ReleaseList. In this case an FSM will already be present. */
	if (map->mgw_fi) {
		/* Check if the RAB-AssignmentRequest contains a RAB-ReleaseItem that matches the RAB-ID we are
		 * managing in this HNBGW context map. */
		if (is_our_rab_release(map, message))
			return release_mgw_fsm(map, ranap_msg);

		/* The RAB-ReleaseItem in the incoming message should match the RAB ID we are managing. A mismatch may
		 * mean that there is an inconsistency between the HNBGW and the MSC state and the MGW FSM on the HNBGW
		 * side may serve an abandonned connection, which we will now close. However we must also assume that
		 * the incoming message may still contain a RAB-Assignment for a new RTP stream, so we still must
		 * continue with the message evaluation. */
		osmo_fsm_inst_state_chg(map->mgw_fi, MGW_ST_FAILURE, 0, 0);
		OSMO_ASSERT(map->mgw_fi == NULL);
	}

	/* This FSM only supports RAB assignments with a single RAB assignment only. This limitation has been taken
	 * into account under the assumption that voice calls typically require a single RAB only. Nevertheless, we
	 * will block all incoming RAB assignments that try to assign more (or less) than one RAB. */
	if (ranap_rab_ass_req_ies_get_count(&message->msg.raB_AssignmentRequestIEs) != 1) {
		LOGP(DMGW, LOGL_ERROR,
		     "%s() rua_ctx_id=%d, RAB-AssignmentRequest with more than one RAB assignment -- abort!\n",
		     __func__, map->rua_ctx_id);
		tx_release_req(map);
		return -1;
	}

	mgw_fsm_priv = talloc_zero(map, struct mgw_fsm_priv);
	mgw_fsm_priv->map = map;

	talloc_steal(mgw_fsm_priv, message);
	mgw_fsm_priv->ranap_rab_ass_req_message = message;

	/* Allocate FSM */
	snprintf(fsm_name, sizeof(fsm_name), "mgw-fsm-%u-%u", map->rua_ctx_id, mgw_fsm_priv->rab_id);
	map->mgw_fi = osmo_fsm_inst_alloc(&mgw_fsm, map, mgw_fsm_priv, LOGL_DEBUG, fsm_name);

	/* Start the FSM */
	mgw_fsm_state_chg(map->mgw_fi, MGW_ST_CRCX_HNB);
	return 0;
}

/*! Handlie RANAP RAB AssignmentResponse (deliver message, complete RTP stream switching).
 *  \param[in] map hnbgw context map that is responsible for this call.
 *  \param[in] ranap_msg msgb containing RANAP RAB AssignmentResponse at msgb_l2(), allocated in OTC_SELECT.
 *                       This function may talloc_steal(ranap_msg) to keep it for later.
 *  \param[in] message decoded RANAP message container, allocated in OTC_SELECT.
 *                     This function may talloc_steal(message) to keep it for later.
 *  \returns 0 on success; negative on error. */
int mgw_fsm_handle_rab_ass_resp(struct hnbgw_context_map *map, struct msgb *ranap_msg, ranap_message *message)
{
	struct mgw_fsm_priv *mgw_fsm_priv;

	OSMO_ASSERT(ranap_msg);

	if (!map->mgw_fi) {
		/* NOTE: This situation is a corner-case. We may end up here when the co-located MGW caused a problem
		 * on the way between RANAP RAB Assignment Request and RANAP RAB Assignment Response. */

		LOGP(DMGW, LOGL_ERROR,
		     "%s() rua_ctx_id=%d, no MGW fsm -- sending Iu-Release-Request!\n",
		     __func__, map->rua_ctx_id);

		/* Send a release request, to make sure that the MSC is aware of the problem. */
		tx_release_req(map);
		return -1;
	}

	if (map->mgw_fi->state == MGW_ST_ESTABLISHED) {
		/* This is a response to a second RAB Assignment Request, which only modified some RAB config on top of
		 * an earlier RAB Assignment. Just forward the response as-is, we already have our MGW set up and need
		 * no info from it. (i.e. we don't support modifying the RTP address.) */
		return map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, ranap_msg);
	}

	mgw_fsm_priv = map->mgw_fi->priv;

	talloc_steal(mgw_fsm_priv, ranap_msg);
	mgw_fsm_priv->ranap_rab_ass_resp_msgb = ranap_msg;

	talloc_steal(mgw_fsm_priv, message);
	mgw_fsm_priv->ranap_rab_ass_resp_message = message;

	osmo_fsm_inst_dispatch(map->mgw_fi, MGW_EV_RAB_ASS_RESP, NULL);
	return 0;
}

/*! Release the FSM and clear its associated RTP streams.
 *  \ptmap[in] map hnbgw context map that is responsible for this call.
 *  \returns 0 on success; negative on error. */
int mgw_fsm_release(struct hnbgw_context_map *map)
{
	if (!map->mgw_fi)
		return -EINVAL;

	osmo_fsm_inst_dispatch(map->mgw_fi, MGW_EV_RELEASE, NULL);
	return 0;
}
