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

struct osmo_tdef mgw_tdefs[] = {
	{.T = -2427, .default_val = 5, .desc = "timeout for MGCP response from MGW" },
	{ }
};

struct osmo_tdef_state_timeout mgw_fsm_timeouts[32] = {
	[MGW_ST_CRCX_HNB] = {.T = -1001 },
	[MGW_ST_ASSIGN] = {.T = -1002 },
	[MGW_ST_MDCX_HNB] = {.T = -1003 },
	[MGW_ST_CRCX_MSC] = {.T = -1004 },
};

#define mgw_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     mgw_fsm_timeouts, \
				     mgw_fsm_T_defs, \
				     -1)

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
	int rc;

	switch (event) {
	case MGW_EV_MGCP_OK:
		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(mgw_fsm_priv->mgcpc_ep_ci_hnb);
		if (!mgw_info) {
			LOGPFSML(fi, LOGL_ERROR, "Got no response from MGW\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
			return;
		}

		rc = ranap_rab_ass_req_ies_replace_inet_addr(&mgw_fsm_priv->ranap_rab_ass_req_message->msg.
							     raB_AssignmentRequestIEs, &addr, mgw_fsm_priv->rab_id);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to replace RTP IP-address (%s) and Port (%u) in RAB-AssignmentRequest\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
			return;
		}

		mgw_fsm_state_chg(MGW_ST_ASSIGN);
		return;
	case MGW_EV_MGCP_FAIL:
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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
	int rc;

	rc = ranap_rab_ass_req_encode(encoded, sizeof(encoded),
				      &mgw_fsm_priv->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_DEBUG, "failed to re-encode RAB-AssignmentRequest message\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG, "forwarding modified RAB-AssignmentRequest to HNB\n");
	rua_tx_dt(map->hnb_ctx, map->is_ps, map->rua_ctx_id, encoded, rc);
}

static void mgw_fsm_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case MGW_EV_RAB_ASS_RESP:
		mgw_fsm_state_chg(MGW_ST_MDCX_HNB);
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
	int rc;

	LOGPFSML(fi, LOGL_DEBUG, "RAB-AssignmentResponse received, completing HNB side call-leg on MGW...\n");

	mgw_info = (struct mgcp_conn_peer) {
		.call_id = map->rua_ctx_id,
		.ptime = 20,
		.conn_mode = MGCP_CONN_RECV_SEND,
	};
	mgw_info.codecs[0] = CODEC_IUFP;
	mgw_info.codecs_len = 1;

	rc = ranap_rab_ass_resp_ies_extract_inet_addr(&addr,
						      &mgw_fsm_priv->ranap_rab_ass_resp_message->msg.
						      raB_AssignmentResponseIEs, mgw_fsm_priv->rab_id);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_ERROR, "Failed to extract RTP IP-address and Port from RAB-AssignmentResponse\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
		return;
	}

	rc = osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	if (rc < 0) {
		LOGPFSML(fi, LOGL_ERROR, "Invalid RTP IP-address or Port in RAB-AssignmentResponse\n");
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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
			LOGPFSML(fi, LOGL_ERROR, "Got no response from MGW\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
			return;
		}
		mgw_fsm_state_chg(MGW_ST_CRCX_MSC);
		return;
	case MGW_EV_MGCP_FAIL:
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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

	switch (event) {
	case MGW_EV_MGCP_OK:
		mgw_info = osmo_mgcpc_ep_ci_get_rtp_info(mgw_fsm_priv->mgcpc_ep_ci_msc);
		if (!mgw_info) {
			LOGPFSML(fi, LOGL_ERROR, "Got no response from MGW\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
			return;
		}
		rc = ranap_rab_ass_resp_ies_replace_inet_addr(&mgw_fsm_priv->ranap_rab_ass_resp_message->msg.
							      raB_AssignmentResponseIEs, &addr, mgw_fsm_priv->rab_id);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to replace RTP IP-address (%s) and Port (%u) in RAB-AssignmentResponse\n",
				 mgw_info->addr, mgw_info->port);
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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
					       msgb_l2len(mgw_fsm_priv->ranap_rab_ass_resp_oph->msg),
					       &mgw_fsm_priv->ranap_rab_ass_resp_message->msg.
					       raB_AssignmentResponseIEs);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_DEBUG, "failed to re-encode RAB-AssignmentResponse message\n");
			osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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
	case MGW_EV_MGCP_FAIL:
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
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

	rc = osmo_sccp_user_sap_down(cn->sccp_user, oph);
	mgw_fsm_priv->ranap_rab_ass_resp_oph = NULL;
	if (rc < 0)
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);

	LOGPFSML(fi, LOGL_DEBUG, "HNB and MSC side call-legs completed!\n");
}

static void mgw_fsm_release_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void mgw_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgw_fsm_priv *mgw_fsm_priv = fi->priv;

	switch (event) {
	case MGW_EV_RELEASE:
		osmo_fsm_inst_state_chg(fi, MGW_ST_RELEASE, 0, 0);
		return;
	case MGW_EV_MGCP_TERM:
		mgw_fsm_priv->mgcpc_ep = NULL;
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
			S(MGW_EV_MGCP_OK) |
			S(MGW_EV_MGCP_FAIL),
		.out_state_mask =
			S(MGW_ST_ASSIGN) |
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
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_MDCX_HNB] = {
		.name = "MGW_ST_MDCX_HNB",
		.onenter = mgw_fsm_mdcx_hnb_onenter,
		.action = mgw_fsm_mdcx_hnb,
		.in_event_mask =
			S(MGW_EV_MGCP_OK) |
			S(MGW_EV_MGCP_FAIL),
		.out_state_mask =
			S(MGW_ST_CRCX_MSC) |
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_CRCX_MSC] = {
		.name = "MGW_ST_CRCX_MSC",
		.onenter = mgw_fsm_crcx_msc_onenter,
		.action = mgw_fsm_crcx_msc,
		.in_event_mask =
			S(MGW_EV_MGCP_OK) |
			S(MGW_EV_MGCP_FAIL),
		.out_state_mask =
			S(MGW_ST_ESTABLISHED) |
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_ESTABLISHED] = {
		.name = "MGW_ST_ESTABLISHED",
		.onenter = mgw_fsm_established_onenter,
		.in_event_mask = 0,
		.out_state_mask =
			S(MGW_ST_RELEASE),
	},
	[MGW_ST_RELEASE] = {
		.name = "MGW_ST_RELEASE",
		.onenter = mgw_fsm_release_onenter,
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
	.allstate_event_mask = S(MGW_EV_MGCP_TERM) | S(MGW_EV_RELEASE),
	.timer_cb = mgw_fsm_timer_cb,
	.cleanup = mgw_fsm_cleanup,
	.pre_term = mgw_fsm_pre_term,
};

/*! Allocate MGW FSM and handle RANAP RAB AssignmentRequest).
 *  \ptmap[in] map hanbgw context map that is responsible for this call.
 *  \ptmap[in] message ranap message container (function takes ownership).
 *  \returns 0 on success; negative on error. */
int mgw_fsm_alloc_and_handle_rab_ass_req(struct hnbgw_context_map *map, ranap_message *message)
{
	static bool initialized = false;
	struct osmo_fsm_inst *fi;
	struct mgw_fsm_priv *mgw_fsm_priv;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	int rc;
	char fsm_name[255];

	/* TODO: Check if the message is about the release of an already existing RAB. If yes, we must do the following:
	 * - In case FSM exists, release the FSM see also: mgw_fsm_release()
	 * - Pass message tranaparently to HNB, so that it can do what's needed to release the RAB */

	/* Initialize FSM if not done yet */
	if (!initialized) {
		OSMO_ASSERT(osmo_fsm_register(&mgw_fsm) == 0);
		initialized = true;
	}

	/* When there is already an FSM, make sure that it is terminated. Under normal circumstances this situation
	 * should not occur. */
	if (map->mgw_fi) {
		LOGPFSML(map->mgw_fi, LOGL_ERROR,
			 "mgw_fsm_alloc_and_handle_rab_ass_req() another FSM instance is about to replace this FSM!\n");
		osmo_fsm_inst_dispatch(map->mgw_fi, MGW_EV_RELEASE, NULL);
		map->mgw_fi = NULL;
	}

	mgw_fsm_priv = talloc_zero(map, struct mgw_fsm_priv);
	mgw_fsm_priv->ranap_rab_ass_req_message = message;

	/* Parse the RAB Assignment Request now, if it is bad for some reason we will exit early and not bother with
	 * creating an FSM etc. */
	rc = ranap_rab_ass_req_ies_extract_inet_addr(&addr, &mgw_fsm_priv->rab_id,
						     &mgw_fsm_priv->ranap_rab_ass_req_message->msg.
						     raB_AssignmentRequestIEs);
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
	mgw_fsm_state_chg(MGW_ST_CRCX_HNB);

	return 0;
error:
	/* TODO: If we fail in this early stage, we should generate an appropriate RAB AssignmentResponse to inform
	 * the core network about the failure. */
	mgw_fsm_priv_cleanup(mgw_fsm_priv);
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
	struct hnb_context *hnb = map->hnb_ctx;
	struct hnbgw_cnlink *cn = hnb->gw->sccp.cnlink;

	OSMO_ASSERT(oph);

	if (!map->mgw_fi) {
		LOGP(DMGW, LOGL_ERROR, "mgw_fsm_handle_rab_ass_resp() rua_ctx_id=%d, no MGW fsm!\n",
		     map->rua_ctx_id);

		/* Cleanup ranap message */
		ranap_cn_rx_co_free(message);
		talloc_free(message);

		/* Transparently forward response to core network */
		LOGP(DMGW, LOGL_ERROR, "mgw_fsm_handle_rab_ass_resp() rua_ctx_id=%d, forwarding unmodifed RAB-AssigmentResponse.\n",
		     map->rua_ctx_id);
		return osmo_sccp_user_sap_down(cn->sccp_user, oph);

		/* TODO: Check if the RAB assignment was successful. If yes, generate RANAP RAB ReleaseRequest, so that
		 * the core network is informed about the problem with the RTP streams. The core network will then
		 * take action to release the RAB again. */
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
		LOGP(DMGW, LOGL_ERROR, "mgw_fsm_release() rua_ctx_id=%d, no MGW fsm -- ignored!\n",
		     map->rua_ctx_id);
		return -EINVAL;
	}

	osmo_fsm_inst_dispatch(map->mgw_fi, MGW_EV_RELEASE, NULL);
	return 0;
}
