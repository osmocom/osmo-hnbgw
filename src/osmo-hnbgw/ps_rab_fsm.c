/* Handle PFCP communication with the UPF for a single RAB. */
/* (C) 2022 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Janosch Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <osmocom/core/tdef.h>

#include <osmocom/pfcp/pfcp_endpoint.h>
#include <osmocom/pfcp/pfcp_cp_peer.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/ps_rab_fsm.h>
#include <osmocom/hnbgw/ps_rab_ass_fsm.h>

#define LOG_PS_RAB(RAB, LOGL, FMT, ARGS...) \
	LOGPFSML((RAB) ? (RAB)->fi : NULL, LOGL, FMT, ##ARGS)

enum ps_rab_state {
	PS_RAB_ST_RX_CORE_REMOTE_F_TEID,
	PS_RAB_ST_WAIT_PFCP_EST_RESP,
	PS_RAB_ST_WAIT_ACCESS_REMOTE_F_TEID,
	PS_RAB_ST_WAIT_PFCP_MOD_RESP,
	PS_RAB_ST_ESTABLISHED,
	PS_RAB_ST_WAIT_PFCP_DEL_RESP,
	PS_RAB_ST_WAIT_USE_COUNT,
};

enum ps_rab_event {
	PS_RAB_EV_PFCP_EST_RESP,
	PS_RAB_EV_RX_ACCESS_REMOTE_F_TEID,
	PS_RAB_EV_PFCP_MOD_RESP,
	PS_RAB_EV_PFCP_DEL_RESP,
	PS_RAB_EV_USE_COUNT_ZERO,
};

static const struct value_string ps_rab_fsm_event_names[] = {
	OSMO_VALUE_STRING(PS_RAB_EV_PFCP_EST_RESP),
	OSMO_VALUE_STRING(PS_RAB_EV_RX_ACCESS_REMOTE_F_TEID),
	OSMO_VALUE_STRING(PS_RAB_EV_PFCP_MOD_RESP),
	OSMO_VALUE_STRING(PS_RAB_EV_PFCP_DEL_RESP),
	OSMO_VALUE_STRING(PS_RAB_EV_USE_COUNT_ZERO),
	{}
};

struct osmo_tdef_state_timeout ps_rab_fsm_timeouts[32] = {
	/* PS_RAB_ST_WAIT_PFCP_EST_RESP is terminated by PFCP timeouts via resp_cb() */
	/* PS_RAB_ST_WAIT_ACCESS_REMOTE_F_TEID is terminated by ps_rab_ass_fsm */
	/* PS_RAB_ST_WAIT_PFCP_MOD_RESP is terminated by PFCP timeouts via resp_cb() */
	/* PS_RAB_ST_WAIT_PFCP_DEL_RESP is terminated by PFCP timeouts via resp_cb() */
};

enum pdr_far_id {
	ID_CORE_TO_ACCESS = 1,
	ID_ACCESS_TO_CORE = 2,
};


#define ps_rab_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, ps_rab_fsm_timeouts, hnbgw_T_defs, -1)

#define PS_RAB_USE_ACTIVE "active"

static struct osmo_fsm ps_rab_fsm;

static int ps_rab_fsm_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line);

static struct ps_rab *ps_rab_alloc(struct hnbgw_context_map *map, uint8_t rab_id)
{
	struct osmo_fsm_inst *fi;
	struct ps_rab *rab;

	/* Allocate with the global hnb_gw, so that we can gracefully handle PFCP release even if a hnb_ctx gets
	 * deallocated. */
	fi = osmo_fsm_inst_alloc(&ps_rab_fsm, g_hnbgw, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	osmo_fsm_inst_update_id_f_sanitize(fi, '-', "%s-RUA-%u-RAB-%u", hnb_context_name(map->hnb_ctx), map->rua_ctx_id,
					   rab_id);

	rab = talloc(fi, struct ps_rab);
	OSMO_ASSERT(rab);
	*rab = (struct ps_rab){
		.fi = fi,
		.map = map,
		.rab_id = rab_id,
		.use_count = {
			.talloc_object = rab,
			.use_cb = ps_rab_fsm_use_cb,
		},
	};
	fi->priv = rab;

	OSMO_ASSERT(osmo_use_count_get_put(&rab->use_count, PS_RAB_USE_ACTIVE, 1) == 0);

	llist_add_tail(&rab->entry, &map->ps_rabs);
	return rab;
}

/* Iterate all ps_rab instances of all context maps and return the one matching the given SEID.
 * If is_cp_seid == true, match seid with rab->cp_seid (e.g. for received PFCP messages).
 * Otherwise match seid with rab->up_f_seid.seid (e.g. for sent PFCP messages). */
struct ps_rab *ps_rab_find_by_seid(uint64_t seid, bool is_cp_seid)
{
	struct hnb_context *hnb;
	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		struct hnbgw_context_map *map;
		llist_for_each_entry(map, &hnb->map_list, hnb_list) {
			struct ps_rab *rab;
			llist_for_each_entry(rab, &map->ps_rabs, entry) {
				uint64_t rab_seid = is_cp_seid ? rab->cp_seid : rab->up_f_seid.seid;
				if (rab_seid == seid)
					return rab;
			}
		}
	}
	return NULL;
}

void ps_rab_pfcp_set_msg_ctx(struct ps_rab *rab, struct osmo_pfcp_msg *m)
{
	if (m->ctx.session_fi)
		return;
	m->ctx.session_fi = rab->fi;
	m->ctx.session_use_count = &rab->use_count;
	m->ctx.session_use_token = "PFCP_MSG";
	OSMO_ASSERT(osmo_use_count_get_put(m->ctx.session_use_count, m->ctx.session_use_token, 1) == 0);
}

static struct osmo_pfcp_msg *ps_rab_new_pfcp_msg_req(struct ps_rab *rab, enum osmo_pfcp_message_type msg_type)
{
	struct osmo_pfcp_msg *m = osmo_pfcp_cp_peer_new_req(g_hnbgw->pfcp.cp_peer, msg_type);

	m->h.seid_present = true;
	m->h.seid = rab->up_f_seid.seid;
	ps_rab_pfcp_set_msg_ctx(rab, m);
	return m;
}

struct ps_rab *ps_rab_get(struct hnbgw_context_map *map, uint8_t rab_id)
{
	struct ps_rab *rab;
	llist_for_each_entry(rab, &map->ps_rabs, entry) {
		if (rab->rab_id != rab_id)
			continue;
		return rab;
	}
	return NULL;
}

bool ps_rab_is_established(const struct ps_rab *rab)
{
	return rab && rab->fi->state == PS_RAB_ST_ESTABLISHED;
}

void ps_rab_failure(struct ps_rab *rab)
{
	if (rab->req_fi)
		osmo_fsm_inst_dispatch(rab->req_fi, PS_RAB_ASS_EV_RAB_FAIL, rab);
	if (rab->resp_fi)
		osmo_fsm_inst_dispatch(rab->resp_fi, PS_RAB_ASS_EV_RAB_FAIL, rab);
	ps_rab_release(rab);
}

struct ps_rab *ps_rab_start(struct hnbgw_context_map *map, uint8_t rab_id,
			    const struct addr_teid *core_f_teid, bool use_x213_nsap,
			    struct osmo_fsm_inst *req_fi)
{
	struct osmo_fsm_inst *fi;
	struct ps_rab *rab;

	rab = ps_rab_alloc(map, rab_id);
	fi = rab->fi;
	rab->req_fi = req_fi;
	rab->core.remote = *core_f_teid;
	rab->core.use_x213_nsap = use_x213_nsap;

	/* Got the RAB's Core side GTP info. Route the GTP for via the local UPF.
	 * Establish a PFCP session with the UPF: tell it about the Core side GTP endpoint and request local F-TEIDs. */
	if (ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_PFCP_EST_RESP)) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		return NULL;
	}

	return rab;
}

#define set_netinst(NETINST_MEMBER, STRING) do { \
		if ((STRING) && *(STRING)) { \
			NETINST_MEMBER##_present = true; \
			OSMO_STRLCPY_ARRAY(NETINST_MEMBER.str, STRING); \
		} \
	} while (0)

/* Add two PDR and two FAR to the PFCP Session Establishment Request message, according to the information found in rab.
 */
static int rab_to_pfcp_session_est_req(struct osmo_pfcp_msg_session_est_req *ser, struct ps_rab *rab)
{
	if (ser->create_pdr_count + 2 > ARRAY_SIZE(ser->create_pdr)
	    || ser->create_far_count + 2 > ARRAY_SIZE(ser->create_far)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "insufficient space for Create PDR / Create FAR IEs\n");
		return -1;
	}

	/* Core to Access:
	 * - UPF should return an F-TEID for the PDR, to be forwarded back to Core later in
	 *   RANAP RAB Assignment Response.
	 * - we don't know the Access side GTP address yet, so set FAR to DROP.
	 */
	ser->create_pdr[ser->create_pdr_count] = (struct osmo_pfcp_ie_create_pdr){
		.pdr_id = ID_CORE_TO_ACCESS,
		.precedence = 255,
		.pdi = {
			.source_iface = OSMO_PFCP_SOURCE_IFACE_CORE,
			.local_f_teid_present = true,
			.local_f_teid = {
				.choose_flag = true,
				.choose = {
					.ipv4_addr = true,
				},
			},
		},
		.outer_header_removal_present = true,
		.outer_header_removal = {
			.desc = OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV4,
		},
		.far_id_present = true,
		.far_id = ID_CORE_TO_ACCESS,
	};
	set_netinst(ser->create_pdr[ser->create_pdr_count].pdi.network_inst, g_hnbgw->config.pfcp.netinst.core);
	ser->create_pdr_count++;

	ser->create_far[ser->create_far_count] = (struct osmo_pfcp_ie_create_far){
		.far_id = ID_CORE_TO_ACCESS,
	};
	osmo_pfcp_bits_set(ser->create_far[ser->create_far_count].apply_action.bits,
			   OSMO_PFCP_APPLY_ACTION_DROP, true);
	ser->create_far_count++;

	/* Access to Core:
	 * - UPF should return an F-TEID for the PDR, to be forwarded to Access in the modified
	 *   RANAP RAB Assignment Request.
	 * - we already know the Core's GTP endpoint F-TEID, so fully set up this FAR.
	 */
	ser->create_pdr[ser->create_pdr_count] = (struct osmo_pfcp_ie_create_pdr){
		.pdr_id = ID_ACCESS_TO_CORE,
		.precedence = 255,
		.pdi = {
			.source_iface = OSMO_PFCP_SOURCE_IFACE_ACCESS,
			.local_f_teid_present = true,
			.local_f_teid = {
				.choose_flag = true,
				.choose = {
					.ipv4_addr = true,
				},
			},
		},
		.outer_header_removal_present = true,
		.outer_header_removal = {
			.desc = OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV4,
		},
		.far_id_present = true,
		.far_id = ID_ACCESS_TO_CORE,
	};
	set_netinst(ser->create_pdr[ser->create_pdr_count].pdi.network_inst, g_hnbgw->config.pfcp.netinst.access);
	ser->create_pdr_count++;

	ser->create_far[ser->create_far_count] = (struct osmo_pfcp_ie_create_far){
		.far_id = ID_ACCESS_TO_CORE,
		.forw_params_present = true,
		.forw_params = {
			.destination_iface = OSMO_PFCP_DEST_IFACE_CORE,
			.outer_header_creation_present = true,
			.outer_header_creation = {
				.teid_present = true,
				.teid = rab->core.remote.teid,
				.ip_addr.v4_present = true,
				.ip_addr.v4 = rab->core.remote.addr,
			},
		},
	};
	osmo_pfcp_bits_set(ser->create_far[ser->create_far_count].forw_params.outer_header_creation.desc_bits,
			   OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4, true);
	osmo_pfcp_bits_set(ser->create_far[ser->create_far_count].apply_action.bits,
			   OSMO_PFCP_APPLY_ACTION_FORW, true);
	set_netinst(ser->create_far[ser->create_far_count].forw_params.network_inst, g_hnbgw->config.pfcp.netinst.core);
	ser->create_far_count++;

	return 0;
}

static int on_pfcp_est_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg);

static void ps_rab_fsm_wait_pfcp_est_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ps_rab *rab = fi->priv;
	struct osmo_pfcp_msg *m;
	struct osmo_pfcp_ie_f_seid cp_f_seid;
	struct osmo_pfcp_msg_session_est_req *ser;

	/* So far we have the rab->core.remote information. Send that to the UPF.
	 * Also request all local GTP endpoints from UPF (rab->{core,access}.local) */
	m = ps_rab_new_pfcp_msg_req(rab, OSMO_PFCP_MSGT_SESSION_EST_REQ);

	/* Send UP-SEID as zero, the UPF has yet to assign a SEID for itself remotely */
	m->h.seid = 0;

	/* Make a new CP-SEID, our local reference for the PFCP session. */
	rab->cp_seid = osmo_pfcp_next_seid(&g_hnbgw->pfcp.cp_peer->next_seid_state);
	cp_f_seid = (struct osmo_pfcp_ie_f_seid){
		.seid = rab->cp_seid,
	};
	osmo_pfcp_ip_addrs_set(&cp_f_seid.ip_addr, &osmo_pfcp_endpoint_get_cfg(g_hnbgw->pfcp.ep)->local_addr);

	m->ies.session_est_req = (struct osmo_pfcp_msg_session_est_req){
		.node_id = m->ies.session_est_req.node_id,
		.cp_f_seid_present = true,
		.cp_f_seid = cp_f_seid,
	};
	ser = &m->ies.session_est_req;

	/* Create PDR+FAR pairs */
	if (rab_to_pfcp_session_est_req(ser, rab)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "Failed to compose PFCP message\n");
		osmo_pfcp_msg_free(m);
		ps_rab_failure(rab);
		return;
	}

	/* Send PFCP Session Establishment Request to UPF, wait for response. */
	m->ctx.resp_cb = on_pfcp_est_resp;
	if (osmo_pfcp_endpoint_tx(g_hnbgw->pfcp.ep, m)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "Failed to send PFCP message\n");
		ps_rab_failure(rab);
	}
}

static int on_pfcp_est_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg)
{
	struct ps_rab *rab = req->ctx.session_fi->priv;

	/* Send as FSM event to ensure this step is currently allowed */
	osmo_fsm_inst_dispatch(rab->fi, PS_RAB_EV_PFCP_EST_RESP, rx_resp);

	/* By returning 0 here, the rx_resp message is not dispatched "again" to pfcp_ep->rx_msg(). We've handled it
	 * here already. */
	return 0;
}

static void ps_rab_rx_pfcp_est_resp(struct osmo_fsm_inst *fi, struct osmo_pfcp_msg *rx);

static void ps_rab_fsm_wait_pfcp_est_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case PS_RAB_EV_PFCP_EST_RESP:
		ps_rab_rx_pfcp_est_resp(fi, data);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

/* Look for dst->local.pdr_id in ser->created_pdr[], and copy the GTP endpoint info to dst->local.addr_teid, if found. */
static int get_local_f_teid_from_created_pdr(struct half_gtp_map *dst, struct osmo_pfcp_msg_session_est_resp *ser,
					     uint8_t pdr_id)
{
	int i;
	for (i = 0; i < ser->created_pdr_count; i++) {
		struct osmo_pfcp_ie_created_pdr *cpdr = &ser->created_pdr[i];
		if (cpdr->pdr_id != pdr_id)
			continue;
		if (!cpdr->local_f_teid_present)
			continue;
		if (cpdr->local_f_teid.choose_flag)
			continue;
		if (!cpdr->local_f_teid.fixed.ip_addr.v4_present)
			continue;
		dst->local.addr = cpdr->local_f_teid.fixed.ip_addr.v4;
		dst->local.teid = cpdr->local_f_teid.fixed.teid;
		dst->local.present = true;
		return 0;
	}
	return -1;
}

static void ps_rab_rx_pfcp_est_resp(struct osmo_fsm_inst *fi, struct osmo_pfcp_msg *rx)
{
	struct ps_rab *rab = fi->priv;
	enum osmo_pfcp_cause *cause;
	struct osmo_pfcp_msg_session_est_resp *ser;

	if (!rx) {
		/* This happens when no response has arrived after all PFCP timeouts and retransmissions. */
		LOG_PS_RAB(rab, LOGL_ERROR, "No response to PFCP Session Establishment Request\n");
		goto pfcp_session_est_failed;
	}

	ser = &rx->ies.session_est_resp;

	cause = osmo_pfcp_msg_cause(rx);
	if (!cause || *cause != OSMO_PFCP_CAUSE_REQUEST_ACCEPTED) {
		LOG_PS_RAB(rab, LOGL_ERROR, "PFCP Session Establishment Response was not successful: %s\n",
			   cause ? osmo_pfcp_cause_str(*cause) : "NULL");
		goto pfcp_session_est_failed;
	}

	/* Get the UPF's SEID for future messages for this PFCP session */
	if (!ser->up_f_seid_present) {
		LOG_PS_RAB(rab, LOGL_ERROR, "PFCP Session Establishment Response lacks a UP F-SEID\n");
		goto pfcp_session_est_failed;
	}
	rab->up_f_seid = ser->up_f_seid;

	if (rab->release_requested) {
		/* The UE conn or the entire HNB has released while we were waiting for a PFCP response. Now that there
		 * is a remote SEID, we can finally delete the session that we asked for earlier. */
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_PFCP_DEL_RESP);
		return;
	}

	/* Get the UPF's local F-TEIDs for both Core and Access */
	if (get_local_f_teid_from_created_pdr(&rab->core, ser, ID_CORE_TO_ACCESS)
	    || get_local_f_teid_from_created_pdr(&rab->access, ser, ID_ACCESS_TO_CORE)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "Missing F-TEID in PFCP Session Establishment Response\n");
		ps_rab_failure(rab);
		return;
	}

	if (rab->req_fi)
		osmo_fsm_inst_dispatch(rab->req_fi, PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX, rab);

	/* The RAB Assignment Response will yield the hNodeB's F-TEID, i.e. the F-TEID we are supposed to send to Access
	 * in outgoing GTP packets. */
	ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_ACCESS_REMOTE_F_TEID);
	return;

pfcp_session_est_failed:
	if (rab->release_requested) {
		/* the RAB was released and we were waiting for some PFCP responsewhile waiting for a response, and now
		 * we know that no session has been created. No PFCP left, deallocate. */
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_USE_COUNT);
		return;
	}
	ps_rab_failure(rab);
}

int ps_rab_rx_access_remote_f_teid(struct hnbgw_context_map *map, uint8_t rab_id,
				   const struct ps_rab_rx_args *args)
{
	int rc;
	struct ps_rab *rab = ps_rab_get(map, rab_id);
	if (!rab) {
		LOG_MAP(map, DLPFCP, LOGL_ERROR, "There is no RAB with id %u\n", rab_id);
		return -ENOENT;
	}
	/* Dispatch as event to make sure this is currently allowed */
	rc = osmo_fsm_inst_dispatch(rab->fi, PS_RAB_EV_RX_ACCESS_REMOTE_F_TEID, (void *)args);
	if (rc)
		return rc;
	return 0;
}

static void ps_rab_fsm_wait_access_remote_f_teid(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ps_rab *rab = fi->priv;
	const struct ps_rab_rx_args *args;
	switch (event) {
	case PS_RAB_EV_RX_ACCESS_REMOTE_F_TEID:
		args = data;
		rab->resp_fi = args->notify_fi;
		rab->access.use_x213_nsap = args->use_x213_nsap;
		rab->access.remote = args->f_teid;
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_PFCP_MOD_RESP);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

/* Add an Update FAR to the PFCP Session Modification Request message, updating a remote F-TEID. */
static int rab_to_pfcp_session_mod_req_upd_far(struct osmo_pfcp_msg_session_mod_req *smr,
					       uint32_t far_id, const struct addr_teid *remote_f_teid,
					       const char *far_netinst)
{
	if (smr->upd_far_count + 1 > ARRAY_SIZE(smr->upd_far))
		return -1;

	smr->upd_far[smr->upd_far_count] = (struct osmo_pfcp_ie_upd_far){
		.far_id = far_id,
		.apply_action_present = true,
		/* apply_action.bits set below */
		.upd_forw_params_present = true,
		.upd_forw_params = {
			.outer_header_creation_present = true,
			.outer_header_creation = {
				/* desc_bits set below */
				.teid_present = true,
				.teid = remote_f_teid->teid,
				.ip_addr.v4_present = true,
				.ip_addr.v4 = remote_f_teid->addr,
			},
		},
	};
	osmo_pfcp_bits_set(smr->upd_far[smr->upd_far_count].apply_action.bits,
			   OSMO_PFCP_APPLY_ACTION_FORW, true);
	osmo_pfcp_bits_set(smr->upd_far[smr->upd_far_count].upd_forw_params.outer_header_creation.desc_bits,
			   OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4, true);
	set_netinst(smr->upd_far[smr->upd_far_count].upd_forw_params.network_inst, far_netinst);
	smr->upd_far_count++;

	return 0;
}

static int on_pfcp_mod_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg);

static void ps_rab_fsm_wait_pfcp_mod_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* We have been given the Access side's remote F-TEID, now in rab->access.remote, and we need to tell the UPF
	 * about it. This affects the Core to Access direction: now we know where to forward payloads coming from Core.
	 */
	struct ps_rab *rab = fi->priv;
	struct osmo_pfcp_msg *m;

	if (!(rab->up_f_seid.ip_addr.v4_present /* || rab->up_f_seid.ip_addr.v6_present */)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "no valid PFCP session\n");
		ps_rab_failure(rab);
		return;
	}

	m = ps_rab_new_pfcp_msg_req(rab, OSMO_PFCP_MSGT_SESSION_MOD_REQ);

	if (rab_to_pfcp_session_mod_req_upd_far(&m->ies.session_mod_req, ID_CORE_TO_ACCESS, &rab->access.remote,
						g_hnbgw->config.pfcp.netinst.access)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "error composing Update FAR IE in PFCP msg\n");
		ps_rab_failure(rab);
		return;
	}

	m->ctx.resp_cb = on_pfcp_mod_resp;
	if (osmo_pfcp_endpoint_tx(g_hnbgw->pfcp.ep, m)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "Failed to send PFCP message\n");
		ps_rab_failure(rab);
	}
}

static int on_pfcp_mod_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg)
{
	struct ps_rab *rab = req->ctx.session_fi->priv;

	/* Send as FSM event to ensure this step is currently allowed */
	osmo_fsm_inst_dispatch(rab->fi, PS_RAB_EV_PFCP_MOD_RESP, rx_resp);

	/* By returning 0 here, the rx_resp message is not dispatched "again" to pfcp_ep->rx_msg(). We've handled it
	 * here already. */
	return 0;
}

static void ps_rab_rx_pfcp_mod_resp(struct osmo_fsm_inst *fi, struct osmo_pfcp_msg *rx);

static void ps_rab_fsm_wait_pfcp_mod_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case PS_RAB_EV_PFCP_MOD_RESP:
		ps_rab_rx_pfcp_mod_resp(fi, data);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static void ps_rab_rx_pfcp_mod_resp(struct osmo_fsm_inst *fi, struct osmo_pfcp_msg *rx)
{
	struct ps_rab *rab = fi->priv;
	enum osmo_pfcp_cause *cause;

	if (!rx) {
		LOG_PS_RAB(rab, LOGL_ERROR, "No response to PFCP Session Modification Request\n");
		ps_rab_failure(rab);
		return;
	}

	cause = osmo_pfcp_msg_cause(rx);
	if (!cause || *cause != OSMO_PFCP_CAUSE_REQUEST_ACCEPTED) {
		LOG_PS_RAB(rab, LOGL_ERROR, "PFCP Session Modification Response was not successful: %s\n",
			   cause ? osmo_pfcp_cause_str(*cause) : "NULL");
		ps_rab_failure(rab);
		return;
	}

	/* This RAB is now complete. Everything went as expected, now we can forward the RAB Assignment Response to the
	 * CN. */
	ps_rab_fsm_state_chg(PS_RAB_ST_ESTABLISHED);
}

static void ps_rab_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ps_rab *rab = fi->priv;
	if (rab->resp_fi)
		osmo_fsm_inst_dispatch(rab->resp_fi, PS_RAB_ASS_EV_RAB_ESTABLISHED, rab);
}

static int on_pfcp_del_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg);

static void ps_rab_fsm_wait_pfcp_del_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* If a PFCP session has been established, send a Session Deletion Request and wait for the response.
	 * If no session is established, just terminate. */
	struct ps_rab *rab = fi->priv;
	struct osmo_pfcp_msg *m;

	if (!(rab->up_f_seid.ip_addr.v4_present /* || rab->up_f_seid.ip_addr.v6_present */)) {
		/* There is no valid PFCP session, so no need to send a Session Deletion Request */
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_USE_COUNT);
		return;
	}

	m = ps_rab_new_pfcp_msg_req(rab, OSMO_PFCP_MSGT_SESSION_DEL_REQ);
	m->ctx.resp_cb = on_pfcp_del_resp;
	if (osmo_pfcp_endpoint_tx(g_hnbgw->pfcp.ep, m)) {
		LOG_PS_RAB(rab, LOGL_ERROR, "Failed to send PFCP message\n");
		ps_rab_failure(rab);
	}
}

static int on_pfcp_del_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg)
{
	struct ps_rab *rab = req->ctx.session_fi->priv;
	if (errmsg)
		LOG_PS_RAB(rab, LOGL_ERROR, "PFCP Session Deletion Response: %s\n", errmsg);
	osmo_fsm_inst_dispatch(rab->fi, PS_RAB_EV_PFCP_DEL_RESP, rx_resp);

	/* By returning 0 here, the rx_resp message is not dispatched "again" to pfcp_ep->rx_msg(). We've handled it
	 * here already. */
	return 0;
}

static void ps_rab_fsm_wait_pfcp_del_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case PS_RAB_EV_PFCP_DEL_RESP:
		/* All done, terminate. Even if the Session Deletion failed, there's nothing we can do about it. */
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_USE_COUNT);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

static int ps_rab_fsm_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct ps_rab *rab = e->use_count->talloc_object;
	if (!osmo_use_count_total(&rab->use_count))
		osmo_fsm_inst_dispatch(rab->fi, PS_RAB_EV_USE_COUNT_ZERO, NULL);
	return 0;
}

static void ps_rab_fsm_wait_use_count_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ps_rab *rab = fi->priv;
	OSMO_ASSERT(osmo_use_count_get_put(&rab->use_count, PS_RAB_USE_ACTIVE, -1) == 0);
}

static void ps_rab_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case PS_RAB_EV_USE_COUNT_ZERO:
		if (fi->state == PS_RAB_ST_WAIT_USE_COUNT)
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		/* else, ignore. */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ps_rab_forget_map(struct ps_rab *rab)
{
	/* remove from map->ps_rabs */
	if (rab->map)
		llist_del(&rab->entry);
	rab->map = NULL;
}

static void ps_rab_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ps_rab *rab = fi->priv;
	ps_rab_forget_map(rab);
}

void ps_rab_release(struct ps_rab *rab)
{
	struct osmo_fsm_inst *fi = rab->fi;
	ps_rab_forget_map(rab);
	switch (fi->state) {
	case PS_RAB_ST_RX_CORE_REMOTE_F_TEID:
		/* No session requested yet. Nothing to be deleted. */
		LOG_PS_RAB(rab, LOGL_NOTICE, "RAB release before PFCP Session Establishment Request, terminating\n");
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_USE_COUNT);
		return;
	case PS_RAB_ST_WAIT_PFCP_EST_RESP:
		/* Session was requested via PFCP, but we only know the SEID to send in a deletion when the PFCP Session
		 * Establishment Response arrives. */
		rab->release_requested = true;
		LOG_PS_RAB(rab, LOGL_ERROR, "RAB release while waiting for PFCP Session Establishment Response\n");
		return;
	default:
		/* Session has been established (and we know the SEID). Initiate deletion. */
		LOG_PS_RAB(rab, LOGL_INFO, "RAB release, deleting PFCP session\n");
		ps_rab_fsm_state_chg(PS_RAB_ST_WAIT_PFCP_DEL_RESP);
		return;
	case PS_RAB_ST_WAIT_PFCP_DEL_RESP:
		/* Already requested a PFCP Session Deletion. Nothing else to do, wait for the Deletion Response (or
		 * timeout). */
		LOG_PS_RAB(rab, LOGL_INFO, "RAB release while waiting for PFCP Session Deletion Response\n");
		return;
	case PS_RAB_ST_WAIT_USE_COUNT:
		/* Already released, just wait for the last users (queued PFCP messages) to expire. */
		LOG_PS_RAB(rab, LOGL_INFO, "RAB release, already waiting for deallocation\n");
		return;
	}
}

#define S(x) (1 << (x))

static const struct osmo_fsm_state ps_rab_fsm_states[] = {
	[PS_RAB_ST_RX_CORE_REMOTE_F_TEID] = {
		.name = "RX_CORE_REMOTE_F_TEID",
		.out_state_mask = 0
			| S(PS_RAB_ST_WAIT_PFCP_EST_RESP)
			| S(PS_RAB_ST_WAIT_USE_COUNT)
			,
	},
	[PS_RAB_ST_WAIT_PFCP_EST_RESP] = {
		.name = "WAIT_PFCP_EST_RESP",
		.onenter = ps_rab_fsm_wait_pfcp_est_resp_onenter,
		.action = ps_rab_fsm_wait_pfcp_est_resp,
		.in_event_mask = 0
			| S(PS_RAB_EV_PFCP_EST_RESP)
			,
		.out_state_mask = 0
			| S(PS_RAB_ST_WAIT_ACCESS_REMOTE_F_TEID)
			| S(PS_RAB_ST_WAIT_USE_COUNT)
			,
	},
	[PS_RAB_ST_WAIT_ACCESS_REMOTE_F_TEID] = {
		.name = "WAIT_ACCESS_REMOTE_F_TEID",
		.action = ps_rab_fsm_wait_access_remote_f_teid,
		.in_event_mask = 0
			| S(PS_RAB_EV_RX_ACCESS_REMOTE_F_TEID)
			,
		.out_state_mask = 0
			| S(PS_RAB_ST_WAIT_PFCP_MOD_RESP)
			| S(PS_RAB_ST_WAIT_PFCP_DEL_RESP)
			| S(PS_RAB_ST_WAIT_USE_COUNT)
			,
	},
	[PS_RAB_ST_WAIT_PFCP_MOD_RESP] = {
		.name = "WAIT_PFCP_MOD_RESP",
		.onenter = ps_rab_fsm_wait_pfcp_mod_resp_onenter,
		.action = ps_rab_fsm_wait_pfcp_mod_resp,
		.in_event_mask = 0
			| S(PS_RAB_EV_PFCP_MOD_RESP)
			,
		.out_state_mask = 0
			| S(PS_RAB_ST_ESTABLISHED)
			| S(PS_RAB_ST_WAIT_PFCP_DEL_RESP)
			| S(PS_RAB_ST_WAIT_USE_COUNT)
			,
	},
	[PS_RAB_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.onenter = ps_rab_fsm_established_onenter,
		.out_state_mask = 0
			| S(PS_RAB_ST_WAIT_PFCP_DEL_RESP)
			| S(PS_RAB_ST_WAIT_USE_COUNT)
			,
	},
	[PS_RAB_ST_WAIT_PFCP_DEL_RESP] = {
		.name = "WAIT_PFCP_DEL_RESP",
		.onenter = ps_rab_fsm_wait_pfcp_del_resp_onenter,
		.action = ps_rab_fsm_wait_pfcp_del_resp,
		.in_event_mask = 0
			| S(PS_RAB_EV_PFCP_DEL_RESP)
			,
		.out_state_mask = 0
			| S(PS_RAB_ST_WAIT_USE_COUNT)
			,
	},
	[PS_RAB_ST_WAIT_USE_COUNT] = {
		.name = "WAIT_USE_COUNT",
		.onenter = ps_rab_fsm_wait_use_count_onenter,
		.in_event_mask = 0
			| S(PS_RAB_EV_USE_COUNT_ZERO)
			,
	},
};

static struct osmo_fsm ps_rab_fsm = {
	.name = "ps_rab",
	.states = ps_rab_fsm_states,
	.num_states = ARRAY_SIZE(ps_rab_fsm_states),
	.log_subsys = DLPFCP,
	.event_names = ps_rab_fsm_event_names,
	.cleanup = ps_rab_fsm_cleanup,
	.allstate_event_mask = S(PS_RAB_EV_USE_COUNT_ZERO),
	.allstate_action = ps_rab_fsm_allstate_action,
};

static __attribute__((constructor)) void ps_rab_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&ps_rab_fsm) == 0);
}
