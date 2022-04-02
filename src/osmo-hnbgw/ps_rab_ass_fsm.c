/* Handle RANAP PS RAB Assignment */
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

#include <asn1c/asn1helpers.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/prim.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/byteswap.h>
#include <arpa/inet.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/tdef.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_common_ran.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/pfcp/pfcp_msg.h>
#include <osmocom/pfcp/pfcp_endpoint.h>
#include <osmocom/pfcp/pfcp_cp_peer.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/ranap_rab_ass.h>
#include <osmocom/hnbgw/ps_rab_fsm.h>

#include <osmocom/hnbgw/hnbgw_rua.h>

#include <osmocom/hnbgw/tdefs.h>

#define PORT_GTP1_U 2152

#define LOG_PS_RAB_ASS(RAB_ASS, LOGL, FMT, ARGS...) \
	LOGPFSML((RAB_ASS) ? (RAB_ASS)->fi : NULL, LOGL, FMT, ##ARGS)

enum ps_rab_ass_fsm_event {
	PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX,
	PS_RAB_ASS_EV_RAB_ASS_RESP,
	PS_RAB_ASS_EV_RAB_ESTABLISHED,
	PS_RAB_ASS_EV_RAB_FAIL,
};

static const struct value_string ps_rab_ass_fsm_event_names[] = {
	OSMO_VALUE_STRING(PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX),
	OSMO_VALUE_STRING(PS_RAB_ASS_EV_RAB_ASS_RESP),
	OSMO_VALUE_STRING(PS_RAB_ASS_EV_RAB_ESTABLISHED),
	OSMO_VALUE_STRING(PS_RAB_ASS_EV_RAB_FAIL),
	{}
};

enum ps_rab_ass_state {
	PS_RAB_ASS_ST_RX_RAB_ASS_MSG,
	PS_RAB_ASS_ST_WAIT_LOCAL_F_TEIDS,
	PS_RAB_ASS_ST_RX_RAB_ASS_RESP,
	PS_RAB_ASS_ST_WAIT_RABS_ESTABLISHED,
};

/* Represents one RANAP PS RAB Assignment Request and Response dialog.
 * There may be any number of PS RAB Assignment Requests, each with any number of RABs being established. We need to
 * manage these asynchronously and flexibly:
 * - RABs may be assigned in a group and released one by one, or vice versa;
 * - we can only forward a RAB Assignment Request / Response when all RABs appearing in it have been set up by the UPF.
 *
 * This structure manages the RAB Assignment procedures, and the currently set up RABs:
 *
 * - hnbgw_context_map
 *   - .ps_rab_ass: list of PS RAB Assignment procedures
 *     - ps_rab_ass_fsm: one RANAP PS RAB Assignment procedure
 *     - ...
 *   - .ps_rabs: list of individual PS RABs
 *     - ps_rab_fsm: one GTP mapping with PFCP session to the UPF, for a single RAB
 *     - ...
 *
 * This ps_rab_ass_fsm lives from a received RAB Assignment Request up to the sent RAB Assignment Response; it
 * deallocates when all the RABs have been set up.
 *
 * The ps_rab_ass_fsm sets up ps_rab_fsm instances, which live longer: up until a RAB or conn release is performed.
 */
struct ps_rab_ass {
	struct llist_head entry;

	struct osmo_fsm_inst *fi;

	/* backpointer */
	struct hnbgw_context_map *map;

	ranap_message *ranap_rab_ass_req_message;

	ranap_message *ranap_rab_ass_resp_message;
	struct osmo_prim_hdr *ranap_rab_ass_resp_oph;

	/* A RAB Assignment may contain more than one RAB. Each RAB sets up a distinct ps_rab_fsm (aka PFCP session) and
	 * reports back about local F-TEIDs assigned by the UPF. This gives the nr of RAB events we expect from
	 * ps_rab_fsms, without iterating the RAB Assignment message every time (minor optimisation). */
	int rabs_count;
	int rabs_done_count;
};

struct osmo_tdef_state_timeout ps_rab_ass_fsm_timeouts[32] = {
	/* PS_RAB_ASS_ST_WAIT_LOCAL_F_TEIDS is terminated by PFCP timeouts via ps_rab_fsm */
	/* PS_RAB_ASS_ST_WAIT_RABS_ESTABLISHED is terminated by PFCP timeouts via ps_rab_fsm */
};

#define ps_rab_ass_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, ps_rab_ass_fsm_timeouts, ps_T_defs, -1)

static struct osmo_fsm ps_rab_ass_fsm;

static struct ps_rab_ass *ps_rab_ass_alloc(struct hnbgw_context_map *map)
{
	struct ps_rab_ass *rab_ass;
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&ps_rab_ass_fsm, map, map, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	osmo_fsm_inst_update_id_f_sanitize(fi, '-', "%s-RUA-%u", hnb_context_name(map->hnb_ctx), map->rua_ctx_id);

	rab_ass = talloc(fi, struct ps_rab_ass);
	OSMO_ASSERT(rab_ass);
	*rab_ass = (struct ps_rab_ass){
		.fi = fi,
		.map = map,
	};
	fi->priv = rab_ass;

	llist_add_tail(&rab_ass->entry, &map->ps_rab_ass);
	return rab_ass;
}

static void ps_rab_ass_failure(struct ps_rab_ass *rab_ass)
{
	LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "PS RAB Assignment failed\n");

	/* TODO: send unsuccessful RAB Assignment Response to Core? */
	/* TODO: remove RAB from Access? */

	osmo_fsm_inst_term(rab_ass->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

/* Add a single RAB from a RANAP PS RAB Assignment Request's list of RABs */
static int ps_rab_setup_core_remote(struct ps_rab_ass *rab_ass, RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair)
{
	struct hnbgw_context_map *map = rab_ass->map;
	uint8_t rab_id;
	struct addr_teid f_teid = {};
	bool use_x213_nsap;
	struct ps_rab *rab;

	RANAP_RAB_SetupOrModifyItemFirst_t first;
	RANAP_TransportLayerAddress_t *transp_layer_addr;
	RANAP_TransportLayerInformation_t *tli;
	int rc;

	if (protocol_ie_field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem)
		return -1;

	/* Extract information about the GTP Core side */
	rc = ranap_decode_rab_setupormodifyitemfirst(&first,
						     &protocol_ie_field_pair->firstValue);
	if (rc < 0)
		goto error_exit;

	rab_id = first.rAB_ID.buf[0];

	/* Decode GTP endpoint IP-Address */
	tli = first.transportLayerInformation;
	transp_layer_addr = &tli->transportLayerAddress;
	rc = ranap_transp_layer_addr_decode2(&f_teid.addr, &use_x213_nsap, transp_layer_addr);
	if (rc < 0)
		goto error_exit;
	osmo_sockaddr_set_port(&f_teid.addr.u.sa, PORT_GTP1_U);

	/* Decode the GTP remote TEID */
	if (tli->iuTransportAssociation.present != RANAP_IuTransportAssociation_PR_gTP_TEI) {
		rc = -1;
		goto error_exit;
	}
	f_teid.teid = osmo_load32be(tli->iuTransportAssociation.choice.gTP_TEI.buf);
	f_teid.present = true;

	rab_ass->rabs_count++;
	rab = ps_rab_start(map, rab_id, &f_teid, use_x213_nsap, rab_ass->fi);
	if (!rab) {
		rc = -1;
		goto error_exit;
	}
	rc = 0;

error_exit:
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, &first);
	return rc;
}

int hnbgw_gtpmap_rx_rab_ass_req(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message)
{
	RANAP_RAB_AssignmentRequestIEs_t *ies = &message->msg.raB_AssignmentRequestIEs;
	int i;

	struct hnb_gw *hnb_gw = map->hnb_ctx->gw;
	struct ps_rab_ass *rab_ass;
	struct osmo_fsm_inst *fi;

	rab_ass = ps_rab_ass_alloc(map);
	rab_ass->ranap_rab_ass_req_message = message;
	/* Now rab_ass owns message and will clean it up */

	if (!osmo_pfcp_cp_peer_is_associated(hnb_gw->pfcp.cp_peer)) {
		LOG_MAP(map, DLPFCP, LOGL_ERROR, "PFCP is not associated, cannot set up GTP mapping\n");
		goto no_rab;
	}

	/* Make sure we indeed deal with a setup-or-modify list */
	if (!(ies->presenceMask & RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_SETUPORMODIFYLIST_PRESENT)) {
		LOG_MAP(map, DLPFCP, LOGL_ERROR, "RANAP PS RAB AssignmentRequest lacks setup-or-modify list\n");
		goto no_rab;
	}

	/* Multiple RABs may be set up, assemble in list rab_ass->ps_rabs. */
	for (i = 0; i < ies->raB_SetupOrModifyList.list.count; i++) {
		RANAP_ProtocolIE_ContainerPair_t *protocol_ie_container_pair;
		RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;

		protocol_ie_container_pair = ies->raB_SetupOrModifyList.list.array[i];
		protocol_ie_field_pair = protocol_ie_container_pair->list.array[0];
		if (!protocol_ie_field_pair)
			goto no_rab;
		if (protocol_ie_field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem)
			goto no_rab;

		if (ps_rab_setup_core_remote(rab_ass, protocol_ie_field_pair))
			goto no_rab;
	}

	/* Got all RABs' state and their Core side GTP info in map->ps_rabs. For each, a ps_rab_fsm has been started and
	 * each will call back with PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX or PS_RAB_ASS_EV_RAB_FAIL. */
	fi = rab_ass->fi;
	return ps_rab_ass_fsm_state_chg(PS_RAB_ASS_ST_WAIT_LOCAL_F_TEIDS);

no_rab:
	ps_rab_ass_failure(rab_ass);
	return -1;
}

static void ps_rab_ass_req_check_local_f_teids(struct ps_rab_ass *rab_ass);

static void ps_rab_ass_fsm_wait_local_f_teids(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ps_rab_ass *rab_ass = fi->priv;

	switch (event) {
	case PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX:
		rab_ass->rabs_done_count++;
		if (rab_ass->rabs_done_count < rab_ass->rabs_count) {
			/* some RABs are still pending, postpone going through the message until all are done. */
			return;
		}
		ps_rab_ass_req_check_local_f_teids(rab_ass);
		return;

	case PS_RAB_ASS_EV_RAB_FAIL:
		ps_rab_ass_failure(rab_ass);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

/* See whether all information is in so that we can forward the modified RAB Assignment Request to RUA. */
static void ps_rab_ass_req_check_local_f_teids(struct ps_rab_ass *rab_ass)
{
	struct ps_rab *rab;
	RANAP_RAB_AssignmentRequestIEs_t *ies = &rab_ass->ranap_rab_ass_req_message->msg.raB_AssignmentRequestIEs;
	int i;
	struct msgb *msg;

	/* Go through all RABs in the RAB Assignment Request message and replace with the F-TEID that the UPF assigned,
	 * verifying that we indeed have local F-TEIDs for all RABs contained in this message. */
	for (i = 0; i < ies->raB_SetupOrModifyList.list.count; i++) {
		RANAP_ProtocolIE_ContainerPair_t *protocol_ie_container_pair;
		RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;
		RANAP_RAB_SetupOrModifyItemFirst_t first;
		uint8_t rab_id;
		int rc;

		protocol_ie_container_pair = ies->raB_SetupOrModifyList.list.array[i];
		protocol_ie_field_pair = protocol_ie_container_pair->list.array[0];
		if (!protocol_ie_field_pair)
			continue;
		if (protocol_ie_field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem)
			continue;

		/* Get to the information about the GTP Core side */
		rc = ranap_decode_rab_setupormodifyitemfirst(&first,
							     &protocol_ie_field_pair->firstValue);
		if (rc < 0)
			goto continue_cleanloop;

		rab_id = first.rAB_ID.buf[0];

		/* Find struct ps_rab for this rab_id */
		rab = ps_rab_get(rab_ass->map, rab_id);
		if (!rab || !rab->access.local.present) {
			/* Not ready to send on the RAB Assignment Request to RUA, a local F-TEID is missing. */
			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, &first);
			return;
		}

		/* Replace GTP endpoint */
		ASN_STRUCT_FREE(asn_DEF_RANAP_TransportLayerInformation, first.transportLayerInformation);
		first.transportLayerInformation = ranap_new_transp_info_gtp(&rab->access.local.addr,
									    rab->access.local.teid,
									    rab->core.use_x213_nsap);

		/* Reencode to update transport-layer-information */
		rc = ANY_fromType_aper(&protocol_ie_field_pair->firstValue, &asn_DEF_RANAP_RAB_SetupOrModifyItemFirst,
				       &first);
		if (rc < 0)
			LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Re-encoding RANAP PS RAB Assignment Request failed\n");
continue_cleanloop:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, &first);
	}

	/* Send the modified RAB Assignment Request to the hNodeB, wait for the RAB Assignment Response */
	msg = ranap_rab_ass_req_encode(ies);
	if (!msg) {
		LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Re-encoding RANAP PS RAB Assignment Request failed\n");
		ps_rab_ass_failure(rab_ass);
		return;
	}
	rua_tx_dt(rab_ass->map->hnb_ctx, rab_ass->map->is_ps, rab_ass->map->rua_ctx_id, msg->data, msg->len);
	/* The request message has been forwarded. The response will be handled by a new FSM instance.
	 * We are done. */
	osmo_fsm_inst_term(rab_ass->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

/* Add a single RAB from a RANAP/RUA RAB Assignment Response's list of RABs */
static int ps_rab_setup_access_remote(struct ps_rab_ass *rab_ass,
				      RANAP_RAB_SetupOrModifiedItem_t *rab_item)
{
	struct hnbgw_context_map *map = rab_ass->map;
	uint8_t rab_id;
	int rc;
	struct ps_rab_rx_args args = {};

	rab_id = rab_item->rAB_ID.buf[0];

	rc = ranap_transp_layer_addr_decode2(&args.f_teid.addr, &args.use_x213_nsap, rab_item->transportLayerAddress);
	if (rc < 0)
		return rc;

	/* Decode the GTP remote TEID */
	if (!rab_item->iuTransportAssociation
	    || rab_item->iuTransportAssociation->present != RANAP_IuTransportAssociation_PR_gTP_TEI)
		return -1;
	args.f_teid.teid = osmo_load32be(rab_item->iuTransportAssociation->choice.gTP_TEI.buf);
	args.f_teid.present = true;

	args.notify_fi = rab_ass->fi;

	return ps_rab_rx_access_remote_f_teid(map, rab_id, &args);
}

int hnbgw_gtpmap_rx_rab_ass_resp(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message)
{
	/* hNodeB responds with its own F-TEIDs. Need to tell the UPF about those to complete the GTP mapping.
	 * 1. here, extract the F-TEIDs (one per RAB),
	 *    trigger each ps_rab_fsm to do a PFCP Session Modification.
	 * 2. after all ps_rab_fsms responded with success, insert our Core side local F-TEIDs and send on the RAB
	 *    Assignment Response to IuPS. (We already know the local F-TEIDs assigned by the UPF and could send on the
	 *    RAB Assignment Response immediately, but rather wait for the PFCP mod req to succeed first.)
	 *
	 * To wait for all the RABs in this response message to complete, create a *separate* rab_ass_fsm instance from
	 * the one created for the earlier RAB Assignment Request message. The reason is that technically we cannot
	 * assume that the request and the response have exactly matching RAB IDs contained in them.
	 *
	 * In the vast majority of practical cases, there will be only one RAB Assignment Request message pending, but
	 * for interop, by treating each RAB on its own and by treating request and response message separately from
	 * each other, we are able to handle mismatching RAB IDs in request and response messages.
	 */

	int rc;
	int i;
	struct ps_rab_ass *rab_ass;
	struct osmo_fsm_inst *fi;
	RANAP_RAB_AssignmentResponseIEs_t *ies;
	struct hnb_gw *hnb_gw = map->hnb_ctx->gw;

	/* Make sure we indeed deal with a setup-or-modify list */
	ies = &message->msg.raB_AssignmentResponseIEs;
	if (!(ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT)) {
		LOG_MAP(map, DRUA, LOGL_ERROR, "RANAP PS RAB AssignmentResponse lacks setup-or-modify list\n");
		return -1;
	}

	rab_ass = ps_rab_ass_alloc(map);
	rab_ass->ranap_rab_ass_resp_message = message;
	rab_ass->ranap_rab_ass_resp_oph = oph;
	/* Now rab_ass owns message and will clean it up */

	if (!osmo_pfcp_cp_peer_is_associated(hnb_gw->pfcp.cp_peer)) {
		LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "PFCP is not associated, cannot set up GTP mapping\n");
		ps_rab_ass_failure(rab_ass);
		return -1;
	}

	LOG_PS_RAB_ASS(rab_ass, LOGL_NOTICE, "PS RAB-AssignmentResponse received, updating RABs\n");

	/* Multiple RABs may be set up, bump matching FSMs in list rab_ass->ps_rabs. */
	for (i = 0; i < ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.count; i++) {
		RANAP_IE_t *list_ie;
		RANAP_RAB_SetupOrModifiedItemIEs_t item_ies;

		list_ie = ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.array[i];
		if (!list_ie)
			continue;

		rc = ranap_decode_rab_setupormodifieditemies_fromlist(&item_ies,
								      &list_ie->value);
		if (rc < 0) {
			LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Failed to decode PS RAB-AssignmentResponse"
				       " SetupOrModifiedItemIEs with list index %d\n", i);
			goto continue_cleanloop;
		}

		if (ps_rab_setup_access_remote(rab_ass, &item_ies.raB_SetupOrModifiedItem))
			LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Failed to apply PS RAB-AssignmentResponse"
				       " SetupOrModifiedItemIEs with list index %d\n", i);
		rab_ass->rabs_count++;

continue_cleanloop:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, &item_ies);
	}

	/* Got all RABs' state and updated their Access side GTP info in map->ps_rabs. For each RAB ID, the matching
	 * ps_rab_fsm has been instructed to tell the UPF about the Access Remote GTP F-TEID. Each will call back with
	 * PS_RAB_ASS_EV_RAB_ESTABLISHED or PS_RAB_ASS_EV_RAB_FAIL. */
	fi = rab_ass->fi;
	return ps_rab_ass_fsm_state_chg(PS_RAB_ASS_ST_WAIT_RABS_ESTABLISHED);
}

static void ps_rab_ass_resp_send_if_ready(struct ps_rab_ass *rab_ass);

static void ps_rab_ass_fsm_wait_rabs_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ps_rab_ass *rab_ass = fi->priv;

	switch (event) {
	case PS_RAB_ASS_EV_RAB_ESTABLISHED:
		rab_ass->rabs_done_count++;
		if (rab_ass->rabs_done_count < rab_ass->rabs_count) {
			/* some RABs are still pending, postpone going through the message until all are done. */
			return;
		}
		/* All RABs have succeeded, ready to forward */
		ps_rab_ass_resp_send_if_ready(rab_ass);
		return;

	case PS_RAB_ASS_EV_RAB_FAIL:
		ps_rab_ass_failure(rab_ass);
		return;
	default:
		OSMO_ASSERT(false);
	}
}

/* See whether all RABs are done establishing, and replace GTP info in the RAB Assignment Response message, so that we
 * can forward the modified RAB Assignment Request to M3UA. */
static void ps_rab_ass_resp_send_if_ready(struct ps_rab_ass *rab_ass)
{
	int i;
	int rc;
	struct hnbgw_cnlink *cn = rab_ass->map->cn_link;
	RANAP_RAB_AssignmentResponseIEs_t *ies = &rab_ass->ranap_rab_ass_resp_message->msg.raB_AssignmentResponseIEs;

	/* Go through all RABs in the RAB Assignment Response message and replace with the F-TEID that the UPF assigned,
	 * verifying that instructing the UPF has succeeded. */
	for (i = 0; i < ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.count; i++) {
		RANAP_IE_t *list_ie;
		RANAP_RAB_SetupOrModifiedItemIEs_t item_ies;
		RANAP_RAB_SetupOrModifiedItem_t *rab_item;
		int rc;
		uint8_t rab_id;
		uint32_t teid_be;
		struct ps_rab *rab;

		list_ie = ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.array[i];
		if (!list_ie)
			continue;

		rc = ranap_decode_rab_setupormodifieditemies_fromlist(&item_ies,
								      &list_ie->value);
		if (rc < 0) {
			LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Failed to decode PS RAB-AssignmentResponse"
				       " SetupOrModifiedItemIEs with list index %d\n", i);
			goto continue_cleanloop;
		}

		rab_item = &item_ies.raB_SetupOrModifiedItem;
		rab_id = rab_item->rAB_ID.buf[0];

		/* Find struct ps_rab for this rab_id */
		rab = ps_rab_get(rab_ass->map, rab_id);
		if (!ps_rab_is_established(rab)) {
			/* Not ready to send on the RAB Assignment Response to M3UA, still waiting for it to be
			 * established */
			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, &item_ies);
			return;
		}

		/* Replace GTP endpoint */
		if (ranap_new_transp_layer_addr(rab_item->transportLayerAddress, &rab->core.local.addr,
						rab->access.use_x213_nsap) < 0) {
			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, &item_ies);
			LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Re-encoding RANAP PS RAB-AssignmentResponse failed\n");
			ps_rab_ass_failure(rab_ass);
			return;
		}

		LOG_PS_RAB_ASS(rab_ass, LOGL_DEBUG, "Re-encoding RANAP PS RAB-AssignmentResponse: RAB %u:"
			       " RUA sent F-TEID %s-0x%x; replacing with %s-0x%x\n",
			       rab_id,
			       osmo_sockaddr_to_str_c(OTC_SELECT, &rab->access.remote.addr), rab->access.remote.teid,
			       osmo_sockaddr_to_str_c(OTC_SELECT, &rab->core.local.addr), rab->core.local.teid);

		teid_be = htonl(rab->core.local.teid);
		rab_item->iuTransportAssociation->present = RANAP_IuTransportAssociation_PR_gTP_TEI;
		OCTET_STRING_fromBuf(&rab_item->iuTransportAssociation->choice.gTP_TEI,
				     (const char *)&teid_be, sizeof(teid_be));

		/* Reencode this list item in the RANAP message */
		rc = ANY_fromType_aper(&list_ie->value, &asn_DEF_RANAP_RAB_SetupOrModifiedItem, rab_item);
		if (rc < 0) {
			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, &item_ies);
			LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Re-encoding RANAP PS RAB-AssignmentResponse failed\n");
			ps_rab_ass_failure(rab_ass);
			return;
		}

continue_cleanloop:
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, &item_ies);
	}

	/* Replaced all the GTP info, re-encode the message. Since we are replacing data 1:1, taking care to use the
	 * same IP address encoding, the resulting message size must be identical to the original message size. */
	rc = ranap_rab_ass_resp_encode(msgb_l2(rab_ass->ranap_rab_ass_resp_oph->msg),
				       msgb_l2len(rab_ass->ranap_rab_ass_resp_oph->msg), ies);
	if (rc < 0) {
		LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Re-encoding RANAP PS RAB-AssignmentResponse failed\n");
		ps_rab_ass_failure(rab_ass);
		return;
	}

	LOG_PS_RAB_ASS(rab_ass, LOGL_NOTICE, "Sending RANAP PS RAB-AssignmentResponse with mapped GTP info\n");
	rc = osmo_sccp_user_sap_down(cn->sccp_user, rab_ass->ranap_rab_ass_resp_oph);
	rab_ass->ranap_rab_ass_resp_oph = NULL;
	if (rc < 0) {
		LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Sending RANAP PS RAB-AssignmentResponse failed\n");
		ps_rab_ass_failure(rab_ass);
	}

	/* The request message has been forwarded. We are done. */
	osmo_fsm_inst_term(rab_ass->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void ps_rab_ass_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ps_rab_ass *rab_ass = fi->priv;
	struct osmo_scu_prim *scu_prim;
	struct msgb *scu_msg;
	struct ps_rab *rab;

	if (rab_ass->ranap_rab_ass_req_message) {
		ranap_ran_rx_co_free(rab_ass->ranap_rab_ass_req_message);
		talloc_free(rab_ass->ranap_rab_ass_req_message);
		rab_ass->ranap_rab_ass_req_message = NULL;
	}

	if (rab_ass->ranap_rab_ass_resp_message) {
		ranap_cn_rx_co_free(rab_ass->ranap_rab_ass_resp_message);
		talloc_free(rab_ass->ranap_rab_ass_resp_message);
		rab_ass->ranap_rab_ass_resp_message = NULL;
	}

	if (rab_ass->ranap_rab_ass_resp_oph) {
		scu_prim = (struct osmo_scu_prim *)rab_ass->ranap_rab_ass_resp_oph;
		scu_msg = scu_prim->oph.msg;
		msgb_free(scu_msg);
		rab_ass->ranap_rab_ass_resp_oph = NULL;
	}

	llist_for_each_entry(rab, &rab_ass->map->ps_rabs, entry) {
		if (rab->req_fi == fi)
			rab->req_fi = NULL;
		if (rab->resp_fi == fi)
			rab->resp_fi = NULL;
	}

	llist_del(&rab_ass->entry);
}

void hnbgw_gtpmap_release(struct hnbgw_context_map *map)
{
	struct ps_rab_ass *rab_ass, *next;
	struct ps_rab *rab, *next2;
	llist_for_each_entry_safe(rab, next2, &map->ps_rabs, entry) {
		ps_rab_release(rab);
	}
	llist_for_each_entry_safe(rab_ass, next, &map->ps_rab_ass, entry) {
		osmo_fsm_inst_term(rab_ass->fi, OSMO_FSM_TERM_REGULAR, NULL);
	}
}

#define S(x) (1 << (x))

static const struct osmo_fsm_state ps_rab_ass_fsm_states[] = {
	[PS_RAB_ASS_ST_RX_RAB_ASS_MSG] = {
		.name = "RX_RAB_ASS_MSG",
		.out_state_mask = 0
			| S(PS_RAB_ASS_ST_WAIT_LOCAL_F_TEIDS)
			| S(PS_RAB_ASS_ST_WAIT_RABS_ESTABLISHED)
			,
	},
	[PS_RAB_ASS_ST_WAIT_LOCAL_F_TEIDS] = {
		.name = "WAIT_LOCAL_F_TEIDS",
		.action = ps_rab_ass_fsm_wait_local_f_teids,
		.in_event_mask = 0
			| S(PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX)
			| S(PS_RAB_ASS_EV_RAB_FAIL)
			,
	},
	[PS_RAB_ASS_ST_WAIT_RABS_ESTABLISHED] = {
		.name = "WAIT_RABS_ESTABLISHED",
		.action = ps_rab_ass_fsm_wait_rabs_established,
		.in_event_mask = 0
			| S(PS_RAB_ASS_EV_RAB_ESTABLISHED)
			| S(PS_RAB_ASS_EV_RAB_FAIL)
			,
	},
};

int ps_rab_ass_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ps_rab_ass *rab_ass = fi->priv;
	LOG_PS_RAB_ASS(rab_ass, LOGL_ERROR, "Timeout of " OSMO_T_FMT "\n", OSMO_T_FMT_ARGS(fi->T));
	/* terminate */
	return 1;
}

static struct osmo_fsm ps_rab_ass_fsm = {
	.name = "ps_rab_ass",
	.states = ps_rab_ass_fsm_states,
	.num_states = ARRAY_SIZE(ps_rab_ass_fsm_states),
	.log_subsys = DRANAP,
	.event_names = ps_rab_ass_fsm_event_names,
	.cleanup = ps_rab_ass_fsm_cleanup,
	.timer_cb = ps_rab_ass_fsm_timer_cb,
};

static __attribute__((constructor)) void ps_rab_ass_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&ps_rab_ass_fsm) == 0);
}
