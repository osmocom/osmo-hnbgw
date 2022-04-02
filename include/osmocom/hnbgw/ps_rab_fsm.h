#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/use_count.h>
#include <osmocom/pfcp/pfcp_msg.h>

struct addr_teid {
	bool present;
	struct osmo_sockaddr addr;
	uint32_t teid;
};

/* Two of this make up a GTP mapping, one for the Access (HNB) side, one for the Core (CN) side.
 *
 * half_gtp_map     |    half_gtp_map
 * Access        HNBGW+UPF       Core
 * remote     local | local    remote
 *     -->PDR-FAR-->|
 *                  |<--FAR-PDR<--
 *
 * See ps_rab.core, ps_rab.access.
 */
struct half_gtp_map {
	/* GTP endpoint, obtained from incoming RAB Assignment Request/Response.
	 * This is the remote side as seen from the UPF's point of view.
	 * For example, ps_rab.core.remote is the CN GTP that the RAB Assignment Request told us.
	 * ps_rab.access.remote is the HNB GTP that RAB Assignment Response told us. */
	struct addr_teid remote;
	/* UPF GTP endpoint, obtained from PFCP Session Establishment Response. */
	struct addr_teid local;
	/* PFCP Packet Detection Rule id that detects GTP-U packets coming from Core/Access */
	uint16_t pdr_id;
	/* PFCP Forward Action Rule id that forwards GTP-U packets to Access/Core */
	uint32_t far_id;
	/* Whether the RANAP message this RAB's remote address was obtained from encoded the address in x213_nsap */
	bool use_x213_nsap;
};

struct ps_rab {
	struct osmo_fsm_inst *fi;

	/* backpointer */
	struct hnb_gw *hnb_gw;

	/* List entry and backpointer.
	 * If map == NULL, do not call llist_del(&entry): the hnbgw_context_map may deallocate before the PFCP release
	 * is complete, in which case it sets map = NULL. */
	struct llist_head entry;
	struct hnbgw_context_map *map;

	/* RAB-ID used in RANAP RAB AssignmentRequest and Response messages */
	uint8_t rab_id;
	/* Backpointer to the ps_rab_ass_fsm for the RAB Assignment Request from Core that created this RAB. */
	struct osmo_fsm_inst *req_fi;
	/* Backpointer to the ps_rab_ass_fsm for the RAB Assignment Response from Access that confirmed this RAB. */
	struct osmo_fsm_inst *resp_fi;

	/* PFCP session controlling the GTP mapping for this RAB */
	uint64_t cp_seid;
	struct osmo_pfcp_ie_f_seid up_f_seid;
	bool release_requested;

	/* 'local' and 'remote' refer to the GTP information from the UPF's point of view:
	 * HNB                             UPF                 CN
	 * access.remote <---> access.local | core.local <---> core.remote
	 */
	struct half_gtp_map core;
	struct half_gtp_map access;

	struct osmo_use_count use_count;
};

struct ps_rab *ps_rab_start(struct hnbgw_context_map *map, uint8_t rab_id,
			    const struct addr_teid *core_f_teid, bool use_x213_nsap,
			    struct osmo_fsm_inst *req_fi);

struct ps_rab *ps_rab_get(struct hnbgw_context_map *map, uint8_t rab_id);
bool ps_rab_is_established(struct ps_rab *rab);
void ps_rab_release(struct ps_rab *rab);

struct ps_rab_rx_args {
	struct addr_teid f_teid;
	bool use_x213_nsap;
	struct osmo_fsm_inst *notify_fi;
};
int ps_rab_rx_access_remote_f_teid(struct hnbgw_context_map *map, uint8_t rab_id,
				   const struct ps_rab_rx_args *args);

struct ps_rab *ps_rab_find_by_seid(struct hnb_gw *hnb_gw, uint64_t seid, bool is_cp_seid);
void ps_rab_pfcp_set_msg_ctx(struct ps_rab *rab, struct osmo_pfcp_msg *m);
