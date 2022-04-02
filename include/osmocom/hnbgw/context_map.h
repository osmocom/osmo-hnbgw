#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/rua/RUA_CN-DomainIndicator.h>

struct msgb;

#define LOG_MAP(HNB_CTX_MAP, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGHNB((HNB_CTX_MAP) ? (HNB_CTX_MAP)->hnb_ctx : NULL, \
	       SUBSYS, LEVEL, "RUA-%u %s: " FMT, \
	       (HNB_CTX_MAP) ? (HNB_CTX_MAP)->rua_ctx_id : 0, \
	       (HNB_CTX_MAP) ? ((HNB_CTX_MAP)->is_ps ? "PS" : "CS") : "NULL", \
	       ##ARGS) \

enum hnbgw_context_map_state {
	MAP_S_NULL,
	MAP_S_ACTIVE,		/* currently active map */
	MAP_S_RESERVED1,	/* just disconnected, still resrved */
	MAP_S_RESERVED2,	/* still reserved */
	MAP_S_NUM_STATES	/* Number of states, keep this at the end */
};

extern const struct value_string hnbgw_context_map_state_names[];
static inline const char *hnbgw_context_map_state_name(enum hnbgw_context_map_state val)
{ return get_value_string(hnbgw_context_map_state_names, val); }

struct hnb_context;
struct hnbgw_cnlink;

struct hnbgw_context_map {
	/* entry in the per-CN list of mappings */
	struct llist_head cn_list;
	/* entry in the per-HNB list of mappings */
	struct llist_head hnb_list;
	/* pointer to HNB */
	struct hnb_context *hnb_ctx;
	/* pointer to CN */
	struct hnbgw_cnlink *cn_link;
	/* RUA contxt ID */
	uint32_t rua_ctx_id;
	/* False for CS, true for PS */
	bool is_ps;
	/* SCCP User SAP connection ID */
	uint32_t scu_conn_id;
	/* Pending data to be sent: when we send an "empty" SCCP CR first, the initial RANAP message will be sent in a
	 * separate DT once the CR is confirmed. This caches the initial RANAP message. */
	struct msgb *cached_msg;

	enum hnbgw_context_map_state state;

	/* FSM instance for the MGW */
	struct osmo_fsm_inst *mgw_fi;

	/* FSMs handling RANAP RAB assignments for PS. list of struct ps_rab_ass. For PS RAB Assignment, each Request
	 * and gets one ps_rab_ass FSM and each Response gets one ps_rab_ass FSM. The reason is that theoretically, each
	 * such message can contain any number and any combination of RAB IDs, and Request and Response don't
	 * necessarily match the RAB IDs contained. In practice I only ever see a single RAB matching in Request and
	 * Response, but we cannot rely on that to always be true. The state of each RAB's PFCP negotiation is kept
	 * separately in the list hnbgw_context_map.ps_rabs, and as soon as all RABs appearing in a PS RAB Assignment
	 * message have completed their PFCP setup, we can replace the GTP info for the RAB IDs and forward the RAB
	 * Assignment Request to HNB / the RAB Assignment Response to CN. */
	struct llist_head ps_rab_ass;

	/* All PS RABs and their GTP tunnel mappings. list of struct ps_rab. Each ps_rab FSM handles the PFCP
	 * communication for one particular RAB ID. */
	struct llist_head ps_rabs;
};


struct hnbgw_context_map *
context_map_alloc_by_hnb(struct hnb_context *hnb, uint32_t rua_ctx_id,
			 bool is_ps,
			 struct hnbgw_cnlink *cn_if_new);

struct hnbgw_context_map *
context_map_by_cn(struct hnbgw_cnlink *cn, uint32_t scu_conn_id);

int context_map_send_cached_msg(struct hnbgw_context_map *map);

void context_map_deactivate(struct hnbgw_context_map *map);

int context_map_init(struct hnb_gw *gw);
