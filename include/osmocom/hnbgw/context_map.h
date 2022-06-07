#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/rua/RUA_CN-DomainIndicator.h>

struct msgb;

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
