#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

#define LOG_MAP(HNB_CTX_MAP, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGHNB((HNB_CTX_MAP) ? (HNB_CTX_MAP)->hnb_ctx : NULL, \
	       SUBSYS, LEVEL, "RUA-%u %s: " FMT, \
	       (HNB_CTX_MAP) ? (HNB_CTX_MAP)->rua_ctx_id : 0, \
	       (HNB_CTX_MAP) ? ((HNB_CTX_MAP)->is_ps ? "PS" : "CS") : "NULL", \
	       ##ARGS)

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
	/* Set to true on SCCP Conn Conf, set to false when an OSMO_SCU_PRIM_N_DISCONNECT has been sent for the SCCP
	 * User SAP conn. Useful to avoid leaking SCCP connections: guarantee that an OSMO_SCU_PRIM_N_DISCONNECT gets
	 * sent, even when RUA fails to gracefully disconnect. */
	bool scu_conn_active;

	enum hnbgw_context_map_state state;

	/* FSM instance for the MGW, handles the async MGCP communication necessary to intercept CS RAB Assignment and
	 * redirect the RTP via the MGW. */
	struct osmo_fsm_inst *mgw_fi;

	/* FSMs handling RANAP RAB assignments for PS, list of struct ps_rab_ass. They handle the async PFCP
	 * communication necessary to intercept PS RAB Assignment and redirect the GTP via the UPF.
	 *
	 * For PS RAB Assignment, each Request gets one ps_rab_ass FSM and each Response gets one ps_rab_ass FSM.
	 * The reason is that theoretically, each such message can contain any number and any combination of RAB IDs,
	 * and Request and Response don't necessarily match the RAB IDs contained. In practice I only ever see a single
	 * RAB matching in Request and Response, but we cannot rely on that to always be true.
	 *
	 * The state of each RAB's PFCP negotiation is kept separately in the list ps_rabs, and as soon as all RABs
	 * appearing in a PS RAB Assignment message have completed their PFCP setup, we can replace the GTP info for the
	 * RAB IDs and forward the RAB Assignment Request to HNB / the RAB Assignment Response to CN.
	 */
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

void context_map_hnb_released(struct hnbgw_context_map *map);

int context_map_init(struct hnb_gw *gw);
