#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/gsm/gsm48.h>

#define LOG_MAP(HNB_CTX_MAP, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGHNB((HNB_CTX_MAP) ? (HNB_CTX_MAP)->hnb_ctx : NULL, \
	       SUBSYS, LEVEL, "RUA-%u %s MI=%s%s%s: " FMT, \
	       (HNB_CTX_MAP) ? (HNB_CTX_MAP)->rua_ctx_id : 0, \
	       (HNB_CTX_MAP) ? \
			((HNB_CTX_MAP)->cnlink ? (HNB_CTX_MAP)->cnlink->name \
			  : ((HNB_CTX_MAP)->is_ps ? "PS" : "CS")) \
			: "NULL", \
	       (HNB_CTX_MAP) ? osmo_mobile_identity_to_str_c(OTC_SELECT, &(HNB_CTX_MAP)->l3.mi) : "null", \
	       (HNB_CTX_MAP) && (HNB_CTX_MAP)->l3.from_other_plmn ? " (from other PLMN)" : "", \
	       (HNB_CTX_MAP) && (HNB_CTX_MAP)->l3.is_emerg ? " EMERGENCY" : "", \
	       ##ARGS)

/* All these events' data argument may either be NULL, or point to a RANAP msgb.
 * - The msgb shall be in the OTC_SELECT talloc pool, so that they will be deallocated automatically. Some events
 *   processing will store the msgb for later, in which case it will take over ownership of the msgb by means of
 *   talloc_steal().
 * - For events that may send a RANAP message towards CN via SCCP, the msgb shall have reserved headroom to fit a struct
 *   osmo_scu_prim. These are: MAP_RUA_EV_RX_*.
 * - The RANAP message shall be at msgb_l2().
 */
enum map_rua_fsm_event {
	/* Receiving a RUA Connect from HNB. */
	MAP_RUA_EV_RX_CONNECT,
	/* Receiving some data from HNB via RUA, to forward via SCCP to CN. */
	MAP_RUA_EV_RX_DIRECT_TRANSFER,
	/* Receiving a RUA Disconnect from HNB. */
	MAP_RUA_EV_RX_DISCONNECT,
	/* SCCP has received some data from CN to forward via RUA to HNB. */
	MAP_RUA_EV_TX_DIRECT_TRANSFER,
	/* The CN side is disconnected (e.g. received an SCCP Released), that means we are going gracefully disconnect
	 * RUA, too. */
	MAP_RUA_EV_CN_DISC,
	/* All of a sudden, there is no RUA link. For example, HNB vanished / restarted, or SCTP SHUTDOWN on the RUA
	 * link. Skip RUA disconnect. */
	MAP_RUA_EV_HNB_LINK_LOST,
};

/* All these events' data argument is identical to enum map_rua_fsm_event, with this specialisation:
 * - The events that may send a RANAP message towards CN via SCCP and hence require a headroom for an osmo_scu_prim are:
 *   MAP_SCCP_EV_TX_DATA_REQUEST, MAP_SCCP_EV_RAN_DISC.
 */
enum map_sccp_fsm_event {
	/* Receiving an SCCP CC from CN. */
	MAP_SCCP_EV_RX_CONNECTION_CONFIRM,
	/* Receiving some data from CN via SCCP, to forward via RUA to HNB. */
	MAP_SCCP_EV_RX_DATA_INDICATION,
	/* RUA has received some data from HNB to forward via SCCP to CN. */
	MAP_SCCP_EV_TX_DATA_REQUEST,
	/* The RAN side received a Disconnect, that means we are going to expect SCCP to disconnect too.
	 * CN should have received an Iu-ReleaseComplete with or before this, give CN a chance to send an SCCP RLSD;
	 * after a timeout we will send a non-standard RLSD to the CN instead. */
	MAP_SCCP_EV_RAN_DISC,
	/* The RAN released ungracefully. We will directly disconnect the SCCP connection, too. */
	MAP_SCCP_EV_RAN_LINK_LOST,
	/* Receiving an SCCP RLSD from CN, or libosmo-sigtran tells us about SCCP connection timeout. All done. */
	MAP_SCCP_EV_RX_RELEASED,
	/* The human admin asks to drop the current SCCP connection, by telnet VTY 'apply sccp' in presence of SCCP
	 * config changes. */
	MAP_SCCP_EV_USER_ABORT,
};

/* For context_map_get_state(), to combine the RUA and SCCP states, for VTY reporting only. */
enum hnbgw_context_map_state {
	MAP_S_CONNECTING,       /* not active yet; effectively waiting for SCCP CC */
	MAP_S_ACTIVE,           /* both RUA and SCCP are connected */
	MAP_S_DISCONNECTING,    /* not active anymore; effectively waiting for SCCP RLSD */
	MAP_S_NUM_STATES        /* Number of states, keep this at the end */
};

extern const struct value_string hnbgw_context_map_state_names[];
static inline const char *hnbgw_context_map_state_name(enum hnbgw_context_map_state val)
{ return get_value_string(hnbgw_context_map_state_names, val); }

struct hnb_context;
struct hnbgw_cnlink;

struct hnbgw_l3_peek {
	/* L3 message type, like GSM48_PDISC_MM+GSM48_MT_MM_LOC_UPD_REQUEST... / GSM48_PDISC_MM_GPRS+GSM48_MT_GMM_ATTACH_REQ... */
	uint8_t gsm48_pdisc;
	uint8_t gsm48_msg_type;
	/* The Mobile Identity from MM and GMM messages */
	struct osmo_mobile_identity mi;
	/* On PS, the "TMSI Based NRI Container", 10 bit integer, or -1 if not present.
	 * This is only for PS -- for CS, the NRI is in the TMSI obtained from 'mi' above. */
	int gmm_nri_container;
	/* For a CM Service Request for voice call, true if this is for an Emergency Call, false otherwise. */
	bool is_emerg;
	/* True if the NAS PDU indicates that the UE was previously attached to a different PLMN than the local PLMN. */
	bool from_other_plmn;
};

struct hnbgw_context_map {
	/* entry in the per-CN list of mappings */
	struct llist_head hnbgw_cnlink_entry;
	/* entry in the per-HNB list of mappings. If hnb_ctx == NULL, then this llist entry has been llist_del()eted and
	 * must not be used. */
	struct llist_head hnb_list;

	/* entry in the per-SCCP-conn-id hashtable */
	struct hlist_node hnbgw_sccp_user_entry;

	/* Pointer to HNB for this map, to transceive RUA. If the HNB has disconnected without releasing the RUA
	 * context, this is NULL. */
	struct hnb_context *hnb_ctx;
	/* RUA context ID used in RUA messages to/from the hnb_gw. */
	uint32_t rua_ctx_id;
	/* FSM handling the RUA state for rua_ctx_id. */
	struct osmo_fsm_inst *rua_fi;

	/* Pointer to CN, to transceive SCCP. */
	struct hnbgw_cnlink *cnlink;
	/* SCCP User SAP connection ID used in SCCP messages to/from the cn_link. */
	uint32_t scu_conn_id;
	/* FSM handling the SCCP state for scu_conn_id. */
	struct osmo_fsm_inst *sccp_fi;

	/* False for CS, true for PS */
	bool is_ps;

	/* Information extracted from RUA Connect's RANAP InitialUE message */
	struct hnbgw_l3_peek l3;

	/* When an FSM is asked to disconnect but must still wait for a response, it may set this flag, to continue to
	 * disconnect once the response is in. In particular, when SCCP is asked to disconnect after an SCCP Connection
	 * Request was already sent and while waiting for a Connection Confirmed, we should still wait for the SCCP CC
	 * and immediately release it after that, to not leak the connection. */
	bool please_disconnect;

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

	/* Flag to prevent calling context_map_free() from cleanup code paths triggered by context_map_free() itself. */
	bool deallocating;
};

enum hnbgw_context_map_state context_map_get_state(struct hnbgw_context_map *map);
enum hnbgw_context_map_state map_rua_get_state(struct hnbgw_context_map *map);
enum hnbgw_context_map_state map_sccp_get_state(struct hnbgw_context_map *map);

struct hnbgw_context_map *context_map_find_by_rua_ctx_id(struct hnb_context *hnb, uint32_t rua_ctx_id, bool is_ps);
struct hnbgw_context_map *context_map_alloc(struct hnb_context *hnb, uint32_t rua_ctx_id, bool is_ps);
int context_map_set_cnlink(struct hnbgw_context_map *map, struct hnbgw_cnlink *cnlink_selected);

void map_rua_fsm_alloc(struct hnbgw_context_map *map);
void map_sccp_fsm_alloc(struct hnbgw_context_map *map);

void context_map_hnb_released(struct hnbgw_context_map *map);

#define map_rua_dispatch(MAP, EVENT, MSGB) \
	_map_rua_dispatch(MAP, EVENT, MSGB, __FILE__, __LINE__)
int _map_rua_dispatch(struct hnbgw_context_map *map, uint32_t event, struct msgb *ranap_msg,
		      const char *file, int line);

#define map_sccp_dispatch(MAP, EVENT, MSGB) \
	_map_sccp_dispatch(MAP, EVENT, MSGB, __FILE__, __LINE__)
int _map_sccp_dispatch(struct hnbgw_context_map *map, uint32_t event, struct msgb *ranap_msg,
		       const char *file, int line);

bool map_rua_is_active(struct hnbgw_context_map *map);
bool map_sccp_is_active(struct hnbgw_context_map *map);
void context_map_free(struct hnbgw_context_map *map);

unsigned int msg_has_l2_data(const struct msgb *msg);
