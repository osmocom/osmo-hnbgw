#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ranap/RANAP_CN-DomainIndicator.h>

#define DEBUG
#include <osmocom/core/logging.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#include <osmocom/hnbgw/nft_kpi.h>

#define STORE_UPTIME_INTERVAL	10 /* seconds */
#define HNB_STORE_RAB_DURATIONS_INTERVAL 1 /* seconds */

enum {
	DMAIN,
	DHNBAP,
	DRUA,
	DRANAP,
	DMGW,
	DHNB,
	DCN,
	DNFT,
};

extern const struct log_info hnbgw_log_info;
extern struct vty_app_info hnbgw_vty_info;

#define LOGHNB(HNB_CTX, ss, lvl, fmt, args ...) \
	LOGP(ss, lvl, "(%s) " fmt, hnb_context_name(HNB_CTX), ## args)

#define DOMAIN_CS RANAP_CN_DomainIndicator_cs_domain
#define DOMAIN_PS RANAP_CN_DomainIndicator_ps_domain

extern const struct value_string ranap_domain_names[];
static inline const char *ranap_domain_name(RANAP_CN_DomainIndicator_t domain)
{
	return get_value_string(ranap_domain_names, domain);
}

enum hnb_ctrl_node {
	CTRL_NODE_HNB = _LAST_CTRL_NODE,
	_LAST_CTRL_NODE_HNB
};

#define HNBGW_LOCAL_IP_DEFAULT "0.0.0.0"
/* TODO: CS and PS now both connect to OsmoSTP, i.e. that's always going to be the same address. Drop the
 * duplicity. */
#define HNBGW_IUCS_REMOTE_IP_DEFAULT "127.0.0.1"
#define HNBGW_IUPS_REMOTE_IP_DEFAULT "127.0.0.1"

#define DEFAULT_PC_HNBGW ((23 << 3) + 5)
#define DEFAULT_PC_MSC ((23 << 3) + 1)
#define DEFAULT_PC_SGSN ((23 << 3) + 4)

/* 25.467 Section 7.1 */
#define IUH_DEFAULT_SCTP_PORT	29169
#define RNA_DEFAULT_SCTP_PORT	25471

#define IUH_PPI_RUA		19
#define IUH_PPI_HNBAP		20
#define IUH_PPI_SABP		31
#define IUH_PPI_RNA		42
#define IUH_PPI_PUA		55

#define IUH_MSGB_SIZE	2048

enum hnb_rate_ctr {
	HNB_CTR_IUH_ESTABLISHED,
	HNB_CTR_RANAP_PS_ERR_IND_UL,
	HNB_CTR_RANAP_CS_ERR_IND_UL,
	HNB_CTR_RANAP_PS_RESET_REQ_UL,
	HNB_CTR_RANAP_CS_RESET_REQ_UL,

	HNB_CTR_RANAP_PS_RAB_ACT_REQ,
	HNB_CTR_RANAP_CS_RAB_ACT_REQ,

	HNB_CTR_RANAP_PS_RAB_ACT_CNF,
	HNB_CTR_RANAP_CS_RAB_ACT_CNF,

	HNB_CTR_RANAP_PS_RAB_ACT_FAIL,
	HNB_CTR_RANAP_CS_RAB_ACT_FAIL,

	HNB_CTR_RANAP_PS_RAB_MOD_REQ,
	HNB_CTR_RANAP_CS_RAB_MOD_REQ,

	HNB_CTR_RANAP_PS_RAB_MOD_CNF,
	HNB_CTR_RANAP_CS_RAB_MOD_CNF,

	HNB_CTR_RANAP_PS_RAB_MOD_FAIL,
	HNB_CTR_RANAP_CS_RAB_MOD_FAIL,

	HNB_CTR_RANAP_PS_RAB_REL_REQ,
	HNB_CTR_RANAP_CS_RAB_REL_REQ,

	HNB_CTR_RANAP_PS_RAB_REL_CNF,
	HNB_CTR_RANAP_CS_RAB_REL_CNF,

	HNB_CTR_RANAP_PS_RAB_REL_FAIL,
	HNB_CTR_RANAP_CS_RAB_REL_FAIL,

	HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT,
	HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT,

	HNB_CTR_RUA_ERR_IND,

	HNB_CTR_RUA_PS_CONNECT_UL,
	HNB_CTR_RUA_CS_CONNECT_UL,

	HNB_CTR_RUA_PS_DISCONNECT_UL,
	HNB_CTR_RUA_CS_DISCONNECT_UL,
	HNB_CTR_RUA_PS_DISCONNECT_DL,
	HNB_CTR_RUA_CS_DISCONNECT_DL,

	HNB_CTR_RUA_PS_DT_UL,
	HNB_CTR_RUA_CS_DT_UL,
	HNB_CTR_RUA_PS_DT_DL,
	HNB_CTR_RUA_CS_DT_DL,

	HNB_CTR_RUA_UDT_UL,
	HNB_CTR_RUA_UDT_DL,

	HNB_CTR_PS_PAGING_ATTEMPTED,
	HNB_CTR_CS_PAGING_ATTEMPTED,

	HNB_CTR_RAB_ACTIVE_MILLISECONDS_TOTAL,

	HNB_CTR_GTPU_DOWNLOAD_PACKETS,
	HNB_CTR_GTPU_DOWNLOAD_GTP_BYTES,
	HNB_CTR_GTPU_UPLOAD_PACKETS,
	HNB_CTR_GTPU_UPLOAD_GTP_BYTES,
};

enum hnb_stat {
	HNB_STAT_UPTIME_SECONDS,
};

struct umts_cell_id {
	uint16_t mcc;	/*!< Mobile Country Code (0-999) */
	uint16_t mnc;	/*!< Mobile Network Code (0-999) */
	uint16_t lac;	/*!< Locaton Area Code (1-65534) */
	uint16_t rac;	/*!< Routing Area Code (0-255) */
	uint16_t sac;	/*!< Service Area Code */
	uint32_t cid;	/*!< Cell ID */
};
const char *umts_cell_id_name(const struct umts_cell_id *ucid);
int umts_cell_id_from_str(struct umts_cell_id *ucid, const char *instr);

/*! are both given umts_cell_id euqal? */
static inline bool umts_cell_id_equal(const struct umts_cell_id *a, const struct umts_cell_id *b)
{
	if (a->mcc != b->mcc)
		return false;
	if (a->mnc != b->mnc)
		return false;
	if (a->lac != b->lac)
		return false;
	if (a->rac != b->rac)
		return false;
	if (a->sac != b->sac)
		return false;
	if (a->cid != b->cid)
		return false;
	return true;
}

struct hnbgw_context_map;

/* osmo-hnbgw keeps a single hnbgw_sccp_user per osmo_sccp_instance, for the local point-code and SSN == RANAP.
 * This relates the (opaque) osmo_sccp_user to osmo-hnbgw's per-ss7 state. */
struct hnbgw_sccp_user {
	/* entry in g_hnbgw->sccp.users */
	struct llist_head entry;

	/* logging context */
	char *name;

	/* Which 'cs7 instance' is this for? Below sccp_user is registered at the osmo_sccp_instance ss7->sccp. */
	struct osmo_ss7_instance *ss7;

	/* Local address: cs7 instance's primary PC if present, else the default HNBGW PC; with SSN == RANAP. */
	struct osmo_sccp_addr local_addr;

	/* osmo_sccp API state for above local address on above ss7 instance. */
	struct osmo_sccp_user *sccp_user;

	/* Fast access to the hnbgw_context_map responsible for a given SCCP conn_id of the ss7->sccp instance.
	 * hlist_node: hnbgw_context_map->hnbgw_sccp_user_entry. */
	DECLARE_HASHTABLE(hnbgw_context_map_by_conn_id, 6);
};

#define LOG_HSI(HNBGW_SCCP_INST, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (HNBGW_SCCP_INST) ? (HNBGW_SCCP_INST)->name : "null", ##ARGS)

/* User provided configuration for struct hnbgw_cnpool. */
struct hnbgw_cnpool_cfg {
	uint8_t nri_bitlen;
	struct osmo_nri_ranges *null_nri_ranges;
};

/* User provided configuration for struct hnbgw_cnlink. */
struct hnbgw_cnlink_cfg {
	/* cs7 address book entry to indicate both the remote point-code of the peer, as well as which cs7 instance to
	 * use. */
	char *remote_addr_name;

	struct osmo_nri_ranges *nri_ranges;
};

/* Collection of CN peers to distribute UE connections across. MSCs for DOMAIN_CS, SGSNs for DOMAIN_PS. */
struct hnbgw_cnpool {
	RANAP_CN_DomainIndicator_t domain;

	/* CN pool string used in VTY config and logging, "iucs" or "iups". */
	const char *pool_name;
	/* CN peer string used in VTY config and logging, "msc" or "sgsn". */
	const char *peer_name;
	/* What we use as the remote MSC/SGSN point-code if the user does not configure any address. */
	uint32_t default_remote_pc;

	struct hnbgw_cnpool_cfg vty;
	struct hnbgw_cnpool_cfg use;

	/* List of struct hnbgw_cnlink */
	struct llist_head cnlinks;

	unsigned int round_robin_next_nr;
	/* Emergency calls potentially select a different set of MSCs, so to not mess up the normal round-robin
	 * behavior, emergency calls need a separate round-robin counter. */
	unsigned int round_robin_next_emerg_nr;

	/* rate counter group that child hnbgw_cnlinks should use (points to msc_ctrg_desc or sgsn_ctrg_desc) */
	const struct rate_ctr_group_desc *cnlink_ctrg_desc;

	/* Running counters for this pool */
	struct rate_ctr_group *ctrs;
};

#define CNPOOL_CTR_INC(cnpool, x) rate_ctr_inc2((cnpool)->ctrs, x)

/* A CN peer, like 'msc 0' or 'sgsn 23' */
struct hnbgw_cnlink {
	struct llist_head entry;

	/* backpointer to CS or PS CN pool. */
	struct hnbgw_cnpool *pool;

	struct osmo_fsm_inst *fi;

	int nr;

	struct hnbgw_cnlink_cfg vty;
	struct hnbgw_cnlink_cfg use;

	/* To print in logging/VTY */
	char *name;

	/* Copy of the address book entry use.remote_addr_name. */
	struct osmo_sccp_addr remote_addr;

	/* The SCCP instance for the cs7 instance indicated by remote_addr_name. (Multiple hnbgw_cnlinks may use the
	 * same hnbgw_sccp_user -- there is exactly one hnbgw_sccp_user per configured cs7 instance.) */
	struct hnbgw_sccp_user *hnbgw_sccp_user;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;

	bool allow_attach;
	bool allow_emerg;
	struct llist_head paging;

	struct rate_ctr_group *ctrs;
};

#define LOG_CNLINK(CNLINK, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (CNLINK) ? (CNLINK)->name : "null", ##ARGS)

#define CNLINK_CTR_INC(cnlink, x) rate_ctr_inc2((cnlink)->ctrs, x)

struct hnbgw_cnlink *cnlink_get_nr(struct hnbgw_cnpool *cnpool, int nr, bool create_if_missing);

static inline bool cnlink_is_cs(const struct hnbgw_cnlink *cnlink)
{
	return cnlink && cnlink->pool->domain == DOMAIN_CS;
}

static inline bool cnlink_is_ps(const struct hnbgw_cnlink *cnlink)
{
	return cnlink && cnlink->pool->domain == DOMAIN_PS;
}

static inline struct osmo_sccp_instance *cnlink_sccp(const struct hnbgw_cnlink *cnlink)
{
	if (!cnlink)
		return NULL;
	if (!cnlink->hnbgw_sccp_user)
		return NULL;
	if (!cnlink->hnbgw_sccp_user->ss7)
		return NULL;
	return cnlink->hnbgw_sccp_user->ss7->sccp;
}

/* The lifecycle of the hnb_context object is the same as its conn */
struct hnb_context {
	/*! Entry in HNB-global list of HNB */
	struct llist_head list;
	/*! SCTP socket + write queue for Iuh to this specific HNB */
	struct osmo_stream_srv *conn;
	/*! copied from HNB-Identity-Info IE */
	char identity_info[256];
	/*! copied from Cell Identity IE */
	struct umts_cell_id id;

	/*! SCTP stream ID for HNBAP */
	uint16_t hnbap_stream;
	/*! SCTP stream ID for RUA */
	uint16_t rua_stream;

	/*! True if a HNB-REGISTER-REQ from this HNB has been accepted. */
	bool hnb_registered;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;

	/*! pointer to the associated hnb persistent state. Always present after HNB-Register */
	struct hnb_persistent *persistent;
};

#define HNBP_CTR(hnbp, x) rate_ctr_group_get_ctr((hnbp)->ctrs, x)
#define HNBP_CTR_INC(hnbp, x) rate_ctr_inc(HNBP_CTR(hnbp, x))
#define HNBP_CTR_ADD(hnbp, x, y) rate_ctr_add2((hnbp)->ctrs, x, y)

#define HNBP_STAT(hbp, x) osmo_stat_item_group_get_item((hnbp)->statg, x)
#define HNBP_STAT_SET(hnbp, x, val) osmo_stat_item_set(HNBP_STAT(hnbp, x), val)

/* persistent data for one HNB.  This continues to exist even as conn / hnb_context is deleted on disconnect */
struct hnb_persistent {
	/*! Entry in HNBGW-global list of hnb_persistent */
	struct llist_head list;
	/*! back-pointer to hnb_context.  Can be NULL if no context at this point */
	struct hnb_context *ctx;

	/*! unique cell identity; copied from HNB REGISTER REQ */
	struct umts_cell_id id;
	/*! stringified version of the cell identiy above (for printing/naming) */
	const char *id_str;

	/*! copied from HNB-Identity-Info IE */
	time_t updowntime;

	struct rate_ctr_group *ctrs;
	struct osmo_stat_item_group *statg;

	struct {
		struct osmo_sockaddr_str addr_remote;
		struct {
			struct nft_kpi_val rx;
			struct nft_kpi_val tx;
		} last;
	} nft_kpi;
};

struct ue_context {
	/*! Entry in the HNB-global list of UE */
	struct llist_head list;
	/*! Unique Context ID for this UE */
	uint32_t context_id;
	char imsi[16+1];
	uint32_t tmsi;
	/*! UE is serviced via this HNB */
	struct hnb_context *hnb;
};

struct hnbgw {
	struct {
		const char *iuh_local_ip;
		/*! SCTP port for Iuh listening */
		uint16_t iuh_local_port;
		/*! The UDP port where we receive multiplexed CS user
		 * plane traffic from HNBs */
		uint16_t iuh_cs_mux_port;
		struct osmo_plmn_id plmn;
		uint16_t rnc_id;
		bool hnbap_allow_tmsi;
		/*! print hnb-id (true) or MCC-MNC-LAC-RAC-SAC (false) in logs */
		bool log_prefix_hnb_id;
		bool accept_all_hnb;
		struct mgcp_client_conf *mgcp_client;
		struct {
			char *local_addr;
			uint16_t local_port;
			char *remote_addr;
			uint16_t remote_port;
			struct {
				char *access;
				char *core;
			} netinst;
		} pfcp;
	} config;
	/*! SCTP listen socket for incoming connections */
	struct osmo_stream_srv_link *iuh;
	/* list of struct hnb_context */
	struct llist_head hnb_list;
	/* list of struct hnb_persistent */
	struct llist_head hnb_persistent_list;
	struct osmo_timer_list store_uptime_timer;
	/* list of struct ue_context */
	struct llist_head ue_list;
	/* next availble UE Context ID */
	uint32_t next_ue_ctx_id;
	struct ctrl_handle *ctrl;
	/* currently active CN links for CS and PS */
	struct {
		/* List of hnbgw_sccp_user */
		struct llist_head users;

		/* Pool of core network peers: MSCs for IuCS */
		struct hnbgw_cnpool cnpool_iucs;
		/* Pool of core network peers: SGSNs for IuPS */
		struct hnbgw_cnpool cnpool_iups;
	} sccp;
	/* MGW pool, also includes the single MGCP client as fallback if no
	 * pool is configured. */
	struct mgcp_client_pool *mgw_pool;

	struct {
		struct osmo_pfcp_endpoint *ep;
		struct osmo_pfcp_cp_peer *cp_peer;
	} pfcp;

	struct osmo_timer_list hnb_store_rab_durations_timer;
};

extern struct hnbgw *g_hnbgw;
extern void *talloc_asn1_ctx;

void g_hnbgw_alloc(void *ctx);

int hnbgw_rua_accept_cb(struct osmo_stream_srv_link *srv, int fd);
int hnb_ctrl_cmds_install(void);
int hnb_ctrl_node_lookup(void *data, vector vline, int *node_type, void **node_data, int *i);
int hnbgw_mgw_setup(void);

struct hnb_context *hnb_context_by_identity_info(const char *identity_info);
const char *hnb_context_name(struct hnb_context *ctx);

struct ue_context *ue_context_by_id(uint32_t id);
struct ue_context *ue_context_by_imsi(const char *imsi);
struct ue_context *ue_context_by_tmsi(uint32_t tmsi);
struct ue_context *ue_context_alloc(struct hnb_context *hnb, const char *imsi,
				    uint32_t tmsi);
void ue_context_free(struct ue_context *ue);

void hnb_context_release(struct hnb_context *ctx);
void hnb_context_release_ue_state(struct hnb_context *ctx);

struct hnb_persistent *hnb_persistent_alloc(const struct umts_cell_id *id);
struct hnb_persistent *hnb_persistent_find_by_id(const struct umts_cell_id *id_str);
struct hnb_persistent *hnb_persistent_find_by_id_str(const char *id);
void hnb_persistent_update_addr(struct hnb_persistent *hnbp, int new_fd);
void hnb_persistent_free(struct hnb_persistent *hnbp);

void hnbgw_vty_init(void);
int hnbgw_vty_go_parent(struct vty *vty);

/* Return true when the user configured GTP mapping to be enabled, by configuring a PFCP link to a UPF.
 * Return false when the user configured to skip GTP mapping and RANAP PS RAB Requests/Responses should be passed thru
 * 1:1.
 * GTP mapping means that there are two GTP tunnels, one towards HNB and one towards CN, and we forward payloads between
 * the two tunnels, mapping the TEIDs and GTP addresses. */
static inline bool hnb_gw_is_gtp_mapping_enabled(void)
{
	return g_hnbgw->config.pfcp.remote_addr != NULL;
}

struct msgb *hnbgw_ranap_msg_alloc(const char *name);

int hnbgw_peek_l3_ul(struct hnbgw_context_map *map, struct msgb *ranap_msg);

unsigned long long hnb_get_updowntime(const struct hnb_context *ctx);
