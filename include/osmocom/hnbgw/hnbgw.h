#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ranap/RANAP_CN-DomainIndicator.h>

#define DEBUG
#include <osmocom/core/logging.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

enum {
	DMAIN,
	DHNBAP,
	DRUA,
	DRANAP,
	DMGW,
	DHNB,
	DCN,
};

extern const struct log_info hnbgw_log_info;
extern struct vty_app_info hnbgw_vty_info;

#define LOGHNB(HNB_CTX, ss, lvl, fmt, args ...) \
	LOGP(ss, lvl, "(%s) " fmt, hnb_context_name(HNB_CTX), ## args)

#define DOMAIN_CS RANAP_CN_DomainIndicator_cs_domain
#define DOMAIN_PS RANAP_CN_DomainIndicator_ps_domain

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

struct umts_cell_id {
	uint16_t mcc;	/*!< Mobile Country Code */
	uint16_t mnc;	/*!< Mobile Network Code */
	uint16_t lac;	/*!< Locaton Area Code */
	uint16_t rac;	/*!< Routing Area Code */
	uint16_t sac;	/*!< Service Area Code */
	uint32_t cid;	/*!< Cell ID */
};

struct hnbgw_context_map;

struct hnbgw_sccp_inst {
	struct llist_head entry;

	char *name;

	/* There is one osmo_sccp_instance per cs7_instance.
	 * Below osmo_sccp_instance is running on this cs7 instance: */
	uint32_t cs7_instance;
	struct osmo_sccp_instance *sccp;
	/* for SSN = RANAP */
	struct osmo_sccp_user *sccp_user;

	DECLARE_HASHTABLE(hnbgw_context_map_by_conn_id, 6);
};

#define LOG_HSI(HNBGW_SCCP_INST, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (HNBGW_SCCP_INST) ? (HNBGW_SCCP_INST)->name : "null", ##ARGS)

enum hnbgw_cnlink_state {
	/* we have just been initialized or were disconnected */
	CNLINK_S_NULL,
	/* establishment of the SUA/SCCP link is pending */
	CNLINK_S_EST_PEND,
	/* establishment of the SUA/SCCP link was confirmed */
	CNLINK_S_EST_CONF,
	/* we have esnt the RANAP RESET and wait for the ACK */
	CNLINK_S_EST_RST_TX_WAIT_ACK,
	/* we have received the RANAP RESET ACK and are active */
	CNLINK_S_EST_ACTIVE,
};

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
	/* maybe todo: add 'const char *local_addr_name;' to configure local point-code? */

	struct osmo_nri_ranges *nri_ranges;
};

/* Collection of CN peers to distribute UE connections across. MSCs for DOMAIN_CS, SGSNs for DOMAIN_PS. */
struct hnbgw_cnpool {
	RANAP_CN_DomainIndicator_t domain;

	/* CN pool string used in VTY config and logging, "iucs" or "iups". */
	const char *pool_name;
	/* CN peer string used in VTY config and logging, "msc" or "sgsn". */
	const char *peer_name;

	struct hnbgw_cnpool_cfg vty;
	struct hnbgw_cnpool_cfg use;

	/* List of struct hnbgw_cnlink */
	struct llist_head cnlinks;

	unsigned int round_robin_next_nr;
	/* Emergency calls potentially select a different set of MSCs, so to not mess up the normal round-robin
	 * behavior, emergency calls need a separate round-robin counter. */
	unsigned int round_robin_next_emerg_nr;
};

/* A CN peer, like MSC or SGSN, operative state. When this instance exists, it means that the cnlink is active. */
struct hnbgw_cnlink {
	struct llist_head entry;

	/* backpointer */
	struct hnbgw_cnpool *pool;

	int nr;

	struct hnbgw_cnlink_cfg vty;
	struct hnbgw_cnlink_cfg use;

	/* To print in logging/VTY */
	char *name;

	/* FUTURE: In principle, there may be different local point-codes for separate CN links on the same SCCP
	 * instance. So far, each hnbgw_cnlink->local_addr just contains SSN = RANAP, so that the cs7 instance fills in
	 * its primary point code. */
	struct osmo_sccp_addr local_addr;

	/* Copy of the address pointed at by use.remote_addr_name. */
	struct osmo_sccp_addr remote_addr;

	/* The SCCP instance for the cs7 instance indicated by remote_addr_name. (Multiple hnbgw_cnlinks may use the
	 * same hnbgw_sccp_inst -- there is exactly one hnbgw_sccp_inst per configured cs7 instance.) */
	struct hnbgw_sccp_inst *hnbgw_sccp_inst;

	enum hnbgw_cnlink_state state;
	/* timer for re-transmitting the RANAP Reset */
	struct osmo_timer_list T_RafC;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;

	bool allow_attach;
	bool allow_emerg;
};

#define LOG_CNLINK(CNLINK, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (CNLINK) ? (CNLINK)->name : "null", ##ARGS)

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
	if (!cnlink->hnbgw_sccp_inst)
		return NULL;
	return cnlink->hnbgw_sccp_inst->sccp;
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
	/* Configuration items that do not take immedate effect / need separate storage for VTY. These are copied to
	 * operative state when they take effect, like parsing iuh_local_ip and iuh_local_port to an osmo_sockaddr.
	 * - For writing the VTY config, use these.
	 * - For active operation, use the operative state instead, because these config settings may go out of sync
	 *   with what is currently active and open in the running process.
	 */
	struct {
		const char *iuh_local_ip;
		/*! SCTP port for Iuh listening */
		uint16_t iuh_local_port;
		/*! The UDP port where we receive multiplexed CS user
		 * plane traffic from HNBs */
		uint16_t iuh_cs_mux_port;
		uint16_t rnc_id;
		bool hnbap_allow_tmsi;
		/*! print hnb-id (true) or MCC-MNC-LAC-RAC-SAC (false) in logs */
		bool log_prefix_hnb_id;
		struct mgcp_client_conf *mgcp_client;
		struct {
			char *local_addr;
			uint16_t local_port;
			char *remote_addr;
			uint16_t remote_port;
		} pfcp;
	} config;
	/*! SCTP listen socket for incoming connections */
	struct osmo_stream_srv_link *iuh;
	/* list of struct hnb_context */
	struct llist_head hnb_list;
	/* list of struct ue_context */
	struct llist_head ue_list;
	/* next availble UE Context ID */
	uint32_t next_ue_ctx_id;
	struct ctrl_handle *ctrl;
	/* currently active CN links for CS and PS */
	struct {
		/* List of hnbgw_sccp_inst */
		struct llist_head instances;

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

struct hnbgw_cnlink *hnbgw_cnlink_select(struct hnbgw_context_map *map);

void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool);
void hnbgw_cnpool_cnlinks_start_or_restart(struct hnbgw_cnpool *cnpool);

int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink);
