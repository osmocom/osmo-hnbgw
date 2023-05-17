#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/ctrl/control_if.h>
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

enum hnb_ctrl_node {
	CTRL_NODE_HNB = _LAST_CTRL_NODE,
	_LAST_CTRL_NODE_HNB
};

#define HNBGW_LOCAL_IP_DEFAULT "0.0.0.0"
/* TODO: CS and PS now both connect to OsmoSTP, i.e. that's always going to be the same address. Drop the
 * duplicity. */
#define HNBGW_IUCS_REMOTE_IP_DEFAULT "127.0.0.1"
#define HNBGW_IUPS_REMOTE_IP_DEFAULT "127.0.0.1"

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

struct hnbgw_cnlink {
	struct llist_head list;

	/* reference to the SCCP User SAP by which we communicate */
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *sccp_user;
	uint32_t next_conn_id;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;
};

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
	struct {
		const char *iuh_local_ip;
		/*! SCTP port for Iuh listening */
		uint16_t iuh_local_port;
		/*! The UDP port where we receive multiplexed CS user
		 * plane traffic from HNBs */
		uint16_t iuh_cs_mux_port;
		const char *iucs_remote_addr_name;
		const char *iups_remote_addr_name;
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
		struct osmo_sccp_instance *client;
		struct hnbgw_cnlink *cnlink;
		struct osmo_sccp_addr local_addr;
		struct osmo_sccp_addr iucs_remote_addr;
		struct osmo_sccp_addr iups_remote_addr;
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
