#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ranap/RANAP_CN-DomainIndicator.h>

#define DEBUG
#include <osmocom/core/logging.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#include <osmocom/hnbgw/nft_kpi.h>
#include <osmocom/hnbgw/cnlink.h>
#include <osmocom/hnbgw/hnbgw_cn.h>

#define STORE_UPTIME_INTERVAL	10 /* seconds */

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

#define DOMAIN_CS RANAP_CN_DomainIndicator_cs_domain
#define DOMAIN_PS RANAP_CN_DomainIndicator_ps_domain

extern const struct value_string ranap_domain_names[];
static inline const char *ranap_domain_name(RANAP_CN_DomainIndicator_t domain)
{
	return get_value_string(ranap_domain_names, domain);
}

#define HNBGW_LOCAL_IP_DEFAULT "0.0.0.0"
/* TODO: CS and PS now both connect to OsmoSTP, i.e. that's always going to be the same address. Drop the
 * duplicity. */
#define HNBGW_IUCS_REMOTE_IP_DEFAULT "127.0.0.1"
#define HNBGW_IUPS_REMOTE_IP_DEFAULT "127.0.0.1"

#define DEFAULT_PC_HNBGW ((23 << 3) + 5)
#define DEFAULT_PC_MSC ((23 << 3) + 1)
#define DEFAULT_PC_SGSN ((23 << 3) + 4)
#define DEFAULT_ADDR_NAME_MSC "addr-dyn-msc-default"
#define DEFAULT_ADDR_NAME_SGSN "addr-dyn-sgsn-default"

/* 25.467 Section 7.1 */
#define IUH_DEFAULT_SCTP_PORT	29169
#define RNA_DEFAULT_SCTP_PORT	25471

#define IUH_PPI_RUA		19
#define IUH_PPI_HNBAP		20
#define IUH_PPI_SABP		31
#define IUH_PPI_RNA		42
#define IUH_PPI_PUA		55

#define IUH_MSGB_SIZE	2048

#define IUH_TX_QUEUE_MAX_LENGTH 1024

struct hnbgw_context_map;

static inline bool cnlink_is_cs(const struct hnbgw_cnlink *cnlink)
{
	return cnlink && cnlink->pool->domain == DOMAIN_CS;
}

static inline bool cnlink_is_ps(const struct hnbgw_cnlink *cnlink)
{
	return cnlink && cnlink->pool->domain == DOMAIN_PS;
}

struct hnbgw {
	struct {
		struct osmo_plmn_id plmn;
		uint16_t rnc_id;
		/*! print hnb-id (true) or MCC-MNC-LAC-RAC-SAC (false) in logs */
		bool log_prefix_hnb_id;
		bool accept_all_hnb;
		struct mgcp_client_conf *mgcp_client;
		struct {
			const char *local_ip;
			/*! SCTP port for Iuh listening */
			uint16_t local_port;
			bool hnbap_allow_tmsi;
			unsigned int tx_queue_max_length;
		} iuh;
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
		struct {
			bool enable;
			/* The table name as used in nftables for the ruleset owned by this process. It is "osmo-hnbgw"
			 * by default. */
			char *table_name;
		} nft_kpi;
	} config;
	/*! SCTP listen socket for incoming connections */
	struct osmo_stream_srv_link *iuh;
	/* list of struct hnb_context */
	struct llist_head hnb_list;

	/* list of struct hnb_persistent */
	struct llist_head hnb_persistent_list;
	/* optimized lookup for hnb_persistent, by cell id string */
	DECLARE_HASHTABLE(hnb_persistent_by_id, 5);

	struct osmo_timer_list store_uptime_timer;
	/* next availble UE Context ID */
	uint32_t next_ue_ctx_id;
	struct ctrl_handle *ctrl;
	/* currently active CN links for CS and PS */
	struct {
		/* List of hnbgw_sccp_user */
		struct llist_head users;

		/* Pool of core network peers: MSCs for IuCS */
		struct hnbgw_cnpool *cnpool_iucs;
		/* Pool of core network peers: SGSNs for IuPS */
		struct hnbgw_cnpool *cnpool_iups;
	} sccp;
	/* MGW pool, also includes the single MGCP client as fallback if no
	 * pool is configured. */
	struct mgcp_client_pool *mgw_pool;

	struct {
		struct osmo_pfcp_endpoint *ep;
		struct osmo_pfcp_cp_peer *cp_peer;
		/* Running counters for the PFCP conn */
		struct osmo_stat_item_group *statg;
	} pfcp;

	struct osmo_timer_list hnb_store_rab_durations_timer;

	struct {
		bool active;
		struct osmo_timer_list get_counters_timer;
		struct timespec next_timer;
	} nft_kpi;
};

extern struct hnbgw *g_hnbgw;
extern void *talloc_asn1_ctx;

void g_hnbgw_alloc(void *ctx);

int hnbgw_rua_accept_cb(struct osmo_stream_srv_link *srv, int fd);
int hnbgw_mgw_setup(void);

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

uint32_t get_next_ue_ctx_id(void);
