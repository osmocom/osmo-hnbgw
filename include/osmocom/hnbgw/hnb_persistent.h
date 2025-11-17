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

#include <osmocom/hnbgw/umts_cell_id.h>
#include <osmocom/hnbgw/nft_kpi.h>
#include <osmocom/hnbgw/cnlink.h>
#include <osmocom/hnbgw/hnbgw_cn.h>

#define LOG_HNBP(HNBP, lvl, fmt, args...) \
	LOGP(DHNB, lvl, "(%s) " fmt, \
	     (HNBP) ? \
		     (((HNBP)->id_str && *(HNBP)->id_str) ? (HNBP)->id_str : "no-cell-id") \
		     : "null", ## args)


enum hnb_rate_ctr {
	HNB_CTR_IUH_ESTABLISHED,
	HNB_CTR_RANAP_PS_ERR_IND_UL,
	HNB_CTR_RANAP_CS_ERR_IND_UL,
	HNB_CTR_RANAP_PS_RESET_REQ_UL,
	HNB_CTR_RANAP_CS_RESET_REQ_UL,

	HNB_CTR_RANAP_PS_RAB_ACT_REQ,
	HNB_CTR_RANAP_CS_RAB_ACT_REQ,
	HNB_CTR_RANAP_PS_RAB_ACT_REQ_UNEXP,
	HNB_CTR_RANAP_CS_RAB_ACT_REQ_UNEXP,

	HNB_CTR_RANAP_PS_RAB_ACT_CNF,
	HNB_CTR_RANAP_CS_RAB_ACT_CNF,
	HNB_CTR_RANAP_PS_RAB_ACT_CNF_UNEXP,
	HNB_CTR_RANAP_CS_RAB_ACT_CNF_UNEXP,

	HNB_CTR_RANAP_PS_RAB_ACT_FAIL,
	HNB_CTR_RANAP_CS_RAB_ACT_FAIL,
	HNB_CTR_RANAP_PS_RAB_ACT_FAIL_UNEXP,
	HNB_CTR_RANAP_CS_RAB_ACT_FAIL_UNEXP,

	HNB_CTR_RANAP_PS_RAB_MOD_REQ,
	HNB_CTR_RANAP_CS_RAB_MOD_REQ,

	HNB_CTR_RANAP_PS_RAB_MOD_CNF,
	HNB_CTR_RANAP_CS_RAB_MOD_CNF,

	HNB_CTR_RANAP_PS_RAB_MOD_FAIL,
	HNB_CTR_RANAP_CS_RAB_MOD_FAIL,

	HNB_CTR_RANAP_PS_RAB_REL_REQ,
	HNB_CTR_RANAP_CS_RAB_REL_REQ,
	HNB_CTR_RANAP_PS_RAB_REL_REQ_ABNORMAL,
	HNB_CTR_RANAP_CS_RAB_REL_REQ_ABNORMAL,
	HNB_CTR_RANAP_PS_RAB_REL_REQ_UNEXP,
	HNB_CTR_RANAP_CS_RAB_REL_REQ_UNEXP,

	HNB_CTR_RANAP_PS_RAB_REL_CNF,
	HNB_CTR_RANAP_CS_RAB_REL_CNF,
	HNB_CTR_RANAP_PS_RAB_REL_CNF_UNEXP,
	HNB_CTR_RANAP_CS_RAB_REL_CNF_UNEXP,

	HNB_CTR_RANAP_PS_RAB_REL_FAIL,
	HNB_CTR_RANAP_CS_RAB_REL_FAIL,
	HNB_CTR_RANAP_PS_RAB_REL_FAIL_UNEXP,
	HNB_CTR_RANAP_CS_RAB_REL_FAIL_UNEXP,

	HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT,
	HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT,
	HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT_ABNORMAL,
	HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT_ABNORMAL,

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

	HNB_CTR_DTAP_CS_LU_REQ,
	HNB_CTR_DTAP_CS_LU_ACC,
	HNB_CTR_DTAP_CS_LU_REJ,

	HNB_CTR_DTAP_PS_ATT_REQ,
	HNB_CTR_DTAP_PS_ATT_ACK,
	HNB_CTR_DTAP_PS_ATT_REJ,

	HNB_CTR_DTAP_PS_RAU_REQ,
	HNB_CTR_DTAP_PS_RAU_ACK,
	HNB_CTR_DTAP_PS_RAU_REJ,

	HNB_CTR_GTPU_PACKETS_UL,
	HNB_CTR_GTPU_TOTAL_BYTES_UL,
	HNB_CTR_GTPU_UE_BYTES_UL,
	HNB_CTR_GTPU_PACKETS_DL,
	HNB_CTR_GTPU_TOTAL_BYTES_DL,
	HNB_CTR_GTPU_UE_BYTES_DL,
};

enum hnb_stat {
	HNB_STAT_UPTIME_SECONDS,
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
	/*! Entry in hash table g_hnbgw->hnb_persistent_by_id. */
	struct hlist_node node_by_id;
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
		int iuh_tx_queue_max_length; /* -1: Use hnbgw default */
	} config;

	/* State that the main thread needs in order to know what was requested from the nft worker threads and what
	 * still needs to be requested. */
	struct {
		/* Whether a persistent named counter was added in nftables for this cell id. */
		bool persistent_counter_added;

		/* The last hNodeB GTP-U address we asked the nft maintenance thread to set up.
		 * osmo_sockaddr_str_is_nonzero(addr_remote) == false when no rules were added yet, and when
		 * we asked the nft maintenance thread to remove the rules for this hNodeB because it has
		 * disconnected. */
		struct osmo_sockaddr_str addr_remote;

		/* the nft handles needed to clean up the UL and DL rules when the hNodeB disconnects,
		 * and the last seen counter value gotten from nft. */
		struct {
			struct nft_kpi_handle h;
			struct nft_kpi_val v;
		} ul;
		struct {
			struct nft_kpi_handle h;
			struct nft_kpi_val v;
		} dl;
	} nft_kpi;

	struct osmo_timer_list disconnected_timeout;
};

struct hnb_persistent *hnb_persistent_alloc(const struct umts_cell_id *id);
struct hnb_persistent *hnb_persistent_find_by_id(const struct umts_cell_id *id);
void hnb_persistent_registered(struct hnb_persistent *hnbp);
void hnb_persistent_deregistered(struct hnb_persistent *hnbp);
void hnb_persistent_free(struct hnb_persistent *hnbp);

unsigned long long hnbp_get_updowntime(const struct hnb_persistent *hnbp);
