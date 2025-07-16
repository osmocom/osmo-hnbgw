#pragma once

#include <stdbool.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/ranap/ranap_ies_defs.h>

#include <osmocom/hnbgw/hnbgw_sccp.h>

struct hnbgw_cnpool;

enum hnbgw_cnlink_ctr {
	/* TODO: basic counters completely missing
	 * ...
	 */
	CNLINK_CTR_RANAP_RX_UDT_RESET,
	CNLINK_CTR_RANAP_RX_UDT_RESET_ACK,
	CNLINK_CTR_RANAP_RX_UDT_PAGING,
	CNLINK_CTR_RANAP_RX_UDT_UNKNOWN,
	CNLINK_CTR_RANAP_RX_UDT_UNSUPPORTED,
	CNLINK_CTR_RANAP_RX_UDT_OVERLOAD_IND,
	CNLINK_CTR_RANAP_RX_UDT_ERROR_IND,

	CNLINK_CTR_RANAP_TX_UDT_RESET,
	CNLINK_CTR_RANAP_TX_UDT_RESET_ACK,

	/* SCCP Counters: */
	CNLINK_CTR_SCCP_N_UNITDATA_REQ,
	CNLINK_CTR_SCCP_N_UNITDATA_IND,
	CNLINK_CTR_SCCP_N_NOTICE_IND,
	CNLINK_CTR_SCCP_N_CONNECT_REQ,
	CNLINK_CTR_SCCP_N_CONNECT_CNF,
	CNLINK_CTR_SCCP_N_DATA_REQ,
	CNLINK_CTR_SCCP_N_DATA_IND,
	CNLINK_CTR_SCCP_N_DISCONNECT_REQ,
	CNLINK_CTR_SCCP_N_DISCONNECT_IND,
	CNLINK_CTR_SCCP_N_PCSTATE_IND,
	CNLINK_CTR_SCCP_RLSD_CN_ORIGIN,

	/* Counters related to link selection from a CN pool. */
	CNLINK_CTR_CNPOOL_SUBSCR_NEW,
	CNLINK_CTR_CNPOOL_SUBSCR_REATTACH,
	CNLINK_CTR_CNPOOL_SUBSCR_KNOWN,
	CNLINK_CTR_CNPOOL_SUBSCR_PAGED,
	CNLINK_CTR_CNPOOL_SUBSCR_ATTACH_LOST,
	CNLINK_CTR_CNPOOL_EMERG_FORWARDED,
};
#define CNLINK_CTR_INC(cnlink, x) rate_ctr_inc2((cnlink)->ctrs, x)

enum cnlink_stat {
	CNLINK_STAT_CONNECTED,
};
#define CNLINK_STAT(cnlink, x) osmo_stat_item_group_get_item((cnlink)->statg, x)
#define CNLINK_STAT_SET(cnlink, x, val) osmo_stat_item_set(CNLINK_STAT(cnlink, x), val)

/* User provided configuration for struct hnbgw_cnlink. */
struct hnbgw_cnlink_cfg {
	/* cs7 address book entry to indicate both the remote point-code of the peer, as well as which cs7 instance to
	 * use. */
	char *remote_addr_name;

	struct osmo_nri_ranges *nri_ranges;
};

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
	struct osmo_stat_item_group *statg;
};

struct hnbgw_cnlink *hnbgw_cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr);
void hnbgw_cnlink_term_and_free(struct hnbgw_cnlink *cnlink);
void hnbgw_cnlink_drop_sccp(struct hnbgw_cnlink *cnlink);
int hnbgw_cnlink_set_name(struct hnbgw_cnlink *cnlink, const char *name);
int hnbgw_cnlink_tx_ranap_reset(struct hnbgw_cnlink *cnlink);
int hnbgw_cnlink_tx_ranap_reset_ack(struct hnbgw_cnlink *cnlink);

int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink);

char *hnbgw_cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr);

static inline struct osmo_sccp_instance *hnbgw_cnlink_sccp(const struct hnbgw_cnlink *cnlink)
{
	if (!cnlink)
		return NULL;
	if (!cnlink->hnbgw_sccp_user)
		return NULL;
	return hnbgw_sccp_user_get_sccp_instance(cnlink->hnbgw_sccp_user);
}

/* cnlink_fsm.c related: */
extern struct osmo_fsm cnlink_fsm;
bool cnlink_is_conn_ready(const struct hnbgw_cnlink *cnlink);
void cnlink_rx_reset_cmd(struct hnbgw_cnlink *cnlink);
void cnlink_rx_reset_ack(struct hnbgw_cnlink *cnlink);
void cnlink_resend_reset(struct hnbgw_cnlink *cnlink);
void cnlink_set_disconnected(struct hnbgw_cnlink *cnlink);

/* cnlink_paging.c related: */
const char *cnlink_paging_add_ranap(struct hnbgw_cnlink *cnlink, const RANAP_PagingIEs_t *paging_ies);
struct hnbgw_cnlink *cnlink_find_by_paging_mi(struct hnbgw_cnpool *cnpool, const struct osmo_mobile_identity *mi);

#define LOG_CNLINK(CNLINK, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (CNLINK) ? (CNLINK)->name : "null", ##ARGS)
