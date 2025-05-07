#pragma once

#include <stdbool.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/ranap/ranap_ies_defs.h>

#include <osmocom/hnbgw/hnbgw_sccp.h>

struct hnbgw_cnpool;

struct hnbgw_cnlink *cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr);

void hnbgw_cnlink_drop_sccp(struct hnbgw_cnlink *cnlink);

bool cnlink_is_conn_ready(const struct hnbgw_cnlink *cnlink);
void cnlink_rx_reset_cmd(struct hnbgw_cnlink *cnlink);
void cnlink_rx_reset_ack(struct hnbgw_cnlink *cnlink);
void cnlink_resend_reset(struct hnbgw_cnlink *cnlink);
void cnlink_set_disconnected(struct hnbgw_cnlink *cnlink);

const char *cnlink_paging_add_ranap(struct hnbgw_cnlink *cnlink, const RANAP_PagingIEs_t *paging_ies);
struct hnbgw_cnlink *cnlink_find_by_paging_mi(struct hnbgw_cnpool *cnpool, const struct osmo_mobile_identity *mi);

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
};

static inline struct osmo_sccp_instance *cnlink_sccp(const struct hnbgw_cnlink *cnlink)
{
	if (!cnlink)
		return NULL;
	if (!cnlink->hnbgw_sccp_user)
		return NULL;
	if (!cnlink->hnbgw_sccp_user->ss7)
		return NULL;
	return osmo_ss7_get_sccp(cnlink->hnbgw_sccp_user->ss7);
}

#define LOG_CNLINK(CNLINK, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (CNLINK) ? (CNLINK)->name : "null", ##ARGS)

#define CNLINK_CTR_INC(cnlink, x) rate_ctr_inc2((cnlink)->ctrs, x)
