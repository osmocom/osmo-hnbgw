#pragma once

#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/ranap/ranap_ies_defs.h>

#include <osmocom/hnbgw/hnbgw.h>

struct hnbgw_cnlink *cnlink_alloc(struct hnbgw_cnpool *cnpool, int nr);
struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_user *hsu,
					       const struct osmo_sccp_addr *remote_addr);
struct hnbgw_cnlink *hnbgw_cnlink_select(struct hnbgw_context_map *map);

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool);
void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool);
void hnbgw_cnpool_cnlinks_start_or_restart(struct hnbgw_cnpool *cnpool);
int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink);

char *cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr);

bool cnlink_is_conn_ready(const struct hnbgw_cnlink *cnlink);
void cnlink_rx_reset_cmd(struct hnbgw_cnlink *cnlink);
void cnlink_rx_reset_ack(struct hnbgw_cnlink *cnlink);
void cnlink_resend_reset(struct hnbgw_cnlink *cnlink);
void cnlink_set_disconnected(struct hnbgw_cnlink *cnlink);

const char *cnlink_paging_add_ranap(struct hnbgw_cnlink *cnlink, RANAP_InitiatingMessage_t *imsg);
struct hnbgw_cnlink *cnlink_find_by_paging_mi(struct hnbgw_cnpool *cnpool, const struct osmo_mobile_identity *mi);

enum hnbgw_cnpool_ctr {
	/* TODO: basic counters completely missing
	 * ...
	 */

	/* Counters related to link selection from a CN pool. */
	CNPOOL_CTR_SUBSCR_NO_CNLINK,
	CNPOOL_CTR_EMERG_FORWARDED,
	CNPOOL_CTR_EMERG_LOST,
};

extern const struct rate_ctr_group_desc iucs_ctrg_desc;
extern const struct rate_ctr_group_desc iups_ctrg_desc;

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

	/* Counters related to link selection from a CN pool. */
	CNLINK_CTR_CNPOOL_SUBSCR_NEW,
	CNLINK_CTR_CNPOOL_SUBSCR_REATTACH,
	CNLINK_CTR_CNPOOL_SUBSCR_KNOWN,
	CNLINK_CTR_CNPOOL_SUBSCR_PAGED,
	CNLINK_CTR_CNPOOL_SUBSCR_ATTACH_LOST,
	CNLINK_CTR_CNPOOL_EMERG_FORWARDED,
};

extern const struct rate_ctr_group_desc msc_ctrg_desc;
extern const struct rate_ctr_group_desc sgsn_ctrg_desc;
