#pragma once

#include <osmocom/core/rate_ctr.h>
#include <osmocom/hnbgw/hnbgw.h>

struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_inst *hsi,
					       const struct osmo_sccp_addr *remote_addr);

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool);

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
