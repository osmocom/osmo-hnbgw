#pragma once

#include <stdint.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/ranap/RANAP_CN-DomainIndicator.h>

struct hnbgw_context_map;

enum hnbgw_cnpool_ctr {
	/* TODO: basic counters completely missing
	 * ...
	 */

	/* Counters related to link selection from a CN pool. */
	CNPOOL_CTR_SUBSCR_NO_CNLINK,
	CNPOOL_CTR_EMERG_FORWARDED,
	CNPOOL_CTR_EMERG_LOST,
};
#define CNPOOL_CTR_INC(cnpool, x) rate_ctr_inc2((cnpool)->ctrs, x)

/* User provided configuration for struct hnbgw_cnpool. */
struct hnbgw_cnpool_cfg {
	uint8_t nri_bitlen;
	struct osmo_nri_ranges *null_nri_ranges;
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

extern const struct rate_ctr_group_desc iucs_ctrg_desc;
extern const struct rate_ctr_group_desc iups_ctrg_desc;

extern const struct rate_ctr_group_desc msc_ctrg_desc;
extern const struct rate_ctr_group_desc sgsn_ctrg_desc;

struct hnbgw_cnlink *hnbgw_cnlink_select(struct hnbgw_context_map *map);

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool);
void hnbgw_cnpool_cnlinks_start_or_restart(struct hnbgw_cnpool *cnpool);
struct hnbgw_cnlink *cnlink_get_nr(struct hnbgw_cnpool *cnpool, int nr, bool create_if_missing);
void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool);

int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink);
char *cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr);
