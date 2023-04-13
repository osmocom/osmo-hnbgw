#pragma once

#include <osmocom/hnbgw/hnbgw.h>

struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_user *hsu,
					       const struct osmo_sccp_addr *remote_addr);
struct hnbgw_cnlink *hnbgw_cnlink_select(struct hnbgw_context_map *map);

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool);
void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool);
void hnbgw_cnpool_cnlinks_start_or_restart(struct hnbgw_cnpool *cnpool);
int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink);

char *cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr);

