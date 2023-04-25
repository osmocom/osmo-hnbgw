#pragma once

#include <osmocom/hnbgw/hnbgw.h>

struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_inst *hsi,
					       const struct osmo_sccp_addr *remote_addr);

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool);
