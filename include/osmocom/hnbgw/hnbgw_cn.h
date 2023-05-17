#pragma once

#include <osmocom/hnbgw/hnbgw.h>

struct hnbgw_cnlink *hnbgw_cnlink_alloc(const char *remote_addr_name, RANAP_CN_DomainIndicator_t domain);

const struct osmo_sccp_addr *hnbgw_cn_get_remote_addr(bool is_ps);

struct hnbgw_cnlink *hnbgw_cnlink_find_by_addr(const struct hnbgw_sccp_user *hsu,
					       const struct osmo_sccp_addr *remote_addr);
struct hnbgw_cnlink *hnbgw_cnlink_select(bool is_ps);

char *cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr);
