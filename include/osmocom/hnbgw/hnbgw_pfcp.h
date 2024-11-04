#pragma once

enum hnbgw_upf_stats {
	HNBGW_UPF_STAT_ASSOCIATED,
};
#define HNBGW_UPF_STAT_SET(stat, val) osmo_stat_item_set(osmo_stat_item_group_get_item(g_hnbgw->pfcp.statg, (stat)), (val))

int hnbgw_pfcp_init(void);
void hnbgw_pfcp_release(void);
