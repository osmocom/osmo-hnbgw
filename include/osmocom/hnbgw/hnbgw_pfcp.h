#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/pfcp/pfcp_endpoint.h>
#include <osmocom/pfcp/pfcp_cp_peer.h>

enum hnbgw_upf_stats {
	HNBGW_UPF_STAT_ASSOCIATED,
};
#define HNBGW_UPF_STAT_SET(stat, val) osmo_stat_item_set(osmo_stat_item_group_get_item(g_hnbgw->pfcp.upf->statg, (stat)), (val))

struct hnbgw_upf {
	struct osmo_pfcp_cp_peer *cp_peer;
	/* Running counters for the PFCP conn */
	struct osmo_stat_item_group *statg;
};

struct hnbgw_upf *hnbgw_upf_alloc(struct osmo_pfcp_endpoint *ep, const struct osmo_sockaddr *rem_addr);
void hnbgw_upf_free(struct hnbgw_upf *upf);

int hnbgw_pfcp_init(void);
void hnbgw_pfcp_release(void);

#define LOGUPF(upf, ss, lvl, fmt, args ...) \
	LOGP(ss, lvl, "UPF(%s) " fmt, osmo_sockaddr_to_str_c(OTC_SELECT, osmo_pfcp_cp_peer_get_remote_addr(upf->cp_peer)), ## args)
