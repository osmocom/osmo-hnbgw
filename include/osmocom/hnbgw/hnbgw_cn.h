#pragma once

#include <osmocom/hnbgw/hnbgw.h>

int hnbgw_cnlink_init(struct hnb_gw *gw, const char *stp_host, uint16_t stp_port, const char *local_ip);

const struct osmo_sccp_addr *hnbgw_cn_get_remote_addr(struct hnb_gw *gw, bool is_ps);
