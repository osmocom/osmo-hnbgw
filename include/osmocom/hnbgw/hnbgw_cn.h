#pragma once

#include <osmocom/hnbgw/hnbgw.h>

int hnbgw_cnlink_init(const char *stp_host, uint16_t stp_port, const char *local_ip);

const struct osmo_sccp_addr *hnbgw_cn_get_remote_addr(bool is_ps);
