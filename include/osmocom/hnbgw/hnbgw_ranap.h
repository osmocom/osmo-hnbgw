#pragma once

#include <osmocom/hnbgw/hnbgw.h>

int hnbgw_ranap_rx_udt_ul(struct msgb *msg, uint8_t *data, size_t len);
int hnbgw_ranap_init(void);
