/* HNBAP, 3GPP TS 25.469 */
#pragma once

#include <osmocom/hnbgw/hnbgw.h>

struct hnb_context;

int hnbgw_hnbap_rx(struct hnb_context *hnb, struct msgb *msg);
int hnbgw_hnbap_init(void);
