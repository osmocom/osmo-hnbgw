/* RANAP, 3GPP TS 25.413 */
#pragma once

#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/hnbgw/hnbgw.h>

struct osmo_scu_unitdata_param;

ranap_message *hnbgw_decode_ranap_cn_co(struct msgb *ranap_msg);

int hnbgw_ranap_rx_udt_ul(struct msgb *msg, uint8_t *data, size_t len);
int hnbgw_ranap_rx_data_ul(struct hnbgw_context_map *map, struct msgb *ranap_msg);

int hnbgw_ranap_rx_udt_dl(struct hnbgw_cnlink *cnlink, const struct osmo_scu_unitdata_param *unitdata,
			  const uint8_t *data, unsigned int len);
int hnbgw_ranap_rx_data_dl(struct hnbgw_context_map *map, struct msgb *ranap_msg);
int hnbgw_ranap_init(void);

