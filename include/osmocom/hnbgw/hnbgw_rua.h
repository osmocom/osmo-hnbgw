/* RUA, 3GPP TS 25.468 */
#pragma once

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/rua/RUA_Cause.h>
#include <osmocom/ranap/ranap_ies_defs.h>

int hnbgw_rua_rx(struct hnb_context *hnb, struct msgb *msg);

int rua_tx_udt(struct hnb_context *hnb, const uint8_t *data, unsigned int len);
int rua_tx_dt(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	      const uint8_t *data, unsigned int len);
int rua_tx_disc(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	        const RUA_Cause_t *cause, const uint8_t *data, unsigned int len);

ranap_message *hnbgw_decode_ranap_co(struct msgb *ranap_msg);
