#pragma once

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/rua/RUA_Cause.h>
#include <osmocom/rua/RUA_CN-DomainIndicator.h>

int hnbgw_rua_rx(struct hnb_context *hnb, struct msgb *msg);
int hnbgw_rua_init(void);

int rua_tx_udt(struct hnb_context *hnb, const uint8_t *data, unsigned int len);
int rua_tx_dt(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	      const uint8_t *data, unsigned int len);
int rua_tx_disc(struct hnb_context *hnb, int is_ps, uint32_t context_id,
	        const RUA_Cause_t *cause, const uint8_t *data, unsigned int len);

int rua_to_scu(struct hnb_context *hnb,
	       RUA_CN_DomainIndicator_t cN_DomainIndicator,
	       enum osmo_scu_prim_type type,
	       uint32_t context_id, uint32_t cause,
	       const uint8_t *data, unsigned int len);
