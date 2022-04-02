#pragma once

#include <osmocom/ranap/ranap_ies_defs.h>

enum ps_rab_ass_fsm_event {
	PS_RAB_ASS_EV_LOCAL_F_TEIDS_RX,
	PS_RAB_ASS_EV_RAB_ASS_RESP,
	PS_RAB_ASS_EV_RAB_ESTABLISHED,
	PS_RAB_ASS_EV_RAB_FAIL,
};

int hnbgw_gtpmap_rx_rab_ass_req(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message);
int hnbgw_gtpmap_rx_rab_ass_resp(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message);
void hnbgw_gtpmap_release(struct hnbgw_context_map *map);
