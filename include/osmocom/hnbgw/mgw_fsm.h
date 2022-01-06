#pragma once

#include <osmocom/ranap/ranap_ies_defs.h>

int mgw_fsm_alloc_and_handle_rab_ass_req(struct hnbgw_context_map *map, ranap_message *message);
int mgw_fsm_handle_rab_ass_resp(struct hnbgw_context_map *map, struct osmo_prim_hdr *oph, ranap_message *message);
int mgw_fsm_release(struct hnbgw_context_map *map);
