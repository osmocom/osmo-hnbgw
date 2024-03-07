#pragma once

#include <osmocom/ranap/ranap_ies_defs.h>

int handle_cs_rab_ass_req(struct hnbgw_context_map *map, struct msgb *ranap_msg, ranap_message *message);
int mgw_fsm_handle_cs_rab_ass_resp(struct hnbgw_context_map *map, struct msgb *ranap_msg, ranap_message *message);
int mgw_fsm_release(struct hnbgw_context_map *map);

uint64_t mgw_fsm_get_elapsed_ms(struct hnbgw_context_map *map, const struct timespec *now);
