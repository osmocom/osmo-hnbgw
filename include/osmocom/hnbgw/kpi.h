#pragma once

#include <osmocom/ranap/ranap_ies_defs.h>

#include <osmocom/hnbgw/hnbgw.h>

void kpi_ranap_process_ul(struct hnbgw_context_map *map, ranap_message *ranap);
void kpi_ranap_process_dl(struct hnbgw_context_map *map, ranap_message *ranap);
