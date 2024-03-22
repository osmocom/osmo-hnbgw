#pragma once
#include <stdint.h>

struct hnb_persistent;

struct nft_kpi_val {
	uint64_t packets;
	uint64_t bytes;
};

int hnb_nft_kpi_start(struct hnb_persistent *hnbp);
int hnb_nft_kpi_end(struct hnb_persistent *hnbp);

const char *nft_kpi_read_counters(void);
