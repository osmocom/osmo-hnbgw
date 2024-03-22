#pragma once
#include <stdint.h>
#include <stdbool.h>

struct hnb_persistent;

struct nft_kpi_val {
	uint64_t packets;
	uint64_t bytes;

	bool handle_present;
	int64_t handle;
};

int hnb_nft_kpi_start(struct hnb_persistent *hnbp);
int hnb_nft_kpi_end(struct hnb_persistent *hnbp);

void nft_kpi_read_counters(void);
