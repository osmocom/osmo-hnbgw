#pragma once
#include <stdint.h>
#include <stdbool.h>

struct hnb_persistent;

struct nft_kpi_val {
	uint64_t packets;
	uint64_t total_bytes;
	uint64_t ue_bytes;

	bool handle_present;
	int64_t handle;
};

int nft_kpi_init(const char *table_name);
int hnb_nft_kpi_start(struct hnb_persistent *hnbp, const struct osmo_sockaddr_str *gtpu_remote);
int hnb_nft_kpi_end(struct hnb_persistent *hnbp);
