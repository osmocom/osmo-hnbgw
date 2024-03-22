#pragma once
#include <stdint.h>
#include <stdbool.h>

struct hnb_persistent;

/* A "handle" that nftables returns for chains and rules -- a plain number. Deleting an unnamed rule can only be done by
 * such a handle. */
struct nft_kpi_handle {
	bool handle_present;
	int64_t handle;
};

/* One GTP-U packet and byte counter cache, i.e. for one UL/DL direction of one hNodeB. */
struct nft_kpi_val {
	uint64_t packets;
	uint64_t total_bytes;
	uint64_t ue_bytes;
};

void nft_kpi_init(const char *table_name);
void nft_kpi_hnb_persistent_add(struct hnb_persistent *hnbp);
void nft_kpi_hnb_persistent_remove(struct hnb_persistent *hnbp);
int nft_kpi_hnb_start(struct hnb_persistent *hnbp, const struct osmo_sockaddr_str *gtpu_remote);
void nft_kpi_hnb_stop(struct hnb_persistent *hnbp);
