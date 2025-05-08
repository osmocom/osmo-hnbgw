/* SCCP, ITU Q.711 - Q.714 */
#pragma once

#include <stdint.h>

#include <osmocom/core/hashtable.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/use_count.h>

#include <osmocom/sigtran/sccp_sap.h>

struct hnbgw_cnlink;

/* osmo-hnbgw keeps a single hnbgw_sccp_user per osmo_sccp_instance, for the local point-code and SSN == RANAP.
 * This relates the (opaque) osmo_sccp_user to osmo-hnbgw's per-ss7 state. */
struct hnbgw_sccp_user {
	/* entry in g_hnbgw->sccp.users */
	struct llist_head entry;

	/* logging context */
	char *name;

	/* Which 'cs7 instance' is this for? Below sccp_user is registered at the osmo_sccp_instance ss7->sccp. */
	struct osmo_ss7_instance *ss7;

	/* Local address: cs7 instance's primary PC if present, else the default HNBGW PC; with SSN == RANAP. */
	struct osmo_sccp_addr local_addr;

	/* osmo_sccp API state for above local address on above ss7 instance. */
	struct osmo_sccp_user *sccp_user;

	/* Ref count of users of this struct, ie.referencing it in cnlink->hnbgw_sccp_user */
	struct osmo_use_count use_count;

	/* Fast access to the hnbgw_context_map responsible for a given SCCP conn_id of the ss7->sccp instance.
	 * hlist_node: hnbgw_context_map->hnbgw_sccp_user_entry. */
	DECLARE_HASHTABLE(hnbgw_context_map_by_conn_id, 6);
};

#define LOG_HSU(HSU, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (HSU) ? (HSU)->name : "null", ##ARGS)

#define HSU_USE_CNLINK "cnlink"
#define hnbgw_sccp_user_get(hsu, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&(hsu)->use_count, use, 1) == 0)
#define hnbgw_sccp_user_put(hsu, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&(hsu)->use_count, use, -1) == 0)

struct hnbgw_sccp_user *hnbgw_sccp_user_alloc(int ss7_inst_id);

int hnbgw_sccp_user_tx_unitdata_req(struct hnbgw_sccp_user *hsu, const struct osmo_sccp_addr *called_addr,
				    struct msgb *ranap_msg);
int hnbgw_sccp_user_tx_connect_req(struct hnbgw_sccp_user *hsu, const struct osmo_sccp_addr *called_addr,
				   uint32_t scu_conn_id, struct msgb *ranap_msg);
int hnbgw_sccp_user_tx_data_req(struct hnbgw_sccp_user *hsu, uint32_t scu_conn_id,
				struct msgb *ranap_msg);
int hnbgw_sccp_user_tx_disconnect_req(struct hnbgw_sccp_user *hsu, uint32_t scu_conn_id);

static inline struct osmo_sccp_instance *hnbgw_sccp_user_get_sccp_instance(const struct hnbgw_sccp_user *hsu)
{
	if (!hsu->ss7)
		return NULL;
	return osmo_ss7_get_sccp(hsu->ss7);
}
