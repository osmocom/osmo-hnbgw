/* SCCP, ITU Q.711 - Q.714 */
#pragma once

#include <osmocom/core/hashtable.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/prim.h>

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

	/* Fast access to the hnbgw_context_map responsible for a given SCCP conn_id of the ss7->sccp instance.
	 * hlist_node: hnbgw_context_map->hnbgw_sccp_user_entry. */
	DECLARE_HASHTABLE(hnbgw_context_map_by_conn_id, 6);
};

#define LOG_HSI(HNBGW_SCCP_INST, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "(%s) " FMT, (HNBGW_SCCP_INST) ? (HNBGW_SCCP_INST)->name : "null", ##ARGS)

struct hnbgw_sccp_user *hnbgw_sccp_user_alloc(const struct hnbgw_cnlink *cnlink, int ss7_inst_id);
