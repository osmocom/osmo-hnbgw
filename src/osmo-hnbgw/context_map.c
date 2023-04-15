/* Mapper between RUA ContextID (24 bit, per HNB) and the SUA/SCCP
 * Connection ID (32bit, per signalling link) */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

/* an expired mapping is destroyed  after 1..2 * EXPIRY_TIMER_SECS */
#define EXPIRY_TIMER_SECS	23

#include <osmocom/core/timer.h>

#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/mgw_fsm.h>
#include <osmocom/hnbgw/ps_rab_ass_fsm.h>

const struct value_string hnbgw_context_map_state_names[] = {
	{ MAP_S_CONNECTING, "connecting" },
	{ MAP_S_ACTIVE, "active" },
	{ MAP_S_DISCONNECTING, "disconnecting" },
	{}
};

/* Combine the RUA and SCCP states, for VTY reporting only. */
enum hnbgw_context_map_state context_map_get_state(struct hnbgw_context_map *map)
{
	enum hnbgw_context_map_state rua = map_rua_get_state(map);
	enum hnbgw_context_map_state sccp = map_sccp_get_state(map);
	if (rua == MAP_S_ACTIVE && sccp == MAP_S_ACTIVE)
		return MAP_S_ACTIVE;
	if (rua == MAP_S_DISCONNECTING || sccp == MAP_S_DISCONNECTING)
		return MAP_S_DISCONNECTING;
	return MAP_S_CONNECTING;
}

/* Map from a HNB + ContextID to the SCCP-side Connection ID */
struct hnbgw_context_map *context_map_find_or_create_by_rua_ctx_id(struct hnb_context *hnb, uint32_t rua_ctx_id,
								   bool is_ps)
{
	struct hnbgw_context_map *map;
	int new_scu_conn_id;
	struct hnbgw_cnlink *cnlink;
	struct hnbgw_sccp_inst *hsi;

	llist_for_each_entry(map, &hnb->map_list, hnb_list) {
		if (map->is_ps != is_ps)
			continue;

		/* Matching on RUA context id -- only match for RUA context that has not been disconnected yet. If an
		 * inactive context map for a rua_ctx_id is still around, we may have two entries for the same
		 * rua_ctx_id around at the same time. That should only stay until its SCCP side is done releasing. */
		if (!map_rua_is_active(map))
			continue;

		if (map->rua_ctx_id != rua_ctx_id)
			continue;

		/* Already exists */
		return map;
	}

	/* Does not exist yet, create a new hnbgw_context_map. */

	/* From the RANAP/RUA input, determine which cnlink to use */
	cnlink = hnbgw_cnlink_select(is_ps);
	if (!cnlink) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Failed to select CN link\n");
		return NULL;
	}

	/* Allocate new SCCP conn id on the SCCP instance the cnlink is on. */
	hsi = cnlink->hnbgw_sccp_inst;
	if (!hsi) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Cannot allocate context map: No SCCP instance for CN link %s\n",
		       cnlink->name);
		return NULL;
	}

	new_scu_conn_id = osmo_sccp_instance_next_conn_id(hsi->sccp);
	if (new_scu_conn_id < 0) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Unable to allocate SCCP conn ID on %s\n", hsi->name);
		return NULL;
	}

	/* allocate a new map entry. */
	map = talloc_zero(hnb, struct hnbgw_context_map);
	map->cnlink = cnlink;
	map->hnb_ctx = hnb;
	map->rua_ctx_id = rua_ctx_id;
	map->is_ps = is_ps;
	map->scu_conn_id = new_scu_conn_id;
	INIT_LLIST_HEAD(&map->ps_rab_ass);
	INIT_LLIST_HEAD(&map->ps_rabs);

	map_rua_fsm_alloc(map);
	map_sccp_fsm_alloc(map);

	llist_add_tail(&map->hnb_list, &hnb->map_list);
	llist_add_tail(&map->hnbgw_cnlink_entry, &cnlink->map_list);
	hash_add(hsi->hnbgw_context_map_by_conn_id, &map->hnbgw_sccp_inst_entry, new_scu_conn_id);

	LOG_MAP(map, DMAIN, LOGL_INFO, "Creating new Mapping RUA CTX %u <-> SCU Conn ID %s/%u\n",
		rua_ctx_id, hsi->name, new_scu_conn_id);

	return map;
}

int _map_rua_dispatch(struct hnbgw_context_map *map, uint32_t event, struct msgb *ranap_msg,
		      const char *file, int line)
{
	OSMO_ASSERT(map);
	if (!map->rua_fi) {
		LOG_MAP(map, DRUA, LOGL_ERROR, "not ready to receive RUA events\n");
		return -EINVAL;
	}
	return _osmo_fsm_inst_dispatch(map->rua_fi, event, ranap_msg, file, line);
}

int _map_sccp_dispatch(struct hnbgw_context_map *map, uint32_t event, struct msgb *ranap_msg,
		       const char *file, int line)
{
	OSMO_ASSERT(map);
	if (!map->sccp_fi) {
		LOG_MAP(map, DRUA, LOGL_ERROR, "not ready to receive SCCP events\n");
		return -EINVAL;
	}
	return _osmo_fsm_inst_dispatch(map->sccp_fi, event, ranap_msg, file, line);
}

unsigned int msg_has_l2_data(const struct msgb *msg)
{
	return msg && msgb_l2(msg) ? msgb_l2len(msg) : 0;
}

void context_map_hnb_released(struct hnbgw_context_map *map)
{
	/* When a HNB disconnects from RUA, the hnb_context will be freed. This hnbgw_context_map was allocated as a
	 * child of the hnb_context and would also be deallocated along with the hnb_context. However, the SCCP side for
	 * this hnbgw_context_map may still be waiting for a graceful release (SCCP RLC). Move this hnbgw_context_map to
	 * the global hnb_gw talloc ctx, so it can stay around for graceful release / for SCCP timeout.
	 *
	 * We could also always allocate hnbgw_context_map under hnb_gw, but it is nice to see which hnb_context owns
	 * which hnbgw_context_map in a talloc report.
	 */
	talloc_steal(g_hnbgw, map);

	/* Tell RUA that the HNB is gone. SCCP release will follow via FSM events. */
	map_rua_dispatch(map, MAP_RUA_EV_HNB_LINK_LOST, NULL);
}

void context_map_free(struct hnbgw_context_map *map)
{
	/* guard against FSM termination infinitely looping back here */
	if (map->deallocating) {
		LOG_MAP(map, DMAIN, LOGL_DEBUG, "context_map_free(): already deallocating\n");
		return;
	}
	map->deallocating = true;

	if (map->rua_fi)
		osmo_fsm_inst_term(map->rua_fi, OSMO_FSM_TERM_REGULAR, NULL);
	OSMO_ASSERT(map->rua_fi == NULL);

	if (map->sccp_fi)
		osmo_fsm_inst_term(map->sccp_fi, OSMO_FSM_TERM_REGULAR, NULL);
	OSMO_ASSERT(map->sccp_fi == NULL);

	if (map->mgw_fi) {
		mgw_fsm_release(map);
		OSMO_ASSERT(map->mgw_fi == NULL);
	}

#if ENABLE_PFCP
	hnbgw_gtpmap_release(map);
#endif

	if (map->cnlink) {
		llist_del(&map->hnbgw_cnlink_entry);
		hash_del(&map->hnbgw_sccp_inst_entry);
	}
	if (map->hnb_ctx)
		llist_del(&map->hnb_list);

	LOG_MAP(map, DMAIN, LOGL_INFO, "Deallocating\n");
	talloc_free(map);
}

void context_map_check_released(struct hnbgw_context_map *map)
{
	if (map_rua_is_active(map) || map_sccp_is_active(map)) {
		/* still active, do not release yet. */
		return;
	}
	context_map_free(map);
}
