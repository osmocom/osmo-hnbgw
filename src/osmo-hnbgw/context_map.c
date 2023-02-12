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

/* is a given SCCP USER SAP Connection ID in use for a given CN link? */
static int cn_id_in_use(struct hnbgw_cnlink *cn, uint32_t id)
{
	struct hnbgw_context_map *map;

	llist_for_each_entry(map, &cn->map_list, cn_list) {
		if (map->scu_conn_id == id)
			return 1;
	}
	return 0;
}

/* try to allocate a new SCCP User SAP Connection ID */
static int alloc_cn_conn_id(struct hnbgw_cnlink *cn, uint32_t *id_out)
{
	uint32_t i;
	uint32_t id;

	/* SUA: RFC3868 sec 3.10.4:
	 *    The source reference number is a 4 octet long integer.
	 *    This is allocated by the source SUA instance.
	 * M3UA/SCCP: ITU-T Q.713 sec 3.3:
	 *    The "source local reference" parameter field is a three-octet field containing a
	 *    reference number which is generated and used by the local node to identify the
	 *    connection section after the connection section is set up.
	 *    The coding "all ones" is reserved for future use.
	 * Hence, let's simply use 24 bit ids to fit all link types (excluding 0x00ffffff).
	 */

	for (i = 0; i < 0x00ffffff; i++) {
		id = cn->next_conn_id++;
		if (cn->next_conn_id == 0x00ffffff)
			cn->next_conn_id = 0;
		if (!cn_id_in_use(cn, id)) {
			*id_out = id;
			return 1;
		}
	}
	return -1;
}

/* Map from a HNB + ContextID to the SCCP-side Connection ID */
struct hnbgw_context_map *
context_map_alloc_by_hnb(struct hnb_context *hnb, uint32_t rua_ctx_id,
			 bool is_ps,
			 struct hnbgw_cnlink *cn_if_new)
{
	struct hnbgw_context_map *map;
	uint32_t new_scu_conn_id;

	llist_for_each_entry(map, &hnb->map_list, hnb_list) {
		if (map->cn_link != cn_if_new)
			continue;

		/* Matching on RUA context id -- only match for RUA context that has not been disconnected yet. If an
		 * inactive context map for a rua_ctx_id is still around, we may have two entries for the same
		 * rua_ctx_id around at the same time. That should only stay until its SCCP side is done releasing. */
		if (!map_rua_is_active(map))
			continue;

		if (map->rua_ctx_id == rua_ctx_id
		    && map->is_ps == is_ps) {
			return map;
		}
	}

	if (alloc_cn_conn_id(cn_if_new, &new_scu_conn_id) < 0) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Unable to allocate CN connection ID\n");
		return NULL;
	}

	LOGHNB(hnb, DMAIN, LOGL_INFO, "Creating new Mapping RUA CTX %p/%u <-> SCU Conn ID %p/%u\n",
		hnb, rua_ctx_id, cn_if_new, new_scu_conn_id);

	/* allocate a new map entry. */
	map = talloc_zero(hnb, struct hnbgw_context_map);
	map->gw = hnb->gw;
	map->cn_link = cn_if_new;
	map->hnb_ctx = hnb;
	map->rua_ctx_id = rua_ctx_id;
	map->is_ps = is_ps;
	map->scu_conn_id = new_scu_conn_id;
	INIT_LLIST_HEAD(&map->ps_rab_ass);
	INIT_LLIST_HEAD(&map->ps_rabs);

	map_rua_fsm_alloc(map);
	map_sccp_fsm_alloc(map);

	/* put it into both lists */
	llist_add_tail(&map->hnb_list, &hnb->map_list);
	llist_add_tail(&map->cn_list, &cn_if_new->map_list);

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

/* Map from a CN + Connection ID to HNB + Context ID */
struct hnbgw_context_map *
context_map_by_cn(struct hnbgw_cnlink *cn, uint32_t scu_conn_id)
{
	struct hnbgw_context_map *map;

	llist_for_each_entry(map, &cn->map_list, cn_list) {
		/* Matching on SCCP conn id -- only match for SCCP conn that has not been disconnected yet. If an
		 * inactive context map for an scu_conn_id is still around, we may have two entries for the same
		 * scu_conn_id around at the same time. That should only stay until its RUA side is done releasing. */
		if (!map_sccp_is_active(map))
			continue;

		if (map->scu_conn_id == scu_conn_id) {
			return map;
		}
	}
	/* we don't allocate new mappings in the CN->HNB
	 * direction, as the RUA=SCCP=SUA connections are always
	 * established from HNB towards CN. */
	LOGP(DMAIN, LOGL_NOTICE, "Unable to resolve map for CN " "connection ID %p/%u\n", cn, scu_conn_id);
	return NULL;
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
	talloc_steal(map->gw, map);

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

	if (map->cn_link)
		llist_del(&map->cn_list);
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
