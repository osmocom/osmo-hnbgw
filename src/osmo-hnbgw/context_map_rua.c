/* RUA side FSM of hnbgw_context_map */
/* (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Neels Hofmeyr
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
 */
#include "config.h"

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/hnbgw_ranap.h>

enum map_rua_fsm_state {
	MAP_RUA_ST_INIT,
	MAP_RUA_ST_CONNECTED,
	MAP_RUA_ST_DISCONNECTED,
	MAP_RUA_ST_DISRUPTED,
};

static const struct value_string map_rua_fsm_event_names[] = {
	OSMO_VALUE_STRING(MAP_RUA_EV_RX_CONNECT),
	OSMO_VALUE_STRING(MAP_RUA_EV_RX_DIRECT_TRANSFER),
	OSMO_VALUE_STRING(MAP_RUA_EV_RX_DISCONNECT),
	OSMO_VALUE_STRING(MAP_RUA_EV_TX_DIRECT_TRANSFER),
	OSMO_VALUE_STRING(MAP_RUA_EV_CN_DISC),
	OSMO_VALUE_STRING(MAP_RUA_EV_HNB_LINK_LOST),
	{}
};

static struct osmo_fsm map_rua_fsm;

static const struct osmo_tdef_state_timeout map_rua_fsm_timeouts[32] = {
	[MAP_RUA_ST_INIT] = { .T = -31 },
	[MAP_RUA_ST_DISCONNECTED] = { .T = -31 },
	[MAP_RUA_ST_DISRUPTED] = { .T = -31 },
};

/* Transition to a state, using the T timer defined in map_rua_fsm_timeouts.
 * Assumes local variable fi exists. */
#define map_rua_fsm_state_chg(state) \
       OSMO_ASSERT(osmo_tdef_fsm_inst_state_chg(fi, state, \
						map_rua_fsm_timeouts, \
						hnbgw_T_defs, \
						5) == 0)

void map_rua_fsm_alloc(struct hnbgw_context_map *map)
{
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc(&map_rua_fsm, map, map, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	osmo_fsm_inst_update_id_f_sanitize(fi, '-', "%s-%s-RUA-%u", hnb_context_name(map->hnb_ctx),
					   map->is_ps ? "PS" : "CS", map->rua_ctx_id);

	OSMO_ASSERT(map->rua_fi == NULL);
	map->rua_fi = fi;

	/* trigger the timeout */
	map_rua_fsm_state_chg(MAP_RUA_ST_INIT);
}

enum hnbgw_context_map_state map_rua_get_state(struct hnbgw_context_map *map)
{
	if (!map || !map->rua_fi)
		return MAP_S_DISCONNECTING;
	switch (map->rua_fi->state) {
	case MAP_RUA_ST_INIT:
		return MAP_S_CONNECTING;
	case MAP_RUA_ST_CONNECTED:
		return MAP_S_ACTIVE;
	default:
	case MAP_RUA_ST_DISCONNECTED:
	case MAP_RUA_ST_DISRUPTED:
		return MAP_S_DISCONNECTING;
	}
}

bool map_rua_is_active(struct hnbgw_context_map *map)
{
	if (!map || !map->rua_fi)
		return false;
	switch (map->rua_fi->state) {
	case MAP_RUA_ST_DISCONNECTED:
	case MAP_RUA_ST_DISRUPTED:
		return false;
	default:
		return true;
	}
}

static int map_rua_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	switch (fi->state) {
	default:
		map_rua_fsm_state_chg(MAP_RUA_ST_DISRUPTED);
		return 0;

	case MAP_RUA_ST_DISCONNECTED:
	case MAP_RUA_ST_DISRUPTED:
		return 1;
	}
}

/* Dispatch RANAP message to SCCP, if any. */
static int handle_rx_rua(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;

	/* If the FSM instance has already terminated, don't dispatch anything. */
	if (fi->proc.terminating)
		return 0;

	if (!msg_has_l2_data(ranap_msg))
		return 0;

	return hnbgw_ranap_rx_data_ul(map, ranap_msg);
}

static int forward_ranap_to_rua(struct hnbgw_context_map *map, struct msgb *ranap_msg)
{
	int rc;

	if (!msg_has_l2_data(ranap_msg))
		return 0;

	if (!map->hnb_ctx) {
		LOGPFSML(map->rua_fi, LOGL_ERROR, "Cannot transmit RUA DirectTransfer: HNB has disconnected\n");
		return -ENOTCONN;
	}

	rc = rua_tx_dt(map->hnb_ctx, map->is_ps, map->rua_ctx_id, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));
	if (rc)
		LOGPFSML(map->rua_fi, LOGL_ERROR, "Failed to transmit RUA DirectTransfer to HNB\n");
	return rc;
}

static void map_rua_init_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_RUA_EV_RX_CONNECT:
		/* not needed for RAB assignment scanning, but for KPI scanning */
		handle_rx_rua(fi, ranap_msg);
		map_rua_fsm_state_chg(MAP_RUA_ST_CONNECTED);
		return;

	case MAP_RUA_EV_RX_DISCONNECT:
		/* Unlikely that SCCP is active, but let the SCCP FSM decide about that. */
		handle_rx_rua(fi, ranap_msg);
		/* There is a reason to shut down this RUA connection. Super unlikely, we haven't even processed the
		 * MAP_RUA_EV_RX_CONNECT that created this FSM. Semantically, RUA is not connected, so we can
		 * directly go to MAP_RUA_ST_DISCONNECTED. */
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
		break;

	case MAP_RUA_EV_CN_DISC:
	case MAP_RUA_EV_HNB_LINK_LOST:
		map_rua_fsm_state_chg(MAP_RUA_ST_DISRUPTED);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_rua_tx_disconnect(struct osmo_fsm_inst *fi)
{
	struct hnbgw_context_map *map = fi->priv;
	RUA_Cause_t rua_cause;

	if (!map->hnb_ctx || !map->hnb_ctx->conn) {
		/* HNB already disconnected, nothing to do. */
		LOGPFSML(fi, LOGL_NOTICE, "HNB vanished, this RUA context cannot disconnect gracefully\n");
		return;
	}

	/* Send Disconnect to RUA without RANAP data. */
	rua_cause = (RUA_Cause_t){
		.present = RUA_Cause_PR_radioNetwork,
		.choice.radioNetwork = RUA_CauseRadioNetwork_network_release,
	};
	LOGPFSML(fi, LOGL_INFO, "Tx RUA Disconnect\n");
	if (rua_tx_disc(map->hnb_ctx, map->is_ps, map->rua_ctx_id, &rua_cause, NULL, 0))
		LOGPFSML(fi, LOGL_ERROR, "Failed to send Disconnect to RUA\n");
}

static void map_rua_connected_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_RUA_EV_RX_DIRECT_TRANSFER:
		/* received DirectTransfer from RUA, forward to SCCP */
		handle_rx_rua(fi, ranap_msg);
		return;

	case MAP_RUA_EV_TX_DIRECT_TRANSFER:
		/* Someone (usually the SCCP side) wants us to send a RANAP payload to HNB via RUA */
		forward_ranap_to_rua(map, ranap_msg);
		return;

	case MAP_RUA_EV_RX_DISCONNECT:
		/* 3GPP TS 25.468 9.1.5: RUA has disconnected.
		 * - Under normal conditions (cause=Normal) the RUA Disconnect contains a RANAP Iu-ReleaseComplete.
		 *   On SCCP, the Iu-ReleaseComplete should still be forwarded as N-Data SCCP Data Form 1),
		 *   and we will expect the CN to send an SCCP RLSD soon.
		 * - Under error conditions, cause!=Normal and there's no RANAP message.
		 *   In that case, we need to tear down the associated SCCP link towards CN,
		 *   which in turn will tear down the upper layer Iu conn.
		 */
		if (msg_has_l2_data(ranap_msg)) {
			/* Forward any payload to SCCP before Disconnect. */
			handle_rx_rua(fi, ranap_msg);
		} else {
			map->rua_fi_ctx.rua_disconnect_err_condition = true;
		}
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
		return;

	case MAP_RUA_EV_HNB_LINK_LOST:
		/* The HNB is gone. Cannot gracefully cleanup the RUA connection, just be gone. */
		map_rua_fsm_state_chg(MAP_RUA_ST_DISRUPTED);
		return;

	case MAP_RUA_EV_CN_DISC:
		/* There is a disruptive reason to shut down this RUA connection, HNB is still there */
		OSMO_ASSERT(data == NULL);
		map_rua_tx_disconnect(fi);
		map_rua_fsm_state_chg(MAP_RUA_ST_DISRUPTED);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_rua_free_if_done(struct hnbgw_context_map *map, uint32_t sccp_event, void *ev_data)
{
	/* From RUA's POV, we can now free the hnbgw_context_map.
	 * If SCCP is still active, tell it to disconnect -- in that case the SCCP side will call context_map_free().
	 * If SCCP is no longer active, free this map. */
	if (map_sccp_is_active(map))
		map_sccp_dispatch(map, sccp_event, ev_data);
	else
		context_map_free(map);
}

static void map_rua_disconnected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	map_rua_free_if_done(map, MAP_SCCP_EV_RAN_DISC, (void *)map->rua_fi_ctx.rua_disconnect_err_condition);
}

static void map_rua_disconnected_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg;

	switch (event) {

	case MAP_RUA_EV_TX_DIRECT_TRANSFER:
		/* This can happen if CN is buggy, or in general if there was a race
		 * condition between us forwarding the release towards CN (SCCP Release
		 * or RANAP Iu-ReleaseComplete) and CN sendig whatever to us. */
		ranap_msg = data;
		if (msg_has_l2_data(ranap_msg)) {
			LOGPFSML(fi, LOGL_NOTICE, "RUA already disconnected, skip forwarding DL RANAP msg (%u bytes)\n",
				 msgb_l2len(ranap_msg));
			LOGPFSML(fi, LOGL_DEBUG, "%s\n", osmo_hexdump(msgb_l2(ranap_msg), msgb_l2len(ranap_msg)));
		}
		break;

	case MAP_RUA_EV_CN_DISC:
	case MAP_RUA_EV_HNB_LINK_LOST:
		/* Ignore events. */
		break;
	}
}

static void map_rua_disrupted_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	map_rua_free_if_done(map, MAP_SCCP_EV_RAN_LINK_LOST, NULL);
}

void map_rua_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct hnbgw_context_map *map = fi->priv;
	map->rua_fi = NULL;
}

#define S(x) (1 << (x))

static const struct osmo_fsm_state map_rua_fsm_states[] = {
	[MAP_RUA_ST_INIT] = {
		.name = "init",
		.in_event_mask = 0
			| S(MAP_RUA_EV_RX_CONNECT)
			| S(MAP_RUA_EV_RX_DISCONNECT)
			| S(MAP_RUA_EV_CN_DISC)
			| S(MAP_RUA_EV_HNB_LINK_LOST)
			,
		.out_state_mask = 0
			| S(MAP_RUA_ST_INIT)
			| S(MAP_RUA_ST_CONNECTED)
			| S(MAP_RUA_ST_DISCONNECTED)
			| S(MAP_RUA_ST_DISRUPTED)
			,
		.action = map_rua_init_action,
	},
	[MAP_RUA_ST_CONNECTED] = {
		.name = "connected",
		.in_event_mask = 0
			| S(MAP_RUA_EV_RX_DIRECT_TRANSFER)
			| S(MAP_RUA_EV_TX_DIRECT_TRANSFER)
			| S(MAP_RUA_EV_RX_DISCONNECT)
			| S(MAP_RUA_EV_CN_DISC)
			| S(MAP_RUA_EV_HNB_LINK_LOST)
			,
		.out_state_mask = 0
			| S(MAP_RUA_ST_DISCONNECTED)
			| S(MAP_RUA_ST_DISRUPTED)
			,
		.action = map_rua_connected_action,
	},
	[MAP_RUA_ST_DISCONNECTED] = {
		.name = "disconnected",
		.in_event_mask = 0
			| S(MAP_RUA_EV_TX_DIRECT_TRANSFER)
			| S(MAP_RUA_EV_CN_DISC)
			| S(MAP_RUA_EV_HNB_LINK_LOST)
			,
		.onenter = map_rua_disconnected_onenter,
		.action = map_rua_disconnected_action,
	},
	[MAP_RUA_ST_DISRUPTED] = {
		.name = "disrupted",
		.in_event_mask = 0
			| S(MAP_RUA_EV_CN_DISC)
			| S(MAP_RUA_EV_HNB_LINK_LOST)
			,
		.onenter = map_rua_disrupted_onenter,
		/* same as MAP_RUA_ST_DISCONNECTED: */
		.action = map_rua_disconnected_action,
	},
};

static struct osmo_fsm map_rua_fsm = {
	.name = "map_rua",
	.states = map_rua_fsm_states,
	.num_states = ARRAY_SIZE(map_rua_fsm_states),
	.log_subsys = DHNB,
	.event_names = map_rua_fsm_event_names,
	.timer_cb = map_rua_fsm_timer_cb,
	.cleanup = map_rua_fsm_cleanup,
};

static __attribute__((constructor)) void map_rua_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&map_rua_fsm) == 0);
}
