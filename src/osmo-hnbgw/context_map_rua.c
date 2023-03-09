/* RUA side FSM of hnbgw_context_map */
/* (C) 2023 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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

#include <osmocom/ranap/ranap_common_cn.h>

#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_cp_peer.h>
#endif

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/mgw_fsm.h>
#include <osmocom/hnbgw/ps_rab_ass_fsm.h>

enum map_rua_fsm_state {
	MAP_RUA_ST_INIT,
	MAP_RUA_ST_CONNECTED,
	MAP_RUA_ST_DISCONNECTED,
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
};

/* Transition to a state, using the T timer defined in map_rua_fsm_timeouts.
 * Assumes local variable fi exists. */
#define map_rua_fsm_state_chg(state) \
       OSMO_ASSERT(osmo_tdef_fsm_inst_state_chg(fi, state, \
						map_rua_fsm_timeouts, \
						cmap_T_defs, \
						5) == 0)

void map_rua_fsm_alloc(struct hnbgw_context_map *map)
{
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc(&map_rua_fsm, map, map, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	osmo_fsm_inst_update_id_f_sanitize(fi, '-', "%s-RUA-%u", hnb_context_name(map->hnb_ctx), map->rua_ctx_id);

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
		return MAP_S_DISCONNECTING;
	}
}

bool map_rua_is_active(struct hnbgw_context_map *map)
{
	if (!map || !map->rua_fi)
		return false;
	switch (map->rua_fi->state) {
	case MAP_RUA_ST_DISCONNECTED:
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
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
		return 0;

	case MAP_RUA_ST_DISCONNECTED:
		return 1;
	}
}

static int destruct_ranap_cn_rx_co_ies(ranap_message *ranap_message_p)
{
	ranap_cn_rx_co_free(ranap_message_p);
	return 0;
}

/* Dispatch RANAP message to SCCP, if any. */
static int handle_rx_rua(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;
	int rc;
	if (!msg_has_l2_data(ranap_msg))
		return 0;

	/* See if it is a RAB Assignment Response message from RUA to SCCP, where we need to change the user plane
	 * information, for RTP mapping via MGW, or GTP mapping via UPF. */
	if (!map->is_ps) {
		ranap_message *message = talloc_zero(OTC_SELECT, ranap_message);
		rc = ranap_cn_rx_co_decode2(message, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));
		if (rc == 0) {
			talloc_set_destructor(message, destruct_ranap_cn_rx_co_ies);

			LOGPFSML(fi, LOGL_DEBUG, "rx from RUA: RANAP %s\n",
				 get_value_string(ranap_procedure_code_vals, message->procedureCode));

			switch (message->procedureCode) {
			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* mgw_fsm_handle_rab_ass_resp() takes ownership of prim->oph and (ranap) message */
				return mgw_fsm_handle_rab_ass_resp(map, ranap_msg, message);
			}
		}
#if ENABLE_PFCP
	} else if (hnb_gw_is_gtp_mapping_enabled(map->gw)) {
		/* map->is_ps == true and PFCP is enabled in osmo-hnbgw.cfg */
		ranap_message *message = talloc_zero(OTC_SELECT, ranap_message);
		rc = ranap_cn_rx_co_decode2(message, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));
		if (rc == 0) {
			talloc_set_destructor(message, destruct_ranap_cn_rx_co_ies);

			LOGPFSML(fi, LOGL_DEBUG, "rx from RUA: RANAP %s\n",
				 get_value_string(ranap_procedure_code_vals, message->procedureCode));

			switch (message->procedureCode) {
			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* ps_rab_ass_fsm takes ownership of prim->oph and RANAP message */
				return hnbgw_gtpmap_rx_rab_ass_resp(map, ranap_msg, message);
			}
		}
#endif
	}

	/* It was not a RAB Assignment Response that needed to be intercepted. Forward as-is to SCCP. */
	return map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, ranap_msg);
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
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_RUA_EV_RX_CONNECT:
		map_rua_fsm_state_chg(MAP_RUA_ST_CONNECTED);
		/* The Connect will never be a RAB Assignment response, so no need for handle_rx_rua() (which decodes
		 * the RANAP message to detect a RAB Assignment response). Just forward to SCCP as is. */
		map_sccp_dispatch(map, MAP_SCCP_EV_TX_DATA_REQUEST, ranap_msg);
		return;

	case MAP_RUA_EV_RX_DISCONNECT:
	case MAP_RUA_EV_CN_DISC:
	case MAP_RUA_EV_HNB_LINK_LOST:
		/* Unlikely that SCCP is active, but let the SCCP FSM decide about that. */
		handle_rx_rua(fi, ranap_msg);
		/* There is a reason to shut down this RUA connection. Super unlikely, we haven't even processed the
		 * MAP_RUA_EV_RX_CONNECT that created this FSM. Semantically, RUA is not connected, so we can
		 * directly go to MAP_RUA_ST_DISCONNECTED. */
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
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
		/* received Disconnect from RUA. forward any payload to SCCP, and change state. */
		if (!map_sccp_is_active(map)) {
			/* If, unlikely, the SCCP is already gone, changing to MAP_RUA_ST_DISCONNECTED frees the
			 * hnbgw_context_map. Avoid a use-after-free. */
			map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
			return;
		}
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
		handle_rx_rua(fi, ranap_msg);
		return;

	case MAP_RUA_EV_HNB_LINK_LOST:
		/* The HNB is gone. Cannot gracefully cleanup the RUA connection, just be gone. */
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
		return;

	case MAP_RUA_EV_CN_DISC:
		/* There is a disruptive reason to shut down this RUA connection, HNB is still there */
		OSMO_ASSERT(data == NULL);
		map_rua_tx_disconnect(fi);
		map_rua_fsm_state_chg(MAP_RUA_ST_DISCONNECTED);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_rua_disconnected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	/* For sanity, always tell SCCP to disconnect, if it hasn't done so. Dispatching MAP_SCCP_EV_RAN_DISC may send
	 * SCCP into MAP_RUA_ST_DISCONNECTED, which calls context_map_check_released() and frees the hnbgw_context_map,
	 * so don't free it a second time. If SCCP stays active, calling context_map_check_released() has no effect. */
	if (map_sccp_is_active(map))
		map_sccp_dispatch(map, MAP_SCCP_EV_RAN_DISC, NULL);
	else
		context_map_check_released(map);
}

static void map_rua_disconnected_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg = data;
	if (msg_has_l2_data(ranap_msg))
		LOGPFSML(fi, LOGL_ERROR, "RUA not connected, cannot dispatch RANAP message\n");
}

void map_rua_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct hnbgw_context_map *map = fi->priv;
	map->rua_fi = NULL;
	context_map_check_released(map);
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
			,
		.action = map_rua_connected_action,
	},
	[MAP_RUA_ST_DISCONNECTED] = {
		.name = "disconnected",
		.in_event_mask = 0
			| S(MAP_RUA_EV_CN_DISC)
			| S(MAP_RUA_EV_HNB_LINK_LOST)
			,
		.onenter = map_rua_disconnected_onenter,
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
