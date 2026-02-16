/* SCCP side FSM of hnbgw_context_map */
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

#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/hnbgw/hnb.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/hnbgw_ranap.h>
#include <osmocom/hnbgw/tdefs.h>

enum map_sccp_fsm_state {
	MAP_SCCP_ST_INIT,
	MAP_SCCP_ST_WAIT_CC,
	MAP_SCCP_ST_CONNECTED,
	MAP_SCCP_ST_WAIT_RLSD,
	MAP_SCCP_ST_DISCONNECTED,
};

static const struct value_string map_sccp_fsm_event_names[] = {
	OSMO_VALUE_STRING(MAP_SCCP_EV_RX_CONNECTION_CONFIRM),
	OSMO_VALUE_STRING(MAP_SCCP_EV_RX_DATA_INDICATION),
	OSMO_VALUE_STRING(MAP_SCCP_EV_TX_DATA_REQUEST),
	OSMO_VALUE_STRING(MAP_SCCP_EV_RAN_DISC),
	OSMO_VALUE_STRING(MAP_SCCP_EV_RAN_LINK_LOST),
	OSMO_VALUE_STRING(MAP_SCCP_EV_RX_RELEASED),
	OSMO_VALUE_STRING(MAP_SCCP_EV_USER_ABORT),
	OSMO_VALUE_STRING(MAP_SCCP_EV_CN_LINK_LOST),
	OSMO_VALUE_STRING(MAP_SCCP_EV_MGCP_LINK_LOST),
	OSMO_VALUE_STRING(MAP_SCCP_EV_PFCP_LINK_LOST),
	{}
};

static struct osmo_fsm map_sccp_fsm;

static const struct osmo_tdef_state_timeout map_sccp_fsm_timeouts[32] = {
	[MAP_SCCP_ST_INIT] = { .T = -31 },
	[MAP_SCCP_ST_WAIT_CC] = { .T = -31 },
	[MAP_SCCP_ST_CONNECTED] = { .T = 0 },
	[MAP_SCCP_ST_WAIT_RLSD] = { .T = -31 },
	[MAP_SCCP_ST_DISCONNECTED] = { .T = -31 },
};

/* Transition to a state, using the T timer defined in map_sccp_fsm_timeouts.
 * Assumes local variable fi exists. */
#define map_sccp_fsm_state_chg(state) \
	OSMO_ASSERT(osmo_tdef_fsm_inst_state_chg(fi, state, \
						 map_sccp_fsm_timeouts, \
						 hnbgw_T_defs, \
						 5) == 0)

void map_sccp_fsm_alloc(struct hnbgw_context_map *map)
{
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc(&map_sccp_fsm, map, map, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	osmo_fsm_inst_update_id_f_sanitize(fi, '-', "%s-%s-SCCP-%u", hnb_context_name(map->hnb_ctx),
					   map->cnlink ? map->cnlink->name : (map->is_ps ? "PS" : "CS"),
					   map->scu_conn_id);

	OSMO_ASSERT(map->sccp_fi == NULL);
	map->sccp_fi = fi;
	INIT_LLIST_HEAD(&map->sccp_fi_ctx.wait_cc_tx_msg_list);
	/* trigger the timeout */
	map_sccp_fsm_state_chg(MAP_SCCP_ST_INIT);
}

enum hnbgw_context_map_state map_sccp_get_state(struct hnbgw_context_map *map)
{
	if (!map || !map->sccp_fi)
		return MAP_S_DISCONNECTING;
	switch (map->sccp_fi->state) {
	case MAP_SCCP_ST_INIT:
	case MAP_SCCP_ST_WAIT_CC:
		return MAP_S_CONNECTING;
	case MAP_SCCP_ST_CONNECTED:
		return MAP_S_ACTIVE;
	default:
	case MAP_SCCP_ST_WAIT_RLSD:
	case MAP_SCCP_ST_DISCONNECTED:
		return MAP_S_DISCONNECTING;
	}
}

bool map_sccp_is_active(struct hnbgw_context_map *map)
{
	if (!map || !map->sccp_fi)
		return false;
	switch (map->sccp_fi->state) {
	case MAP_SCCP_ST_DISCONNECTED:
		return false;
	default:
		return true;
	}
}

static int tx_sccp_cr(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;

	if (!map->cnlink) {
		LOGPFSML(fi, LOGL_ERROR, "Failed to send SCCP Connection Request: no CN link\n");
		return -1;
	}

	if (!ranap_msg) {
		/* prepare a msgb to send an empty N-Connect prim (but this should never happen in practice) */
		ranap_msg = hnbgw_ranap_msg_alloc("SCCP-CR-empty");
	}

	CNLINK_CTR_INC(map->cnlink, CNLINK_CTR_SCCP_N_CONNECT_REQ);
	return hnbgw_sccp_user_tx_connect_req(map->cnlink->hnbgw_sccp_user,
					      &map->cnlink->remote_addr,
					      map->scu_conn_id,
					      ranap_msg);
}

static int tx_sccp_df1(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;

	if (!msg_has_l2_data(ranap_msg))
		return 0;

	if (!map->cnlink) {
		LOGPFSML(fi, LOGL_ERROR, "Failed to send SCCP Data Form 1: no CN link\n");
		return -1;
	}

	CNLINK_CTR_INC(map->cnlink, CNLINK_CTR_SCCP_N_DATA_REQ);
	return hnbgw_sccp_user_tx_data_req(map->cnlink->hnbgw_sccp_user,
					   map->scu_conn_id,
					   ranap_msg);
}

static int tx_sccp_rlsd(struct osmo_fsm_inst *fi)
{
	struct hnbgw_context_map *map = fi->priv;

	if (!map->cnlink) {
		LOGPFSML(fi, LOGL_ERROR, "Failed to send SCCP RLSD: no CN link\n");
		return -1;
	}

	CNLINK_CTR_INC(map->cnlink, CNLINK_CTR_SCCP_N_DISCONNECT_REQ);
	return hnbgw_sccp_user_tx_disconnect_req(map->cnlink->hnbgw_sccp_user,
						 map->scu_conn_id);
}

static int handle_rx_sccp(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;

	/* If the FSM instance has already terminated, don't dispatch anything. */
	if (fi->proc.terminating)
		return 0;

	/* When there was no message received along with the received event, then there is nothing to forward to RUA. */
	if (!msg_has_l2_data(ranap_msg))
		return 0;

	return hnbgw_ranap_rx_data_dl(map, ranap_msg);
}

static void wait_cc_tx_msg_list_enqueue(struct hnbgw_context_map *map, struct msgb *ranap_msg)
{
	talloc_steal(map, ranap_msg);
	msgb_enqueue(&map->sccp_fi_ctx.wait_cc_tx_msg_list, ranap_msg);
}

static struct msgb *wait_cc_tx_msg_list_dequeue(struct hnbgw_context_map *map)
{
	struct msgb *ranap_msg = msgb_dequeue(&map->sccp_fi_ctx.wait_cc_tx_msg_list);
	if (ranap_msg)
		talloc_steal(OTC_SELECT, ranap_msg);
	return ranap_msg;
}

static void map_sccp_init_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg = NULL;
	struct hnbgw_context_map *map = fi->priv;

	switch (event) {

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		ranap_msg = data;
		/* In the INIT state, the first MAP_SCCP_EV_TX_DATA_REQUEST will be the RANAP message received from the
		 * RUA Connect message. Send the SCCP CR and transition to WAIT_CC. */
		if (tx_sccp_cr(fi, ranap_msg) == 0)
			map_sccp_fsm_state_chg(MAP_SCCP_ST_WAIT_CC);
		return;

	case MAP_SCCP_EV_RAN_LINK_LOST:
	case MAP_SCCP_EV_USER_ABORT:
	case MAP_SCCP_EV_CN_LINK_LOST:
	case MAP_SCCP_EV_MGCP_LINK_LOST:
	case MAP_SCCP_EV_PFCP_LINK_LOST:
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RAN_DISC:
		/* bool rua_disconnect_err_condition = !!data; */
		/* 3GPP TS 25.468 9.1.5: RUA has disconnected.
		 * In this state we didn't send an SCCP CR yet, so nothing to be torn down on CN side. */
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_RELEASED:
		/* SCCP RLSD received from CN. This will never happen since we haven't even asked for a connection, but
		 * for completeness: */
		CNLINK_CTR_INC(map->cnlink, CNLINK_CTR_SCCP_RLSD_CN_ORIGIN);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_sccp_wait_cc_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg = NULL;

	switch (event) {

	case MAP_SCCP_EV_RX_CONNECTION_CONFIRM:
		ranap_msg = data;
		map_sccp_fsm_state_chg(MAP_SCCP_ST_CONNECTED);
		/* Usually doesn't but if the SCCP CC contained data, forward it to RUA */
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		ranap_msg = data;
		LOGPFSML(fi, LOGL_INFO, "Caching RANAP msg from RUA while waiting for SCCP CC\n");
		wait_cc_tx_msg_list_enqueue(map, ranap_msg);
		return;

	case MAP_SCCP_EV_RAN_LINK_LOST:
	case MAP_SCCP_EV_USER_ABORT:
	case MAP_SCCP_EV_CN_LINK_LOST:
	case MAP_SCCP_EV_MGCP_LINK_LOST:
	case MAP_SCCP_EV_PFCP_LINK_LOST:
		map->please_disconnect = true;
		return;

	case MAP_SCCP_EV_RAN_DISC:
		/* bool rua_disconnect_err_condition = !!data; */
		/* 3GPP TS 25.468 9.1.5: RUA has disconnected.
		 * In this state we didn't send an SCCP CR yet, so nothing to be torn down on CN side. */
		map->please_disconnect = true;
		return;

	case MAP_SCCP_EV_RX_RELEASED:
		ranap_msg = data;
		/* SCCP RLSD received from CN. This will never happen since we haven't even received a Connection
		 * Confirmed, but for completeness: */
		CNLINK_CTR_INC(map->cnlink, CNLINK_CTR_SCCP_RLSD_CN_ORIGIN);
		handle_rx_sccp(fi, ranap_msg);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_sccp_connected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg;

	/* Now that SCCP conn is confirmed, forward pending msgs received from RUA side: */
	while ((ranap_msg = wait_cc_tx_msg_list_dequeue(map)))
		tx_sccp_df1(fi, ranap_msg);

	if (map->please_disconnect) {
		/* SCCP has already been asked to disconnect, so disconnect now that the
		 * CC has been received. Send RLSD to SCCP (without RANAP data) */
		tx_sccp_rlsd(fi);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
	}
}

static void map_sccp_connected_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg = NULL;
	bool rua_disconnect_err_condition;

	switch (event) {

	case MAP_SCCP_EV_RX_DATA_INDICATION:
		ranap_msg = data;
		/* forward RANAP from SCCP to RUA */
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		ranap_msg = data;
		/* Someone (usually the RUA side) wants us to send a RANAP payload to CN via SCCP */
		tx_sccp_df1(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_RAN_DISC:
		rua_disconnect_err_condition = !!data;
		/* 3GPP TS 25.468 9.1.5: RUA has disconnected.
		 * - Under normal conditions (cause=Normal) the RUA Disconnect
		 *   contained a RANAP Iu-ReleaseComplete which we already
		 *   handled here through MAP_SCCP_EV_TX_DATA_REQUEST.
		 *   On SCCP, We will expect the CN to send an SCCP RLSD soon.
		 * - Under error conditions, cause!=Normal and there was no RANAP message.
		 *   In that case, we need to tear down the associated SCCP link towards CN,
		 *   which in turn will tear down the upper layer Iu conn.
		 */
		if (rua_disconnect_err_condition) {
			tx_sccp_rlsd(fi);
			map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		} else {
			map_sccp_fsm_state_chg(MAP_SCCP_ST_WAIT_RLSD);
		}
		return;

	case MAP_SCCP_EV_RAN_LINK_LOST:
		/* RUA has disconnected ungracefully, so there is no Iu Release that told the CN to disconnect.
		 * Disconnect on the SCCP layer, ungracefully. */
	case MAP_SCCP_EV_USER_ABORT:
		/* The user is asking for disconnection, so there is no Iu Release in progress. Disconnect now. */
	case MAP_SCCP_EV_CN_LINK_LOST:
		/* The CN peer has sent a RANAP RESET, so the old link that this map ran on is lost */
	case MAP_SCCP_EV_MGCP_LINK_LOST:
	case MAP_SCCP_EV_PFCP_LINK_LOST:
		/* The MGW failed somehow, we cannot continue */
		tx_sccp_rlsd(fi);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_RELEASED:
		ranap_msg = data;
		/* The CN sends an N-Disconnect (SCCP Released). */
		CNLINK_CTR_INC(map->cnlink, CNLINK_CTR_SCCP_RLSD_CN_ORIGIN);
		handle_rx_sccp(fi, ranap_msg);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_CONNECTION_CONFIRM:
		ranap_msg = data;
		/* Already connected. Unusual, but if there is data just forward it. */
		LOGPFSML(fi, LOGL_ERROR, "Already connected, but received SCCP CC again\n");
		handle_rx_sccp(fi, ranap_msg);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_sccp_wait_rlsd_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	/* For sanity, always tell RUA to disconnect, if it hasn't done so. */
	if (map_rua_is_active(map))
		map_rua_dispatch(map, MAP_RUA_EV_CN_DISC, NULL);
}

static void map_sccp_wait_rlsd_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg = NULL;

	switch (event) {

	case MAP_SCCP_EV_RX_RELEASED:
		ranap_msg = data;
		/* The CN sends the expected SCCP RLSD.
		 * Usually there is no data, but if there is just forward it.
		 * Usually RUA is already disconnected, but let the RUA FSM decide about that. */
		handle_rx_sccp(fi, ranap_msg);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_DATA_INDICATION:
		ranap_msg = data;
		/* RUA is probably already disconnected, but let the RUA FSM decide about that. */
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		ranap_msg = data;
		/* Normally, RUA would already disconnected, but since SCCP is officially still connected, we can still
		 * forward messages there. Already waiting for CN to send the SCCP RLSD. If there is a message, forward
		 * it, and just continue to time out on the SCCP RLSD. */
		tx_sccp_df1(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_RX_CONNECTION_CONFIRM:
		ranap_msg = data;
		/* Already connected. Unusual, but if there is data just forward it. */
		LOGPFSML(fi, LOGL_ERROR, "Already connected, but received SCCP CC\n");
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_RAN_LINK_LOST:
	case MAP_SCCP_EV_USER_ABORT:
	case MAP_SCCP_EV_CN_LINK_LOST:
	case MAP_SCCP_EV_MGCP_LINK_LOST:
	case MAP_SCCP_EV_PFCP_LINK_LOST:
	case MAP_SCCP_EV_RAN_DISC:
		/* Stop waiting for RLSD, send RLSD now. */
		tx_sccp_rlsd(fi);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_sccp_disconnected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	/* From SCCP's POV, we can now free the hnbgw_context_map.
	 * If RUA is still active, tell it to disconnect -- in that case the RUA side will call context_map_free().
	 * If RUA is no longer active, free this map. */
	if (map_rua_is_active(map))
		map_rua_dispatch(map, MAP_RUA_EV_CN_DISC, NULL);
	else
		context_map_free(map);
}

static void map_sccp_disconnected_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg = data;

	if (msg_has_l2_data(ranap_msg))
		LOGPFSML(fi, LOGL_ERROR, "SCCP not connected, cannot dispatch RANAP message\n");
}

static int map_sccp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct hnbgw_context_map *map = fi->priv;

	/* Return 1 to terminate FSM instance, 0 to keep running */
	switch (fi->state) {
	case MAP_SCCP_ST_INIT:
		/* cannot sent SCCP RLSD, because we haven't set up an SCCP link */
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return 0;

	case MAP_SCCP_ST_WAIT_CC:
		/* send N-DISCONNECT. libosmo-sigtran/sccp_scoc.c will do the SCCP connection cleanup, like waiting a
		 * bit whether the SCCP CC might still arrive, and cleanup the conn if not. */
	case MAP_SCCP_ST_CONNECTED:
	case MAP_SCCP_ST_WAIT_RLSD:
		/* send SCCP RLSD. libosmo-sigtran/sccp_scoc.c will do the SCCP connection cleanup.
		 * (It will repeatedly send SCCP RLSD until the peer responded with SCCP RLC, or until the
		 * sccp_connection->t_int timer expires, and the sccp_connection is freed.) */
		if (map->cnlink)
			tx_sccp_rlsd(fi);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return 0;

	default:
	case MAP_SCCP_ST_DISCONNECTED:
		return 1;
	}
}

void map_sccp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct hnbgw_context_map *map = fi->priv;
	map->sccp_fi = NULL;
	msgb_queue_free(&map->sccp_fi_ctx.wait_cc_tx_msg_list);
}

#define S(x)    (1 << (x))

static const struct osmo_fsm_state map_sccp_fsm_states[] = {
	[MAP_SCCP_ST_INIT] = {
		.name = "init",
		.in_event_mask = 0
			| S(MAP_SCCP_EV_TX_DATA_REQUEST)
			| S(MAP_SCCP_EV_RAN_DISC)
			| S(MAP_SCCP_EV_RAN_LINK_LOST)
			| S(MAP_SCCP_EV_RX_RELEASED)
			| S(MAP_SCCP_EV_USER_ABORT)
			| S(MAP_SCCP_EV_CN_LINK_LOST)
			| S(MAP_SCCP_EV_MGCP_LINK_LOST)
			| S(MAP_SCCP_EV_PFCP_LINK_LOST)
			,
		.out_state_mask = 0
			| S(MAP_SCCP_ST_INIT)
			| S(MAP_SCCP_ST_WAIT_CC)
			| S(MAP_SCCP_ST_DISCONNECTED)
			,
		.action = map_sccp_init_action,
	},
	[MAP_SCCP_ST_WAIT_CC] = {
		.name = "wait_cc",
		.in_event_mask = 0
			| S(MAP_SCCP_EV_RX_CONNECTION_CONFIRM)
			| S(MAP_SCCP_EV_TX_DATA_REQUEST)
			| S(MAP_SCCP_EV_RAN_DISC)
			| S(MAP_SCCP_EV_RAN_LINK_LOST)
			| S(MAP_SCCP_EV_RX_RELEASED)
			| S(MAP_SCCP_EV_USER_ABORT)
			| S(MAP_SCCP_EV_CN_LINK_LOST)
			| S(MAP_SCCP_EV_MGCP_LINK_LOST)
			| S(MAP_SCCP_EV_PFCP_LINK_LOST)
			,
		.out_state_mask = 0
			| S(MAP_SCCP_ST_CONNECTED)
			| S(MAP_SCCP_ST_DISCONNECTED)
			,
		.action = map_sccp_wait_cc_action,
	},
	[MAP_SCCP_ST_CONNECTED] = {
		.name = "connected",
		.in_event_mask = 0
			| S(MAP_SCCP_EV_RX_DATA_INDICATION)
			| S(MAP_SCCP_EV_TX_DATA_REQUEST)
			| S(MAP_SCCP_EV_RAN_DISC)
			| S(MAP_SCCP_EV_RAN_LINK_LOST)
			| S(MAP_SCCP_EV_RX_RELEASED)
			| S(MAP_SCCP_EV_RX_CONNECTION_CONFIRM)
			| S(MAP_SCCP_EV_USER_ABORT)
			| S(MAP_SCCP_EV_CN_LINK_LOST)
			| S(MAP_SCCP_EV_MGCP_LINK_LOST)
			| S(MAP_SCCP_EV_PFCP_LINK_LOST)
			,
		.out_state_mask = 0
			| S(MAP_SCCP_ST_WAIT_RLSD)
			| S(MAP_SCCP_ST_DISCONNECTED)
			,
		.onenter = map_sccp_connected_onenter,
		.action = map_sccp_connected_action,
	},
	[MAP_SCCP_ST_WAIT_RLSD] = {
		.name = "wait_rlsd",
		.in_event_mask = 0
			| S(MAP_SCCP_EV_RX_RELEASED)
			| S(MAP_SCCP_EV_RX_DATA_INDICATION)
			| S(MAP_SCCP_EV_TX_DATA_REQUEST)
			| S(MAP_SCCP_EV_RAN_DISC)
			| S(MAP_SCCP_EV_RAN_LINK_LOST)
			| S(MAP_SCCP_EV_RX_CONNECTION_CONFIRM)
			| S(MAP_SCCP_EV_USER_ABORT)
			| S(MAP_SCCP_EV_CN_LINK_LOST)
			| S(MAP_SCCP_EV_MGCP_LINK_LOST)
			| S(MAP_SCCP_EV_PFCP_LINK_LOST)
			,
		.out_state_mask = 0
			| S(MAP_SCCP_ST_DISCONNECTED)
			,
		.onenter = map_sccp_wait_rlsd_onenter,
		.action = map_sccp_wait_rlsd_action,
	},
	[MAP_SCCP_ST_DISCONNECTED] = {
		.name = "disconnected",
		.in_event_mask = 0
			| S(MAP_SCCP_EV_TX_DATA_REQUEST)
			| S(MAP_SCCP_EV_RAN_DISC)
			| S(MAP_SCCP_EV_RAN_LINK_LOST)
			| S(MAP_SCCP_EV_USER_ABORT)
			| S(MAP_SCCP_EV_CN_LINK_LOST)
			| S(MAP_SCCP_EV_MGCP_LINK_LOST)
			| S(MAP_SCCP_EV_PFCP_LINK_LOST)
			,
		.onenter = map_sccp_disconnected_onenter,
		.action = map_sccp_disconnected_action,
	},
};

static struct osmo_fsm map_sccp_fsm = {
	.name = "map_sccp",
	.states = map_sccp_fsm_states,
	.num_states = ARRAY_SIZE(map_sccp_fsm_states),
	.log_subsys = DCN,
	.event_names = map_sccp_fsm_event_names,
	.timer_cb = map_sccp_fsm_timer_cb,
	.cleanup = map_sccp_fsm_cleanup,
};

static __attribute__((constructor)) void map_sccp_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&map_sccp_fsm) == 0);
}
