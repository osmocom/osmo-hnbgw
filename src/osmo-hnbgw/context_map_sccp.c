/* SCCP side FSM of hnbgw_context_map */
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

#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/ranap/ranap_common_ran.h>

#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_cp_peer.h>
#endif

#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/mgw_fsm.h>
#include <osmocom/hnbgw/ps_rab_ass_fsm.h>

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
	OSMO_VALUE_STRING(MAP_SCCP_EV_RX_RELEASED),
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
						 cmap_T_defs, \
						 5) == 0)

void map_sccp_fsm_alloc(struct hnbgw_context_map *map)
{
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc(&map_sccp_fsm, map, map, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);
	osmo_fsm_inst_update_id_f_sanitize(fi, '-', "%s-%s-SCCP-%u", hnb_context_name(map->hnb_ctx),
					   map->is_ps ? "PS" : "CS", map->scu_conn_id);

	OSMO_ASSERT(map->sccp_fi == NULL);
	map->sccp_fi = fi;

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
	struct osmo_scu_prim *prim;
	int rc;

	if (!ranap_msg) {
		/* prepare a msgb to send an empty N-Connect prim (but this should never happen in practice) */
		ranap_msg = hnbgw_ranap_msg_alloc("SCCP-CR-empty");
	}

	prim = (struct osmo_scu_prim *)msgb_push(ranap_msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST, ranap_msg);
	prim->u.connect.called_addr = *hnbgw_cn_get_remote_addr(map->is_ps);
	prim->u.connect.calling_addr = g_hnbgw->sccp.local_addr;
	prim->u.connect.sccp_class = 2;
	prim->u.connect.conn_id = map->scu_conn_id;

	rc = osmo_sccp_user_sap_down_nofree(map->cn_link->sccp_user, &prim->oph);
	if (rc)
		LOGPFSML(fi, LOGL_ERROR, "Failed to forward SCCP Connectoin Request to CN\n");
	return rc;
}

static int tx_sccp_df1(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;
	struct osmo_scu_prim *prim;
	int rc;

	if (!msg_has_l2_data(ranap_msg))
		return 0;

	prim = (struct osmo_scu_prim *)msgb_push(ranap_msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST, ranap_msg);
	prim->u.data.conn_id = map->scu_conn_id;

	rc = osmo_sccp_user_sap_down_nofree(map->cn_link->sccp_user, &prim->oph);
	if (rc)
		LOGPFSML(fi, LOGL_ERROR, "Failed to forward SCCP Data Form 1 to CN\n");
	return rc;
}

static int tx_sccp_rlsd(struct osmo_fsm_inst *fi)
{
	struct hnbgw_context_map *map = fi->priv;
	return osmo_sccp_tx_disconn(map->cn_link->sccp_user, map->scu_conn_id, NULL, 0);
}

static int destruct_ranap_ran_rx_co_ies(ranap_message *ranap_message_p)
{
	ranap_ran_rx_co_free(ranap_message_p);
	return 0;
}

static int handle_rx_sccp(struct osmo_fsm_inst *fi, struct msgb *ranap_msg)
{
	struct hnbgw_context_map *map = fi->priv;
	int rc;

	/* When there was no message received along with the received event, then there is nothing to forward to RUA. */
	if (!msg_has_l2_data(ranap_msg))
		return 0;

	/* See if it is a RAB Assignment Request message from SCCP to RUA, where we need to change the user plane
	 * information, for RTP mapping via MGW, or GTP mapping via UPF. */
	if (!map->is_ps) {
		ranap_message *message;
		/* Circuit-Switched. Set up mapping of RTP ports via MGW */
		message = talloc_zero(OTC_SELECT, ranap_message);
		rc = ranap_ran_rx_co_decode(message, message, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));

		if (rc == 0) {
			talloc_set_destructor(message, destruct_ranap_ran_rx_co_ies);

			LOGPFSML(fi, LOGL_DEBUG, "rx from SCCP: RANAP %s\n",
				 get_value_string(ranap_procedure_code_vals, message->procedureCode));

			switch (message->procedureCode) {
			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* mgw_fsm_alloc_and_handle_rab_ass_req() takes ownership of (ranap) message */
				return handle_rab_ass_req(map, ranap_msg, message);
			case RANAP_ProcedureCode_id_Iu_Release:
				/* Any IU Release will terminate the MGW FSM, the message itsself is not passed to the
				 * FSM code. It is just forwarded normally by map_rua_tx_dt() below. */
				mgw_fsm_release(map);
				break;
			}
		}
#if ENABLE_PFCP
	} else {
		ranap_message *message;
		/* Packet-Switched. Set up mapping of GTP ports via UPF */
		message = talloc_zero(OTC_SELECT, ranap_message);
		rc = ranap_ran_rx_co_decode(message, message, msgb_l2(ranap_msg), msgb_l2len(ranap_msg));

		if (rc == 0) {
			talloc_set_destructor(message, destruct_ranap_ran_rx_co_ies);

			LOGPFSML(fi, LOGL_DEBUG, "rx from SCCP: RANAP %s\n",
				 get_value_string(ranap_procedure_code_vals, message->procedureCode));

			switch (message->procedureCode) {

			case RANAP_ProcedureCode_id_RAB_Assignment:
				/* If a UPF is configured, handle the RAB Assignment via ps_rab_ass_fsm, and replace the
				 * GTP F-TEIDs in the RAB Assignment message before passing it on to RUA. */
				if (hnb_gw_is_gtp_mapping_enabled()) {
					LOGP(DMAIN, LOGL_DEBUG,
					     "RAB Assignment: setting up GTP tunnel mapping via UPF %s\n",
					     osmo_sockaddr_to_str_c(OTC_SELECT, &g_hnbgw->pfcp.cp_peer->remote_addr));
					return hnbgw_gtpmap_rx_rab_ass_req(map, ranap_msg, message);
				}
				/* If no UPF is configured, directly forward the message as-is (no GTP mapping). */
				LOGP(DMAIN, LOGL_DEBUG, "RAB Assignment: no UPF configured, forwarding as-is\n");
				break;

			case RANAP_ProcedureCode_id_Iu_Release:
				/* Any IU Release will terminate the MGW FSM, the message itsself is not passed to the
				 * FSM code. It is just forwarded normally by map_rua_tx_dt() below. */
				hnbgw_gtpmap_release(map);
				break;
			}
		}
#endif
	}

	/* It was not a RAB Assignment Request that needed to be intercepted. Forward as-is to RUA. */
	return map_rua_dispatch(map, MAP_RUA_EV_TX_DIRECT_TRANSFER, ranap_msg);
}

static void map_sccp_init_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		/* In the INIT state, the first MAP_SCCP_EV_TX_DATA_REQUEST will be the RANAP message received from the
		 * RUA Connect message. Send the SCCP CR and transition to WAIT_CC. */
		if (tx_sccp_cr(fi, ranap_msg) == 0)
			map_sccp_fsm_state_chg(MAP_SCCP_ST_WAIT_CC);
		return;

	case MAP_SCCP_EV_RAN_DISC:
		/* No CR has been sent yet, just go to disconnected state. */
		if (msg_has_l2_data(ranap_msg))
			LOG_MAP(map, DLSCCP, LOGL_ERROR, "SCCP not connected, cannot dispatch RANAP message\n");
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_RELEASED:
		/* SCCP RLSD received from CN. This will never happen since we haven't even asked for a connection, but
		 * for completeness: */
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_sccp_wait_cc_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_context_map *map = fi->priv;
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_SCCP_EV_RX_CONNECTION_CONFIRM:
		map_sccp_fsm_state_chg(MAP_SCCP_ST_CONNECTED);
		/* Usually doesn't but if the SCCP CC contained data, forward it to RUA */
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		LOGPFSML(fi, LOGL_ERROR, "Connection not yet confirmed, cannot forward RANAP to CN\n");
		return;

	case MAP_SCCP_EV_RAN_DISC:
		/* RUA connection was terminated. First wait for the CC before releasing the SCCP conn. */
		if (msg_has_l2_data(ranap_msg))
			LOGPFSML(fi, LOGL_ERROR, "Connection not yet confirmed, cannot forward RANAP to CN\n");
		map->please_disconnect = true;
		return;

	case MAP_SCCP_EV_RX_RELEASED:
		/* SCCP RLSD received from CN. This will never happen since we haven't even received a Connection
		 * Confirmed, but for completeness: */
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
	if (map->please_disconnect) {
		/* SCCP has already been asked to disconnect, so disconnect now that the CC has been received. Send RLSD
		 * to SCCP (without RANAP data) */
		tx_sccp_rlsd(fi);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
	}
}

static void map_sccp_connected_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_SCCP_EV_RX_DATA_INDICATION:
		/* forward RANAP from SCCP to RUA */
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_TX_DATA_REQUEST:
		/* Someone (usually the RUA side) wants us to send a RANAP payload to CN via SCCP */
		tx_sccp_df1(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_RAN_DISC:
		/* RUA has disconnected, and usually has sent an Iu-ReleaseComplete along with its RUA Disconnect. On
		 * SCCP, the Iu-ReleaseComplete should still be forwarded as N-Data (SCCP Data Form 1), and we will
		 * expect the CN to send an SCCP RLSD soon. */
		map_sccp_fsm_state_chg(MAP_SCCP_ST_WAIT_RLSD);
		tx_sccp_df1(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_RX_RELEASED:
		/* The CN sends an N-Disconnect (SCCP Released) out of the usual sequence. Not what we expected, but
		 * handle it. */
		LOGPFSML(fi, LOGL_ERROR, "CN sends SCCP Released sooner than expected\n");
		handle_rx_sccp(fi, ranap_msg);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_CONNECTION_CONFIRM:
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
	struct msgb *ranap_msg = data;

	switch (event) {

	case MAP_SCCP_EV_RX_RELEASED:
		/* The CN sends the expected SCCP RLSD.
		 * Usually there is no data, but if there is just forward it.
		 * Usually RUA is already disconnected, but let the RUA FSM decide about that. */
		handle_rx_sccp(fi, ranap_msg);
		map_sccp_fsm_state_chg(MAP_SCCP_ST_DISCONNECTED);
		return;

	case MAP_SCCP_EV_RX_DATA_INDICATION:
		/* RUA is probably already disconnected, but let the RUA FSM decide about that. */
		handle_rx_sccp(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_TX_DATA_REQUEST:
	case MAP_SCCP_EV_RAN_DISC:
		/* Normally, RUA would already disconnected, but since SCCP is officially still connected, we can still
		 * forward messages there. Already waiting for CN to send the SCCP RLSD. If there is a message, forward
		 * it, and just continue to time out on the SCCP RLSD. */
		tx_sccp_df1(fi, ranap_msg);
		return;

	case MAP_SCCP_EV_RX_CONNECTION_CONFIRM:
		/* Already connected. Unusual, but if there is data just forward it. */
		LOGPFSML(fi, LOGL_ERROR, "Already connected, but received SCCP CC\n");
		handle_rx_sccp(fi, ranap_msg);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void map_sccp_disconnected_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_context_map *map = fi->priv;
	/* For sanity, always tell RUA to disconnect, if it hasn't done so. Dispatching MAP_RUA_EV_CN_DISC may send
	 * RUA into MAP_RUA_ST_DISCONNECTED, which calls context_map_check_released() and frees the hnbgw_context_map,
	 * so don't free it a second time. If RUA stays active, calling context_map_check_released() has no effect. */
	if (map_rua_is_active(map))
		map_rua_dispatch(map, MAP_RUA_EV_CN_DISC, NULL);
	else
		context_map_check_released(map);
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
		if (map->cn_link && map->cn_link->sccp_user)
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
}

#define S(x)    (1 << (x))

static const struct osmo_fsm_state map_sccp_fsm_states[] = {
	[MAP_SCCP_ST_INIT] = {
		.name = "init",
		.in_event_mask = 0
			| S(MAP_SCCP_EV_TX_DATA_REQUEST)
			| S(MAP_SCCP_EV_RAN_DISC)
			| S(MAP_SCCP_EV_RX_RELEASED)
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
			| S(MAP_SCCP_EV_RX_RELEASED)
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
			| S(MAP_SCCP_EV_RX_RELEASED)
			| S(MAP_SCCP_EV_RX_CONNECTION_CONFIRM)
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
			| S(MAP_SCCP_EV_RX_CONNECTION_CONFIRM)
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
