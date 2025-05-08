/* (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
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
 *
 */

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/sigtran/sccp_helpers.h>

#include <asn1c/asn1helpers.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/context_map.h>

enum cnlink_fsm_state {
	CNLINK_ST_DISC,
	CNLINK_ST_CONN,
};

enum cnlink_fsm_event {
	CNLINK_EV_RX_RESET,
	CNLINK_EV_RX_RESET_ACK,
};

static const struct value_string cnlink_fsm_event_names[] = {
	OSMO_VALUE_STRING(CNLINK_EV_RX_RESET),
	OSMO_VALUE_STRING(CNLINK_EV_RX_RESET_ACK),
	{}
};

static const struct osmo_tdef_state_timeout cnlink_timeouts[32] = {
	[CNLINK_ST_DISC] = { .T = 4 },
};

#define cnlink_fsm_state_chg(FI, STATE) \
	osmo_tdef_fsm_inst_state_chg(FI, STATE, \
				     cnlink_timeouts, \
				     hnbgw_T_defs, \
				     -1)

static void link_up(struct hnbgw_cnlink *cnlink)
{
	LOGPFSML(cnlink->fi, LOGL_NOTICE, "link up\n");
	CNLINK_STAT_SET(cnlink, CNLINK_STAT_CONNECTED, 1);
}

static void link_lost(struct hnbgw_cnlink *cnlink)
{
	struct hnbgw_context_map *map, *map2;

	LOGPFSML(cnlink->fi, LOGL_NOTICE, "link lost\n");
	CNLINK_STAT_SET(cnlink, CNLINK_STAT_CONNECTED, 0);

	llist_for_each_entry_safe(map, map2, &cnlink->map_list, hnbgw_cnlink_entry)
		context_map_cnlink_lost(map);
}


static void cnlink_disc_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_cnlink *cnlink = (struct hnbgw_cnlink *)fi->priv;
	if (prev_state == CNLINK_ST_CONN)
		link_lost(cnlink);
}

static void cnlink_disc_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_cnlink *cnlink = (struct hnbgw_cnlink *)fi->priv;
	switch (event) {

	case CNLINK_EV_RX_RESET:
		hnbgw_cnlink_tx_ranap_reset_ack(cnlink);
		cnlink_fsm_state_chg(fi, CNLINK_ST_CONN);
		break;

	case CNLINK_EV_RX_RESET_ACK:
		cnlink_fsm_state_chg(fi, CNLINK_ST_CONN);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void cnlink_conn_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct hnbgw_cnlink *cnlink = (struct hnbgw_cnlink *)fi->priv;
	if (prev_state != CNLINK_ST_CONN)
		link_up(cnlink);
}

static void cnlink_conn_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct hnbgw_cnlink *cnlink = (struct hnbgw_cnlink *)fi->priv;

	switch (event) {

	case CNLINK_EV_RX_RESET:
		/* We were connected, but the remote side has restarted. */
		link_lost(cnlink);
		hnbgw_cnlink_tx_ranap_reset_ack(cnlink);
		link_up(cnlink);
		break;

	case CNLINK_EV_RX_RESET_ACK:
		LOGPFSML(fi, LOGL_INFO, "Link is already up, ignoring RESET ACK\n");
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int cnlink_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct hnbgw_cnlink *cnlink = (struct hnbgw_cnlink *)fi->priv;

	hnbgw_cnlink_tx_ranap_reset(cnlink);

	/* (re-)enter disconnect state to resend RESET after timeout. */
	cnlink_fsm_state_chg(fi, CNLINK_ST_DISC);

	/* Return 0 to not terminate the fsm */
	return 0;
}

#define S(x) (1 << (x))

static struct osmo_fsm_state cnlink_fsm_states[] = {
	[CNLINK_ST_DISC] = {
		     .name = "DISCONNECTED",
		     .in_event_mask = 0
			     | S(CNLINK_EV_RX_RESET)
			     | S(CNLINK_EV_RX_RESET_ACK)
			     ,
		     .out_state_mask = 0
			     | S(CNLINK_ST_DISC)
			     | S(CNLINK_ST_CONN)
			     ,
		     .onenter = cnlink_disc_onenter,
		     .action = cnlink_disc_action,
		     },
	[CNLINK_ST_CONN] = {
		     .name = "CONNECTED",
		     .in_event_mask = 0
			     | S(CNLINK_EV_RX_RESET)
			     | S(CNLINK_EV_RX_RESET_ACK)
			     ,
		     .out_state_mask = 0
			     | S(CNLINK_ST_DISC)
			     | S(CNLINK_ST_CONN)
			     ,
		     .onenter = cnlink_conn_onenter,
		     .action = cnlink_conn_action,
		     },
};

struct osmo_fsm cnlink_fsm = {
	.name = "cnlink",
	.states = cnlink_fsm_states,
	.num_states = ARRAY_SIZE(cnlink_fsm_states),
	.log_subsys = DRANAP,
	.timer_cb = cnlink_fsm_timer_cb,
	.event_names = cnlink_fsm_event_names,
};

bool cnlink_is_conn_ready(const struct hnbgw_cnlink *cnlink)
{
	return cnlink->fi->state == CNLINK_ST_CONN;
}

void cnlink_resend_reset(struct hnbgw_cnlink *cnlink)
{
	/* Immediately (1ms) kick off reset sending mechanism */
	osmo_fsm_inst_state_chg_ms(cnlink->fi, CNLINK_ST_DISC, 1, 0);
}

void cnlink_set_disconnected(struct hnbgw_cnlink *cnlink)
{
	/* Go to disconnected state, with the normal RESET timeout to re-send RESET. */
	cnlink_fsm_state_chg(cnlink->fi, CNLINK_ST_DISC);
}

static __attribute__((constructor)) void cnlink_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&cnlink_fsm) == 0);
}

void cnlink_rx_reset_cmd(struct hnbgw_cnlink *cnlink)
{
	osmo_fsm_inst_dispatch(cnlink->fi, CNLINK_EV_RX_RESET, NULL);
}

void cnlink_rx_reset_ack(struct hnbgw_cnlink *cnlink)
{
	osmo_fsm_inst_dispatch(cnlink->fi, CNLINK_EV_RX_RESET_ACK, NULL);
}

