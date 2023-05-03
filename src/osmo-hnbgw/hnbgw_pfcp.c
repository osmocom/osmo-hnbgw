/* PFCP link to UPF for osmo-hnbgw */
/* (C) 2022 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Janosch Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <osmocom/core/sockaddr_str.h>
#include <osmocom/pfcp/pfcp_endpoint.h>
#include <osmocom/pfcp/pfcp_cp_peer.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/ps_rab_fsm.h>

static void pfcp_set_msg_ctx(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m, struct osmo_pfcp_msg *req)
{
	if (!m->ctx.peer_fi)
		osmo_pfcp_cp_peer_set_msg_ctx(g_hnbgw->pfcp.cp_peer, m);

	/* If this is a response to an earlier request, just take the msg context from the request message.
	 * In osmo-hnbgw, a session_fi always points at a ps_rab FSM. */
	if (!m->ctx.session_fi && req && req->ctx.session_fi)
		ps_rab_pfcp_set_msg_ctx(req->ctx.session_fi->priv, m);

	/* Otherwise iterate all PS RABs in all hnb contexts matching on the SEID. This rarely happens at all: for tx,
	 * ps_rab_new_pfcp_msg_tx() already sets the msg ctx, and for rx, we only expect to receive PFCP Responses,
	 * which are handled above. The only time this will happen is when the UPF shuts down and sends a Deletion. */
	if (!m->ctx.session_fi && m->h.seid_present && m->h.seid != 0) {
		struct ps_rab *rab = ps_rab_find_by_seid(m->h.seid, m->rx);
		if (rab)
			ps_rab_pfcp_set_msg_ctx(rab, m);
	}
}

static void pfcp_rx_msg(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m, struct osmo_pfcp_msg *req)
{
	switch (m->h.message_type) {

		/* We only expect responses to requests. Those are handled by osmo_pfcp_msg.ctx.resp_cb. */

		/* TODO: handle graceful shutdown from UPF (Session Modification? Deletion?) */

	default:
		LOGP(DLPFCP, LOGL_ERROR, "rx unexpected PFCP message: %s\n",
		     osmo_pfcp_message_type_str(m->h.message_type));
		return;
	}
}

int hnbgw_pfcp_init(void)
{
	struct osmo_pfcp_endpoint_cfg cfg;
	struct osmo_pfcp_endpoint *ep;
	struct osmo_sockaddr_str local_addr_str;
	struct osmo_sockaddr_str upf_addr_str;
	struct osmo_sockaddr upf_addr;

	if (!hnb_gw_is_gtp_mapping_enabled()) {
		LOGP(DLPFCP, LOGL_NOTICE, "No UPF configured, NOT setting up PFCP, NOT mapping GTP via UPF\n");
		return 0;
	}
	LOGP(DLPFCP, LOGL_DEBUG, "%p cfg: pfcp remote-addr %s\n", g_hnbgw, g_hnbgw->config.pfcp.remote_addr);

	if (!g_hnbgw->config.pfcp.local_addr) {
		LOGP(DLPFCP, LOGL_ERROR, "Configuration error: missing local PFCP address, required for Node Id\n");
		return -1;
	}

	cfg = (struct osmo_pfcp_endpoint_cfg){
		.set_msg_ctx_cb = pfcp_set_msg_ctx,
		.rx_msg_cb = pfcp_rx_msg,
	};

	/* Set up PFCP endpoint's local node id from local IP address. Parse address string into local_addr_str... */
	if (osmo_sockaddr_str_from_str(&local_addr_str, g_hnbgw->config.pfcp.local_addr, g_hnbgw->config.pfcp.local_port)) {
		LOGP(DLPFCP, LOGL_ERROR, "Error in PFCP local IP: %s\n",
		     osmo_quote_str_c(OTC_SELECT, g_hnbgw->config.pfcp.local_addr, -1));
		return -1;
	}
	/* ...and convert to osmo_sockaddr, write to ep->cfg */
	if (osmo_sockaddr_str_to_sockaddr(&local_addr_str, &cfg.local_addr.u.sas)) {
		LOGP(DLPFCP, LOGL_ERROR, "Error in PFCP local IP: %s\n",
		     osmo_quote_str_c(OTC_SELECT, g_hnbgw->config.pfcp.local_addr, -1));
		return -1;
	}
	/* also store the local addr as local Node ID */
	if (osmo_pfcp_ie_node_id_from_osmo_sockaddr(&cfg.local_node_id, &cfg.local_addr)) {
		LOGP(DLPFCP, LOGL_ERROR, "Error in PFCP local IP: %s\n",
		     osmo_quote_str_c(OTC_SELECT, g_hnbgw->config.pfcp.local_addr, -1));
		return -1;
	}

	g_hnbgw->pfcp.ep = ep = osmo_pfcp_endpoint_create(g_hnbgw, &cfg);
	if (!ep) {
		LOGP(DLPFCP, LOGL_ERROR, "Failed to allocate PFCP endpoint\n");
		return -1;
	}

	/* Set up remote PFCP address to reach UPF at. First parse the string into upf_addr_str. */
	if (osmo_sockaddr_str_from_str(&upf_addr_str, g_hnbgw->config.pfcp.remote_addr, g_hnbgw->config.pfcp.remote_port)) {
		LOGP(DLPFCP, LOGL_ERROR, "Error in PFCP remote IP: %s\n",
		     osmo_quote_str_c(OTC_SELECT, g_hnbgw->config.pfcp.remote_addr, -1));
		return -1;
	}
	/* then convert upf_addr_str to osmo_sockaddr */
	if (osmo_sockaddr_str_to_sockaddr(&upf_addr_str, &upf_addr.u.sas)) {
		LOGP(DLPFCP, LOGL_ERROR, "Error in PFCP remote IP: %s\n",
		     osmo_quote_str_c(OTC_SELECT, g_hnbgw->config.pfcp.remote_addr, -1));
		return -1;
	}

	/* Start the socket */
	if (osmo_pfcp_endpoint_bind(ep)) {
		LOGP(DLPFCP, LOGL_ERROR, "Cannot bind PFCP endpoint\n");
		return -1;
	}

	/* Associate with UPF */
	g_hnbgw->pfcp.cp_peer = osmo_pfcp_cp_peer_alloc(g_hnbgw, ep, &upf_addr);
	if (!g_hnbgw->pfcp.cp_peer) {
		LOGP(DLPFCP, LOGL_ERROR, "Cannot allocate PFCP CP Peer FSM\n");
		return -1;
	}
	if (osmo_pfcp_cp_peer_associate(g_hnbgw->pfcp.cp_peer)) {
		LOGP(DLPFCP, LOGL_ERROR, "Cannot start PFCP CP Peer FSM\n");
		return -1;
	}

	return 0;
}
