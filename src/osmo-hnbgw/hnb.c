/* HNB related code */

/* (C) 2015,2024 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <inttypes.h>

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/netif/stream.h>

#include <osmocom/hnbgw/umts_cell_id.h>
#include <osmocom/hnbgw/hnb.h>
#include <osmocom/hnbgw/hnb_persistent.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_hnbap.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/mgw_fsm.h>

/* update the active RAB duration rate_ctr for given HNB */
void hnb_store_rab_durations(struct hnb_context *hnb)
{
	struct hnbgw_context_map *map;
	struct timespec now;
	uint64_t elapsed_cs_rab_ms = 0;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	/* iterate over all context_maps (subscribers) */
	llist_for_each_entry(map, &hnb->map_list, hnb_list) {
		/* skip any PS maps, we care about CS RABs only here */
		if (map->is_ps)
			continue;
		elapsed_cs_rab_ms += mgw_fsm_get_elapsed_ms(map, &now);
	}

	/* Export to rate countes. */
	rate_ctr_add(HNBP_CTR(hnb->persistent, HNB_CTR_RAB_ACTIVE_MILLISECONDS_TOTAL), elapsed_cs_rab_ms);
}

/***********************************************************************
 * HNB Context
 ***********************************************************************/

/* look-up HNB context by id. Used from CTRL */
static struct hnb_context *hnb_context_by_id(uint32_t cid)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (hnb->id.cid == cid)
			return hnb;
	}

	return NULL;
}

/* look-up HNB context by identity_info. Used from VTY */
struct hnb_context *hnb_context_by_identity_info(const char *identity_info)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (strcmp(identity_info, hnb->identity_info) == 0)
			return hnb;
	}

	return NULL;
}

static int hnb_read_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
static int hnb_closed_cb(struct osmo_stream_srv *conn);

static struct hnb_context *hnb_context_alloc(struct osmo_stream_srv_link *link, int new_fd)
{
	struct hnb_context *ctx;

	ctx = talloc_zero(g_hnbgw, struct hnb_context);
	if (!ctx)
		return NULL;
	INIT_LLIST_HEAD(&ctx->map_list);

	ctx->conn = osmo_stream_srv_create2(g_hnbgw, link, new_fd, ctx);
	if (!ctx->conn) {
		LOGP(DMAIN, LOGL_INFO, "error while creating connection\n");
		talloc_free(ctx);
		return NULL;
	}
	osmo_stream_srv_set_read_cb(ctx->conn, hnb_read_cb);
	osmo_stream_srv_set_closed_cb(ctx->conn, hnb_closed_cb);

	llist_add_tail(&ctx->list, &g_hnbgw->hnb_list);
	return ctx;
}

const char *hnb_context_name(struct hnb_context *ctx)
{
	char *result;
	if (!ctx)
		return "NULL";

	if (ctx->conn) {
		char hostbuf_r[INET6_ADDRSTRLEN];
		char portbuf_r[6];
		int fd = osmo_stream_srv_get_fd(ctx->conn);

		/* get remote addr */
		if (fd >= 0 && osmo_sock_get_ip_and_port(fd, hostbuf_r, sizeof(hostbuf_r), portbuf_r, sizeof(portbuf_r), false) == 0)
			result = talloc_asprintf(OTC_SELECT, "%s:%s", hostbuf_r, portbuf_r);
		else
			result = "?";
	} else {
		result = "disconnected";
	}

	if (g_hnbgw->config.log_prefix_hnb_id)
		result = talloc_asprintf(OTC_SELECT, "%s %s", result, ctx->identity_info);
	else
		result = talloc_asprintf(OTC_SELECT, "%s %s", result, umts_cell_id_to_str(&ctx->id));
	return result;
}

void hnb_context_release_ue_state(struct hnb_context *ctx)
{
	struct hnbgw_context_map *map, *map2;

	/* deactivate all context maps */
	llist_for_each_entry_safe(map, map2, &ctx->map_list, hnb_list) {
		context_map_hnb_released(map);
		/* hnbgw_context_map will remove itself from lists when it is ready. */
	}
}

void hnb_context_release(struct hnb_context *ctx)
{
	struct hnbgw_context_map *map;

	LOGHNB(ctx, DMAIN, LOGL_INFO, "Releasing HNB context\n");

	if (ctx->persistent) {
		struct timespec tp;
		int rc;
		rc = osmo_clock_gettime(CLOCK_MONOTONIC, &tp);
		ctx->persistent->updowntime = (rc < 0) ? 0 : tp.tv_sec;
	}

	/* remove from the list of HNB contexts */
	llist_del(&ctx->list);

	hnb_context_release_ue_state(ctx);

	if (ctx->conn) { /* we own a conn, we must free it: */
		LOGHNB(ctx, DMAIN, LOGL_INFO, "Closing HNB SCTP connection %s\n",
		       osmo_stream_srv_get_sockname(ctx->conn));
		/* Avoid our closed_cb calling hnb_context_release() again: */
		osmo_stream_srv_set_data(ctx->conn, NULL);
		osmo_stream_srv_destroy(ctx->conn);
	} /* else: we are called from closed_cb, so conn is being freed separately */

	/* hnbgw_context_map are still listed in ctx->map_list, but we are freeing ctx. Remove all entries from the
	 * list, but keep the hnbgw_context_map around for graceful release. They are also listed under
	 * hnbgw_cnlink->map_list, and will remove themselves when ready. */
	while ((map = llist_first_entry_or_null(&ctx->map_list, struct hnbgw_context_map, hnb_list))) {
		llist_del(&map->hnb_list);
		map->hnb_ctx = NULL;
	}

	/* remove back reference from hnb_persistent to context */
	if (ctx->persistent)
		hnb_persistent_deregistered(ctx->persistent);

	talloc_free(ctx);
}

unsigned long long hnb_get_updowntime(const struct hnb_context *ctx)
{
	if (!ctx->persistent)
		return 0;
	return hnbp_get_updowntime(ctx->persistent);
}

/***********************************************************************
 * SCTP Socket / stream handling
 ***********************************************************************/

static int hnb_read_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg)
{
	struct hnb_context *hnb = osmo_stream_srv_get_data(conn);
	int flags = msgb_sctp_msg_flags(msg);
	int rc;

	OSMO_ASSERT(hnb);

	LOGHNB(hnb, DMAIN, LOGL_DEBUG, "%s(): sctp_recvmsg() returned %d (flags=0x%x)\n",
	       __func__, res, flags);

	/* Notification received */
	if (flags & OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *)msgb_data(msg);
		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_LOST:
				LOGHNB(hnb, DMAIN, LOGL_NOTICE,
				       "sctp_recvmsg(%s) = SCTP_COMM_LOST, closing conn\n",
				       osmo_stream_srv_get_sockname(conn));
				msgb_free(msg);
				osmo_stream_srv_destroy(conn);
				return -EBADF;
			case SCTP_RESTART:
				LOGHNB(hnb, DMAIN, LOGL_NOTICE, "HNB SCTP conn RESTARTed, marking as HNBAP-unregistered\n");
				hnb->hnb_registered = false;
				hnb_context_release_ue_state(hnb);
				/* The tx queue may be quite full after an SCTP RESTART: (SYS#6113)
				 * The link may have been flaky (a possible reason for the peer restarting the conn) and
				 * hence the kernel socket Tx queue may be full (no ACKs coming back) and our own userspace
				 * queue may contain plenty of oldish messages to be sent. Since the HNB will re-register after
				 * this, we simply drop all those old messages: */
				osmo_stream_srv_clear_tx_queue(conn);
				msgb_free(msg);
				return 0;
			}
			break;
		case SCTP_SHUTDOWN_EVENT:
			LOGHNB(hnb, DMAIN, LOGL_NOTICE,
			       "sctp_recvmsg(%s) = SCTP_SHUTDOWN_EVENT, closing conn\n",
			       osmo_stream_srv_get_sockname(conn));
			msgb_free(msg);
			osmo_stream_srv_destroy(conn);
			return -EBADF;
		default:
			msgb_free(msg);
			return 0;
		};
	}

	if (OSMO_UNLIKELY(res < 0)) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Error during sctp_recvmsg(%s)\n",
		       osmo_stream_srv_get_sockname(conn));
		msgb_free(msg);
		osmo_stream_srv_destroy(conn);
		return -EBADF;
	} else if (OSMO_UNLIKELY(res == 0)) {
		LOGHNB(hnb, DMAIN, LOGL_NOTICE, "Connection closed sctp_recvmsg(%s) = 0\n",
		       osmo_stream_srv_get_sockname(conn));
		msgb_free(msg);
		osmo_stream_srv_destroy(conn);
		return -EBADF;
	}

	/* we store a reference to the HomeNodeB in the msg->dest for the
	 * benefit of various downstream processing functions */
	msg->dst = hnb;

	switch (msgb_sctp_ppid(msg)) {
	case IUH_PPI_HNBAP:
		hnb->hnbap_stream = msgb_sctp_stream(msg);
		rc = hnbgw_hnbap_rx(hnb, msg);
		break;
	case IUH_PPI_RUA:
		if (!hnb->hnb_registered) {
			LOGHNB(hnb, DMAIN, LOGL_NOTICE, "Discarding RUA as HNB is not registered\n");
			msgb_free(msg);
			return 0;
		}
		hnb->rua_stream = msgb_sctp_stream(msg);
		rc = hnbgw_rua_rx(hnb, msg);
		break;
	case IUH_PPI_SABP:
	case IUH_PPI_RNA:
	case IUH_PPI_PUA:
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Unimplemented SCTP PPID=%lu received\n", msgb_sctp_ppid(msg));
		rc = 0;
		break;
	default:
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Unknown SCTP PPID=%lu received\n", msgb_sctp_ppid(msg));
		rc = 0;
		break;
	}

	msgb_free(msg);
	return rc;
}

static int hnb_closed_cb(struct osmo_stream_srv *conn)
{
	struct hnb_context *hnb = osmo_stream_srv_get_data(conn);
	if (!hnb)
		return 0; /* hnb_context is being freed, nothing do be done */

	LOGHNB(hnb, DMAIN, LOGL_INFO, "connection closed\n");

	/* hnb: conn became broken, let's release the associated hnb.
	 * conn object is being freed after closed_cb(), so unassign it from hnb
	 * if available to avoid it freeing it again: */
	hnb->conn = NULL;
	hnb_context_release(hnb);

	return 0;
}

/*! call-back when the listen FD has something to read */
int hnbgw_rua_accept_cb(struct osmo_stream_srv_link *srv, int fd)
{
	struct hnb_context *ctx;

	LOGP(DMAIN, LOGL_INFO, "New HNB SCTP connection %s\n",
	     osmo_sock_get_name2(fd));

	ctx = hnb_context_alloc(srv, fd);
	if (!ctx)
		return -ENOMEM;

	return 0;
}

CTRL_CMD_DEFINE_RO(hnb_info, "info");
static int get_hnb_info(struct ctrl_cmd *cmd, void *data)
{
	struct hnb_context *hnb = data;

	cmd->reply = talloc_strdup(cmd, hnb->identity_info);

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(hnbs, "num-hnb");
static int get_hnbs(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = talloc_asprintf(cmd, "%u", llist_count(&g_hnbgw->hnb_list));

	return CTRL_CMD_REPLY;
}

int hnb_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_hnbs);
	rc |= ctrl_cmd_install(CTRL_NODE_HNB, &cmd_hnb_info);

	return rc;
}

int hnb_ctrl_node_lookup(void *data, vector vline, int *node_type, void **node_data, int *i)
{
	const char *token = vector_slot(vline, *i);
	struct hnb_context *hnb;
	long num;

	switch (*node_type) {
	case CTRL_NODE_ROOT:
		if (strcmp(token, "hnb") != 0)
			return 0;

		(*i)++;

		if (!ctrl_parse_get_num(vline, *i, &num))
			return -ERANGE;

		hnb = hnb_context_by_id(num);
		if (!hnb)
			return -ENODEV;

		*node_data = hnb;
		*node_type = CTRL_NODE_HNB;
		break;
	default:
		return 0;
	}

	return 1;
}
