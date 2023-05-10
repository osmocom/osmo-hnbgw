/* kitchen sink for OsmoHNBGW implementation */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/vty/vty.h>

#include <osmocom/netif/stream.h>

#include "config.h"
#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_proto.h>
#endif

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_hnbap.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/context_map.h>

struct hnbgw *g_hnbgw = NULL;

void g_hnbgw_alloc(void *ctx)
{
	OSMO_ASSERT(!g_hnbgw);
	g_hnbgw = talloc_zero(ctx, struct hnbgw);

	/* strdup so we can easily talloc_free in the VTY code */
	g_hnbgw->config.iuh_local_ip = talloc_strdup(g_hnbgw, HNBGW_LOCAL_IP_DEFAULT);
	g_hnbgw->config.iuh_local_port = IUH_DEFAULT_SCTP_PORT;
	g_hnbgw->config.log_prefix_hnb_id = true;

	g_hnbgw->next_ue_ctx_id = 23;
	INIT_LLIST_HEAD(&g_hnbgw->hnb_list);
	INIT_LLIST_HEAD(&g_hnbgw->ue_list);

	g_hnbgw->mgw_pool = mgcp_client_pool_alloc(g_hnbgw);
	g_hnbgw->config.mgcp_client = talloc_zero(g_hnbgw, struct mgcp_client_conf);
	mgcp_client_conf_init(g_hnbgw->config.mgcp_client);

#if ENABLE_PFCP
	g_hnbgw->config.pfcp.remote_port = OSMO_PFCP_PORT;
#endif
}

static struct hnb_context *hnb_context_by_id(uint32_t cid)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (hnb->id.cid == cid)
			return hnb;
	}

	return NULL;
}

struct hnb_context *hnb_context_by_identity_info(const char *identity_info)
{
	struct hnb_context *hnb;

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		if (strcmp(identity_info, hnb->identity_info) == 0)
			return hnb;
	}

	return NULL;
}

struct ue_context *ue_context_by_id(uint32_t id)
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		if (ue->context_id == id)
			return ue;
	}
	return NULL;

}

struct ue_context *ue_context_by_imsi(const char *imsi)
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		if (!strcmp(ue->imsi, imsi))
			return ue;
	}
	return NULL;
}

struct ue_context *ue_context_by_tmsi(uint32_t tmsi)
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		if (ue->tmsi == tmsi)
			return ue;
	}
	return NULL;
}

static void ue_context_free_by_hnb(const struct hnb_context *hnb)
{
	struct ue_context *ue, *tmp;

	llist_for_each_entry_safe(ue, tmp, &g_hnbgw->ue_list, list) {
		if (ue->hnb == hnb)
			ue_context_free(ue);
	}
}

static uint32_t get_next_ue_ctx_id(void)
{
	uint32_t id;

	do {
		id = g_hnbgw->next_ue_ctx_id++;
	} while (ue_context_by_id(id));

	return id;
}

struct ue_context *ue_context_alloc(struct hnb_context *hnb, const char *imsi,
				    uint32_t tmsi)
{
	struct ue_context *ue;

	ue = talloc_zero(g_hnbgw, struct ue_context);
	if (!ue)
		return NULL;

	ue->hnb = hnb;
	if (imsi)
		OSMO_STRLCPY_ARRAY(ue->imsi, imsi);
	else
		ue->imsi[0] = '\0';
	ue->tmsi = tmsi;
	ue->context_id = get_next_ue_ctx_id();
	llist_add_tail(&ue->list, &g_hnbgw->ue_list);

	LOGP(DHNBAP, LOGL_INFO, "created UE context: id 0x%x, imsi %s, tmsi 0x%x\n",
	     ue->context_id, imsi? imsi : "-", tmsi);

	return ue;
}

void ue_context_free(struct ue_context *ue)
{
	llist_del(&ue->list);
	talloc_free(ue);
}

static int hnb_read_cb(struct osmo_stream_srv *conn)
{
	struct hnb_context *hnb = osmo_stream_srv_get_data(conn);
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct msgb *msg = msgb_alloc(IUH_MSGB_SIZE, "Iuh rx");
	int rc;

	if (!msg)
		return -ENOMEM;

	OSMO_ASSERT(hnb);
	/* we store a reference to the HomeNodeB in the msg->dest for the
	 * benefit of various downstream processing functions */
	msg->dst = hnb;

	rc = osmo_stream_srv_recv(conn, msg);
	/* Notification received */
	if (msgb_sctp_msg_flags(msg) & OSMO_STREAM_SCTP_MSG_FLAGS_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *)msgb_data(msg);
		rc = 0;
		switch (notif->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			switch (notif->sn_assoc_change.sac_state) {
			case SCTP_COMM_LOST:
				LOGHNB(hnb, DMAIN, LOGL_NOTICE,
				       "sctp_recvmsg(%s) = SCTP_COMM_LOST, closing conn\n",
				       osmo_sock_get_name2(ofd->fd));
				osmo_stream_srv_destroy(conn);
				rc = -EBADF;
				break;
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
				break;
			}
			break;
		case SCTP_SHUTDOWN_EVENT:
			LOGHNB(hnb, DMAIN, LOGL_NOTICE,
			       "sctp_recvmsg(%s) = SCTP_SHUTDOWN_EVENT, closing conn\n",
			       osmo_sock_get_name2(ofd->fd));
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
			break;
		}
		goto out;
	} else if (rc == -EAGAIN) {
		/* Older versions of osmo_stream_srv_recv() not supporting
		 * msgb_sctp_msg_flags() may still return -EAGAIN when an sctp
		 * notification is received. */
		rc = 0;
		goto out;
	} else if (rc < 0) {
		LOGHNB(hnb, DMAIN, LOGL_ERROR, "Error during sctp_recvmsg(%s)\n",
		       osmo_sock_get_name2(ofd->fd));
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else if (rc == 0) {
		LOGHNB(hnb, DMAIN, LOGL_NOTICE, "Connection closed sctp_recvmsg(%s) = 0\n",
		       osmo_sock_get_name2(ofd->fd));
		osmo_stream_srv_destroy(conn);
		rc = -EBADF;
		goto out;
	} else {
		msgb_put(msg, rc);
	}

	switch (msgb_sctp_ppid(msg)) {
	case IUH_PPI_HNBAP:
		hnb->hnbap_stream = msgb_sctp_stream(msg);
		rc = hnbgw_hnbap_rx(hnb, msg);
		break;
	case IUH_PPI_RUA:
		if (!hnb->hnb_registered) {
			LOGHNB(hnb, DMAIN, LOGL_NOTICE, "Discarding RUA as HNB is not registered\n");
			goto out;
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

out:
	msgb_free(msg);
	return rc;
}

static int hnb_closed_cb(struct osmo_stream_srv *conn)
{
	struct hnb_context *hnb = osmo_stream_srv_get_data(conn);
	if (!hnb)
		return 0; /* hnb_context is being freed, nothing do be done */

	/* hnb: conn became broken, let's release the associated hnb.
	 * conn object is being freed after closed_cb(), so unassign it from hnb
	 * if available to avoid it freeing it again: */
	hnb->conn = NULL;
	hnb_context_release(hnb);

	return 0;
}

static struct hnb_context *hnb_context_alloc(struct osmo_stream_srv_link *link, int new_fd)
{
	struct hnb_context *ctx;

	ctx = talloc_zero(g_hnbgw, struct hnb_context);
	if (!ctx)
		return NULL;
	INIT_LLIST_HEAD(&ctx->map_list);

	ctx->conn = osmo_stream_srv_create(g_hnbgw, link, new_fd, hnb_read_cb, hnb_closed_cb, ctx);
	if (!ctx->conn) {
		LOGP(DMAIN, LOGL_INFO, "error while creating connection\n");
		talloc_free(ctx);
		return NULL;
	}

	llist_add_tail(&ctx->list, &g_hnbgw->hnb_list);
	return ctx;
}

static const char *umts_cell_id_name(const struct umts_cell_id *ucid)
{
	static __thread char buf[40];

	snprintf(buf, sizeof(buf), "%u-%u-L%u-R%u-S%u", ucid->mcc, ucid->mnc, ucid->lac, ucid->rac, ucid->sac);
	return buf;
}

const char *hnb_context_name(struct hnb_context *ctx)
{
	if (!ctx)
		return "NULL";

	if (g_hnbgw->config.log_prefix_hnb_id)
		return ctx->identity_info;
	else
		return umts_cell_id_name(&ctx->id);
}

void hnb_context_release_ue_state(struct hnb_context *ctx)
{
	struct hnbgw_context_map *map, *map2;

	/* deactivate all context maps */
	llist_for_each_entry_safe(map, map2, &ctx->map_list, hnb_list) {
		context_map_hnb_released(map);
		/* hnbgw_context_map will remove itself from lists when it is ready. */
	}
	ue_context_free_by_hnb(ctx);
}

void hnb_context_release(struct hnb_context *ctx)
{
	struct hnbgw_context_map *map;

	LOGHNB(ctx, DMAIN, LOGL_INFO, "Releasing HNB context\n");

	/* remove from the list of HNB contexts */
	llist_del(&ctx->list);

	hnb_context_release_ue_state(ctx);

	if (ctx->conn) { /* we own a conn, we must free it: */
		LOGHNB(ctx, DMAIN, LOGL_INFO, "Closing HNB SCTP connection %s\n",
		     osmo_sock_get_name2(osmo_stream_srv_get_ofd(ctx->conn)->fd));
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

	talloc_free(ctx);
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

int hnbgw_mgw_setup(void)
{
	struct mgcp_client *mgcp_client_single;
	unsigned int pool_members_initalized;

	/* Initialize MGW pool. This initalizes and connects all MGCP clients that are currently configured in
	 * the pool. Adding additional MGCP clients to the pool is possible but the user has to configure and
	 * (re)connect them manually from the VTY. */
	if (!mgcp_client_pool_empty(g_hnbgw->mgw_pool)) {
		pool_members_initalized = mgcp_client_pool_connect(g_hnbgw->mgw_pool);
		if (!pool_members_initalized) {
			LOGP(DMGW, LOGL_ERROR, "MGW pool failed to initialize any pool members\n");
			return -EINVAL;
		}
		LOGP(DMGW, LOGL_NOTICE,
		     "MGW pool with %u pool members configured, (ignoring MGW configuration in VTY node 'mgcp').\n",
		     pool_members_initalized);
		return 0;
	}

	/* Initialize and connect a single MGCP client. This MGCP client will appear as the one and only pool
	 * member if there is no MGW pool configured. */
	LOGP(DMGW, LOGL_NOTICE, "No MGW pool configured, using MGW configuration in VTY node 'mgcp'\n");
	mgcp_client_single = mgcp_client_init(g_hnbgw, g_hnbgw->config.mgcp_client);
	if (!mgcp_client_single) {
		LOGP(DMGW, LOGL_ERROR, "MGW (single) client initalization failed\n");
		return -EINVAL;
	}
	if (mgcp_client_connect(mgcp_client_single)) {
		LOGP(DMGW, LOGL_ERROR, "MGW (single) connect failed at (%s:%u)\n",
		     g_hnbgw->config.mgcp_client->remote_addr,
		     g_hnbgw->config.mgcp_client->remote_port);
		return -EINVAL;
	}
	mgcp_client_pool_register_single(g_hnbgw->mgw_pool, mgcp_client_single);

	return 0;
}

struct msgb *hnbgw_ranap_msg_alloc(const char *name)
{
	struct msgb *ranap_msg;
	ranap_msg = msgb_alloc_c(OTC_SELECT, sizeof(struct osmo_scu_prim) + 1500, name);
	msgb_reserve(ranap_msg, sizeof(struct osmo_scu_prim));
	ranap_msg->l2h = ranap_msg->data;
	return ranap_msg;
}

#define HNBGW_COPYRIGHT \
	"OsmoHNBGW - Osmocom Home Node B Gateway implementation\r\n" \
	"Copyright (C) 2016-2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n" \
	"Contributions by Daniel Willmann, Harald Welte, Neels Hofmeyr\r\n" \
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n" \
	"This is free software: you are free to change and redistribute it.\r\n" \
	"There is NO WARRANTY, to the extent permitted by law.\r\n"

static const struct log_info_cat hnbgw_log_cat[] = {
	[DMAIN] = {
		.name = "DMAIN", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "Main program",
	},
	[DHNBAP] = {
		.name = "DHNBAP", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "Home Node B Application Part",
	},
	[DRUA] = {
		.name = "DRUA", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "RANAP User Adaptation",
	},
	[DRANAP] = {
		.name = "DRANAP", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "RAN Application Part",
	},
	[DMGW] = {
		.name = "DMGW", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "\033[1;33m",
		.description = "Media Gateway",
	},
	[DHNB] = {
		.name = "DHNB", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_CYAN,
		.description = "HNB side (via RUA)",
	},
	[DCN] = {
		.name = "DCN", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_DARKYELLOW,
		.description = "Core Network side (via SCCP)",
	},
};

const struct log_info hnbgw_log_info = {
	.cat = hnbgw_log_cat,
	.num_cat = ARRAY_SIZE(hnbgw_log_cat),
};

struct vty_app_info hnbgw_vty_info = {
	.name = "OsmoHNBGW",
	.version = PACKAGE_VERSION,
	.go_parent_cb = hnbgw_vty_go_parent,
	.copyright = HNBGW_COPYRIGHT,
};
