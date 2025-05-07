#pragma once

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ranap/RANAP_CN-DomainIndicator.h>

#define DEBUG
#include <osmocom/core/logging.h>

#include <osmocom/netif/stream.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>

#include <osmocom/hnbgw/umts_cell_id.h>
#include <osmocom/hnbgw/nft_kpi.h>
#include <osmocom/hnbgw/cnlink.h>
#include <osmocom/hnbgw/hnbgw_cn.h>

#define HNB_STORE_RAB_DURATIONS_INTERVAL 1 /* seconds */

#define LOGHNB(HNB_CTX, ss, lvl, fmt, args ...) \
	LOGP(ss, lvl, "(%s) " fmt, hnb_context_name(HNB_CTX), ## args)

enum hnb_ctrl_node {
	CTRL_NODE_HNB = _LAST_CTRL_NODE,
	_LAST_CTRL_NODE_HNB
};

/* The lifecycle of the hnb_context object is the same as its conn */
struct hnb_context {
	/*! Entry in HNB-global list of HNB */
	struct llist_head list;
	/*! SCTP socket + write queue for Iuh to this specific HNB */
	struct osmo_stream_srv *conn;
	/*! copied from HNB-Identity-Info IE */
	char identity_info[256];
	/*! copied from Cell Identity IE */
	struct umts_cell_id id;

	/*! SCTP stream ID for HNBAP */
	uint16_t hnbap_stream;
	/*! SCTP stream ID for RUA */
	uint16_t rua_stream;

	/*! True if a HNB-REGISTER-REQ from this HNB has been accepted. */
	bool hnb_registered;

	/* linked list of hnbgw_context_map */
	struct llist_head map_list;

	/*! pointer to the associated hnb persistent state. Always present after HNB-Register */
	struct hnb_persistent *persistent;
};


int hnbgw_rua_accept_cb(struct osmo_stream_srv_link *srv, int fd);
int hnb_ctrl_cmds_install(void);
int hnb_ctrl_node_lookup(void *data, vector vline, int *node_type, void **node_data, int *i);

struct hnb_context *hnb_context_by_identity_info(const char *identity_info);
const char *hnb_context_name(struct hnb_context *ctx);

void hnb_context_release(struct hnb_context *ctx);
void hnb_context_release_ue_state(struct hnb_context *ctx);

unsigned long long hnb_get_updowntime(const struct hnb_context *ctx);
void hnb_store_rab_durations(struct hnb_context *hnb);
