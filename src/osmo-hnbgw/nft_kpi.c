/* Set up and read internet traffic counters using netfilter */
/* Copyright (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
 */

#include <stdbool.h>
#include <ctype.h>

#include <nftables/libnftables.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/hnbgw/nft_kpi.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/tdefs.h>

struct nft_kpi_state {
	struct {
		struct nft_ctx *nft_ctx;
		char *table_name;
		bool table_created;
	} nft;
	struct osmo_timer_list period;
};

static struct nft_kpi_state g_nft_kpi_state = {};

static struct nft_ctx *g_nft_ctx(void)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;

	if (s->nft.nft_ctx)
		return s->nft.nft_ctx;

	s->nft.nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!s->nft.nft_ctx) {
		LOGP(DNFT, LOGL_ERROR, "cannot allocate libnftables nft_ctx\n");
		OSMO_ASSERT(false);
	}

	return s->nft.nft_ctx;
}

static int nft_run_now(const char *buffer)
{
	int rc;
	const int logmax = 256;

	rc = nft_run_cmd_from_buffer(g_nft_ctx(), buffer);
	if (rc < 0) {
		LOGP(DNFT, LOGL_ERROR, "error running nft buffer: rc=%d buffer=%s\n",
		     rc, osmo_quote_str_c(OTC_SELECT, buffer, -1));
		return -EIO;
	}

	if (log_check_level(DNFT, LOGL_DEBUG)) {
		size_t l = strlen(buffer);
		LOGP(DNFT, LOGL_DEBUG, "ran nft buffer, %zu chars: \"%s%s\"\n",
		     l,
		     osmo_escape_cstr_c(OTC_SELECT, buffer, OSMO_MIN(logmax, l)),
		     l > logmax ? "..." : "");
	}

	return 0;
}

static void nft_kpi_period_cb(void *data);

static void nft_kpi_period_schedule(void)
{
	unsigned long period = osmo_tdef_get(hnbgw_T_defs, -34, OSMO_TDEF_S, 10);
	if (period < 1)
		period = 1;
	osmo_timer_setup(&g_nft_kpi_state.period, nft_kpi_period_cb, NULL);
	osmo_timer_schedule(&g_nft_kpi_state.period, period, 0);
}

static int nft_kpi_init(void)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;

	if (s->nft.table_created)
		return 0;

	if (!s->nft.table_name || !*s->nft.table_name)
		s->nft.table_name = talloc_strdup(g_hnbgw, "osmo-hnbgw");

	if (nft_run_now(talloc_asprintf(OTC_SELECT, "add table inet %s { flags owner; };\n", s->nft.table_name)))
		return -EIO;

	s->nft.table_created = true;
	nft_kpi_period_schedule();
	return 0;
}

/* Set up counters for the hNodeB's remote address */
int hnb_nft_kpi_start(struct hnb_persistent *hnbp)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;
	char *cmd;

	nft_kpi_init();

	hnbp->nft_kpi.last.rx = (struct nft_kpi_val){};
	hnbp->nft_kpi.last.tx = (struct nft_kpi_val){};

	cmd = talloc_asprintf(OTC_SELECT,
			      "add chain inet %s hnb-rx-%s {"
			      " type filter hook input priority filter;"
			      " ip protocol udp udp sport 2152 udp dport 2152 ip saddr %s counter;"
			      "};\n"
			      "add chain inet %s hnb-tx-%s {"
			      " type filter hook output priority filter;"
			      " ip protocol udp udp sport 2152 udp dport 2152 ip daddr %s counter;"
			      "};\n",
			      s->nft.table_name,
			      hnbp->id_str,
			      hnbp->nft_kpi.addr_remote.ip,
			      s->nft.table_name,
			      hnbp->id_str,
			      hnbp->nft_kpi.addr_remote.ip);
	return nft_run_now(cmd);
}

int hnb_nft_kpi_end(struct hnb_persistent *hnbp)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;
	char *cmd;

	if (!s->nft.table_created)
		return 0;

	if (!osmo_sockaddr_str_is_nonzero(&hnbp->nft_kpi.addr_remote))
		return 0;
	hnbp->nft_kpi.addr_remote = (struct osmo_sockaddr_str){};

	cmd = talloc_asprintf(OTC_SELECT,
			      "delete chain inet %s hnb-rx-%s;\n"
			      "delete chain inet %s hnb-tx-%s;\n",
			      s->nft.table_name,
			      hnbp->id_str,
			      s->nft.table_name,
			      hnbp->id_str);
	return nft_run_now(cmd);
}

static void update_ctr(struct rate_ctr_group *cg, int cgidx, uint64_t *last_val, uint64_t new_val)
{
	if (new_val <= *last_val)
		return;
	rate_ctr_add2(cg, cgidx, new_val - *last_val);
	*last_val = new_val;
}

static void hnb_update_counters(struct hnb_persistent *hnbp, bool rx, int64_t packets, int64_t bytes)
{
	update_ctr(hnbp->ctrs,
		   rx ? HNB_CTR_GTPU_UPLOAD_PACKETS : HNB_CTR_GTPU_DOWNLOAD_PACKETS,
		   rx ? &hnbp->nft_kpi.last.rx.packets : &hnbp->nft_kpi.last.tx.packets,
		   packets);
	update_ctr(hnbp->ctrs,
		   rx ? HNB_CTR_GTPU_UPLOAD_GTP_BYTES : HNB_CTR_GTPU_DOWNLOAD_GTP_BYTES,
		   rx ? &hnbp->nft_kpi.last.rx.bytes : &hnbp->nft_kpi.last.tx.bytes,
		   bytes);
}

const char *nft_kpi_read_counters(void)
{
	int rc;
	const int logmax = 256;
	struct nft_kpi_state *s = &g_nft_kpi_state;
	struct nft_ctx *nft = s->nft.nft_ctx;
	char *cmd;
	const char *output = NULL;
	const char *pos;
	char buf[128];

	if (!nft)
		return NULL;

	cmd = talloc_asprintf(OTC_SELECT, "list table inet %s", s->nft.table_name);

	rc = nft_ctx_buffer_output(nft);
	if (rc) {
		LOGP(DNFT, LOGL_ERROR, "error: nft_ctx_buffer_output() returned failure: rc=%d cmd=%s\n",
		     rc, osmo_quote_str_c(OTC_SELECT, cmd, -1));
		goto unbuffer_and_exit;
	}
	rc = nft_run_cmd_from_buffer(nft, cmd);
	if (rc < 0) {
		LOGP(DNFT, LOGL_ERROR, "error running nft cmd: rc=%d cmd=%s\n",
		     rc, osmo_quote_str_c(OTC_SELECT, cmd, -1));
		goto unbuffer_and_exit;
	}
	if (log_check_level(DNFT, LOGL_DEBUG)) {
		size_t l = strlen(cmd);
		LOGP(DNFT, LOGL_DEBUG, "ran nft request, %zu chars: \"%s%s\"\n",
		     l,
		     osmo_escape_cstr_c(OTC_SELECT, cmd, OSMO_MIN(logmax, l)),
		     l > logmax ? "..." : "");
	}

	output = nft_ctx_get_output_buffer(nft);

	pos = output;
	while (*pos) {
		const char *id, *id_end;
		const char *chain_end;
		const char *counter;
		const char *counter_end;
		int64_t packets;
		int64_t bytes;
		bool rx;
		struct hnb_persistent *hnbp;

		id = strstr(pos, "chain hnb-");
		if (!id)
			break;
		id += 10;

		if (osmo_str_startswith(id, "rx-"))
			rx = true;
		else if (osmo_str_startswith(id, "tx-"))
			rx = false;
		else
			break;
		id += 3;

		id_end = id;
		while (*id_end && *id_end != ' ' && *id_end != '{')
			id_end++;

		osmo_strlcpy(buf, id, OSMO_MIN(sizeof(buf), id_end - id + 1));

		hnbp = hnb_persistent_find_by_id_str(buf);
		if (!hnbp)
			break;

		if (!osmo_str_startswith(id_end, " {"))
			break;
		chain_end = id_end + 2;
		while (*chain_end && *chain_end != '}')
			chain_end++;

		counter = strstr(id_end + 2, "counter packets ");
		if (!counter)
			break;
		counter += 16;
		if (counter > chain_end)
			break;
		if (!isdigit(*counter))
			break;

		counter_end = counter;
		while (isdigit(*counter_end))
			counter_end++;
		if (counter_end > chain_end)
			break;
		osmo_strlcpy(buf, counter, OSMO_MIN(sizeof(buf), counter_end - counter + 1));
		if (osmo_str_to_int64(&packets, buf, 10, 0, INT64_MAX))
			break;
		if (packets < 0)
			break;

		counter = strstr(counter_end, " bytes ");
		if (!counter)
			break;
		counter += 7;
		if (counter > chain_end)
			break;
		if (!isdigit(*counter))
			break;
		counter_end = counter;
		while (isdigit(*counter_end))
			counter_end++;
		if (counter_end > chain_end)
			break;
		osmo_strlcpy(buf, counter, OSMO_MIN(sizeof(buf), counter_end - counter + 1));
		if (osmo_str_to_int64(&bytes, buf, 10, 0, INT64_MAX))
			break;
		if (bytes < 0)
			break;

		hnb_update_counters(hnbp, rx, packets, bytes);

		pos = chain_end + 1;
	}

unbuffer_and_exit:
	nft_ctx_unbuffer_output(nft);
	return output;
}

static void nft_kpi_period_cb(void *data)
{
	nft_kpi_read_counters();
	nft_kpi_period_schedule();
}
