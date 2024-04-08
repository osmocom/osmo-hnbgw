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

#include <osmocom/core/logging.h>
#include <osmocom/hnbgw/hnbgw.h>

#include "config.h"

#if !ENABLE_NFTABLES

int hnb_nft_kpi_start(struct hnb_persistent *hnbp, const struct osmo_sockaddr_str *gtpu_remote)
{
	LOGP(DNFT, LOGL_INFO, "Built without libnftables support, not starting nft based counters for HNB %s\n",
	     hnbp->id_str);
	return 0;
}

int hnb_nft_kpi_end(struct hnb_persistent *hnbp)
{
	return 0;
}

#else

#include <stdbool.h>
#include <ctype.h>
#include <inttypes.h>

#include <nftables/libnftables.h>

#include <osmocom/core/timer.h>
#include <osmocom/hnbgw/nft_kpi.h>
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

	nft_ctx_output_set_flags(s->nft.nft_ctx, NFT_CTX_OUTPUT_HANDLE);

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

int nft_kpi_init(const char *table_name)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };

	if (s->nft.table_created)
		return 0;

	if (!table_name || !*table_name)
		table_name = "osmo-hnbgw";
	osmo_talloc_replace_string(g_hnbgw, &s->nft.table_name, table_name);

	OSMO_STRBUF_PRINTF(sb, "add table inet %s { flags owner; };\n", s->nft.table_name);
	OSMO_STRBUF_PRINTF(sb,
			   "add chain inet %s gtpu-ul {"
			   " type filter hook prerouting priority 0; policy accept;"
			   " ip protocol != udp accept;"
			   " udp sport != 2152 accept;"
			   " udp dport != 2152 accept;"
			   "};\n",
			   s->nft.table_name);
	OSMO_STRBUF_PRINTF(sb,
			   "add chain inet %s gtpu-dl {"
			   " type filter hook postrouting priority 0; policy accept;"
			   " ip protocol != udp accept;"
			   " udp sport != 2152 accept;"
			   " udp dport != 2152 accept;"
			   "};\n",
			   s->nft.table_name);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));

	if (nft_run_now(cmd))
		return -EIO;

	s->nft.table_created = true;
	nft_kpi_period_schedule();
	return 0;
}

/* Set up counters for the hNodeB's remote address */
int hnb_nft_kpi_start(struct hnb_persistent *hnbp, const struct osmo_sockaddr_str *gtpu_remote)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };
	int rc;

	if (!osmo_sockaddr_str_is_nonzero(gtpu_remote)) {
		LOGP(DNFT, LOGL_ERROR, "HNB %s: invalid remote GTP-U address: " OSMO_SOCKADDR_STR_FMT "\n",
		     hnbp->id_str, OSMO_SOCKADDR_STR_FMT_ARGS(gtpu_remote));
		return -EINVAL;
	}

	if (!osmo_sockaddr_str_cmp(gtpu_remote, &hnbp->nft_kpi.addr_remote)) {
		/* The remote address is unchanged, no need to update the nft probe */
		return 0;
	}

	/* When there is no table created, it means nft is disabled. Do not attempt to set up counters. */
	if (!s->nft.table_created)
		return 0;

	/* The remote address has changed. Cancel previous probe, if any, and start a new one. */
	if (osmo_sockaddr_str_is_nonzero(&hnbp->nft_kpi.addr_remote))
		hnb_nft_kpi_end(hnbp);

	hnbp->nft_kpi.last.ul = (struct nft_kpi_val){};
	hnbp->nft_kpi.last.dl = (struct nft_kpi_val){};

	hnbp->nft_kpi.addr_remote = *gtpu_remote;

	OSMO_STRBUF_PRINTF(sb, "add rule inet %s gtpu-ul ip saddr %s counter comment \"ul:%s\";\n",
			   s->nft.table_name,
			   hnbp->nft_kpi.addr_remote.ip,
			   hnbp->id_str);
	OSMO_STRBUF_PRINTF(sb, "add rule inet %s gtpu-dl ip daddr %s counter comment \"dl:%s\";\n",
			   s->nft.table_name,
			   hnbp->nft_kpi.addr_remote.ip,
			   hnbp->id_str);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));

	rc = nft_run_now(cmd);
	if (rc) {
		/* There was an error running the rule, clear addr_remote to indicate that no rule exists. */
		hnbp->nft_kpi.addr_remote = (struct osmo_sockaddr_str){};
	}
	return rc;
}

static void nft_kpi_read_counters(void);

/* Terminate nft based counters for this HNB */
int hnb_nft_kpi_end(struct hnb_persistent *hnbp)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;
	char *cmd;

	/* When there is no table created, neither can there be any rules to be deleted.
	 * The rules get removed, but the table remains present for as long as osmo-hnbgw runs. */
	if (!s->nft.table_created)
		return 0;

	/* presence of addr_remote indicates whether an nft rule has been submitted and still needs to be removed */
	if (!osmo_sockaddr_str_is_nonzero(&hnbp->nft_kpi.addr_remote))
		return 0;

	if (!hnbp->nft_kpi.last.ul.handle_present
	    || !hnbp->nft_kpi.last.dl.handle_present) {
		/* We get to know the nft handles only after creating the rule, when querying the counters. If the
		 * handle is not known here yet, then it means we haven't read the counters yet. We have to find out the
		 * handle now. */
		nft_kpi_read_counters();
	}

	/* clear the addr to indicate that the nft rule no longer exists. Even if below 'delete rule' fails, just
	 * attempt to delete the rule once. */
	hnbp->nft_kpi.addr_remote = (struct osmo_sockaddr_str){};

	cmd = talloc_asprintf(OTC_SELECT,
			      "delete rule inet %s gtpu-ul handle %"PRId64";\n"
			      "delete rule inet %s gtpu-dl handle %"PRId64";\n",
			      s->nft.table_name,
			      hnbp->nft_kpi.last.ul.handle,
			      s->nft.table_name,
			      hnbp->nft_kpi.last.dl.handle);
	return nft_run_now(cmd);
}

static void update_ctr(struct rate_ctr_group *cg, int cgidx, uint64_t *last_val, uint64_t new_val)
{
	/* Because an hNodeB may re-connect, or even change the address it connects from, we need to store the last seen
	 * value and add the difference to the rate counter. For example, the rate_ctr that lives in hnb_persistent has
	 * seen 100 GTP-U packets. The hNodeB disconnects for ten seconds and then comes back. Now the nft ruleset has
	 * been deleted and re-created, so the counters we read are back at 0, but we want to continue showing 100. When
	 * the ruleset detects 10, we want to show 110. Hence this last_val stuff here.
	 * last_val is also back to zero whenever the nft counters are restarted, see hnb_nft_kpi_start(), where
	 * hnbp->nft_kpi.last.ul and last.dl are zeroed.
	 */
	if (new_val > *last_val)
		rate_ctr_add2(cg, cgidx, new_val - *last_val);
	*last_val = new_val;
}

static void hnb_update_counters(struct hnb_persistent *hnbp, bool ul, int64_t packets, int64_t bytes, int64_t handle)
{
	struct nft_kpi_val *val = (ul ? &hnbp->nft_kpi.last.ul : &hnbp->nft_kpi.last.dl);

	/* Remember the nftables handle, which is needed to remove a rule when a hNodeB disconnects. */
	if (handle) {
		val->handle_present = true;
		val->handle = handle;
	}

	update_ctr(hnbp->ctrs,
		   ul ? HNB_CTR_GTPU_PACKETS_UL : HNB_CTR_GTPU_PACKETS_DL,
		   &val->packets, packets);
	update_ctr(hnbp->ctrs,
		   ul ? HNB_CTR_GTPU_TOTAL_BYTES_UL : HNB_CTR_GTPU_TOTAL_BYTES_DL,
		   &val->total_bytes, bytes);

	/* Assuming an IP header of 20 bytes, derive the GTP-U payload size:
	 *
	 *  [...]             \              \
	 *  [ UDP ][ TCP ]    | UE payload   | nft reports these bytes
	 *  [ IP ]            /              |
	 *  -- payload --                    |
	 *  [ GTP-U 8 bytes ]                |   \
	 *  [ UDP 8 bytes ]                  |   | need to subtract these, ~20 + 8 + 8
	 *  [ IP 20 bytes ]                  /   /
	 */
	update_ctr(hnbp->ctrs,
		   ul ? HNB_CTR_GTPU_UE_BYTES_UL : HNB_CTR_GTPU_UE_BYTES_DL,
		   &val->ue_bytes, bytes - OSMO_MIN(bytes, packets * (20 + 8 + 8)));
}

/* In the string section *pos .. end, find the first occurrence of after_str and return the following token, which ends
 * by a space or at end. If end is NULL, search until the '\0' termination of *pos.
 * Return true if after_str was found, copy the following token into buf, and in *pos, return the position just after
 * that token. */
static bool get_token_after(char *buf, size_t buflen, const char **pos, const char *end, const char *after_str)
{
	const char *found = strstr(*pos, after_str);
	const char *token_end;
	size_t token_len;
	if (!found)
		return false;
	if (end && found >= end) {
		*pos = end;
		return false;
	}
	found += strlen(after_str);
	while (*found && *found == ' ' && (!end || found < end))
		found++;
	token_end = found;
	while (*token_end != ' ' && (!end || token_end < end))
		token_end++;
	if (token_end <= found) {
		*pos = found;
		return false;
	}
	if (*found == '"' && token_end > found + 1 && *(token_end - 1) == '"') {
		found++;
		token_end--;
	}
	token_len = token_end - found;
	token_len = OSMO_MIN(token_len, buflen - 1);
	memcpy(buf, found, token_len);
	buf[token_len] = '\0';
	*pos = token_end;
	return true;
}

static void decode_nft_response(const char *response)
{
	struct nft_kpi_state *s = &g_nft_kpi_state;
	const char *pos;
	char buf[128];
	int count = 0;

	/* find and parse all occurences of strings like:
	 *    [...] counter packets 3 bytes 129 comment "ul:001-01-L2-R3-S4-C1" # handle 10
	 */
	pos = response;
	while (*pos) {
		const char *line_end;
		int64_t packets;
		int64_t bytes;
		int64_t handle = 0;
		bool ul;
		struct hnb_persistent *hnbp;

		if (!get_token_after(buf, sizeof(buf), &pos, NULL, "counter packets "))
			break;
		if (osmo_str_to_int64(&packets, buf, 10, 0, INT64_MAX))
			break;
		line_end = strchr(pos, '\n');
		if (!line_end)
			line_end = pos + strlen(pos);

		if (!get_token_after(buf, sizeof(buf), &pos, line_end, "bytes "))
			break;
		if (osmo_str_to_int64(&bytes, buf, 10, 0, INT64_MAX))
			break;

		if (!get_token_after(buf, sizeof(buf), &pos, line_end, "comment "))
			break;

		if (osmo_str_startswith(buf, "ul:"))
			ul = true;
		else if (osmo_str_startswith(buf, "dl:"))
			ul = false;
		else
			break;

		hnbp = hnb_persistent_find_by_id_str(buf + 3);
		if (!hnbp)
			break;

		if (!get_token_after(buf, sizeof(buf), &pos, line_end, "# handle "))
			break;
		if (osmo_str_to_int64(&handle, buf, 10, 0, INT64_MAX))
			break;

		hnb_update_counters(hnbp, ul, packets, bytes, handle);
		count++;
	}

	LOGP(DNFT, LOGL_DEBUG, "read %d counters from nft table %s\n", count, s->nft.table_name);
}

static void nft_kpi_read_counters(void)
{
	int rc;
	const int logmax = 256;
	struct nft_kpi_state *s = &g_nft_kpi_state;
	struct nft_ctx *nft = s->nft.nft_ctx;
	char cmd[256];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };
	const char *output;

	if (!nft)
		return;

	OSMO_STRBUF_PRINTF(sb, "list table inet %s", s->nft.table_name);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));

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

	output = nft_ctx_get_output_buffer(nft);
	if (log_check_level(DNFT, LOGL_DEBUG)) {
		size_t l = strlen(cmd);
		LOGP(DNFT, LOGL_DEBUG, "ran nft request, %zu chars: \"%s%s\"\n",
		     l,
		     osmo_escape_cstr_c(OTC_SELECT, cmd, OSMO_MIN(logmax, l)),
		     l > logmax ? "..." : "");
		l = strlen(output);
		LOGP(DNFT, LOGL_DEBUG, "got nft response, %zu chars: \"%s%s\"\n",
		     l,
		     osmo_escape_cstr_c(OTC_SELECT, output, OSMO_MIN(logmax, l)),
		     l > logmax ? "..." : "");
	}

	decode_nft_response(output);

unbuffer_and_exit:
	nft_ctx_unbuffer_output(nft);
}

static void nft_kpi_period_cb(void *data)
{
	nft_kpi_read_counters();
	nft_kpi_period_schedule();
}

#endif // ENABLE_NFTABLES
