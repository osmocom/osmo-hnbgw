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

#include <inttypes.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/it_q.h>
#include <osmocom/hnbgw/hnb_persistent.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/nft_kpi.h>
#include <osmocom/hnbgw/umts_cell_id.h>

#include "config.h"

#if !ENABLE_NFTABLES

/* These are stubs that do nothing, for compiling osmo-hnbgw without nftables support.
 * They allow keeping lots of #if .. #endif out of the remaining code base of osmo-hnbgw. */

void nft_kpi_init(const char *table_name)
{
	LOGP(DNFT, LOGL_NOTICE, "Built without libnftables support, not initializing nft based counters\n");
}

void nft_kpi_hnb_persistent_add(struct hnb_persistent *hnbp)
{
}

void nft_kpi_hnb_persistent_remove(struct hnb_persistent *hnbp)
{
}

int nft_kpi_hnb_start(struct hnb_persistent *hnbp, const struct osmo_sockaddr_str *gtpu_remote)
{
	return 0;
}

void nft_kpi_hnb_stop(struct hnb_persistent *hnbp)
{
}

#else

#include <stdbool.h>
#include <ctype.h>
#include <inttypes.h>

#include <nftables/libnftables.h>

#include <osmocom/hnbgw/nft_kpi.h>
#include <osmocom/hnbgw/tdefs.h>

/* This implements setting up and retrieving packet and byte counters for GTP-U traffic per-hNodeB via nftables. The aim
 * is merely to increment rate counters accurately with GTP-U traffic seen to/from each hNodeB.
 * See HNB_CTR_GTPU_PACKETS_UL and friends.
 *
 * A worker thread implementation offloads nftables interaction from the main thread. There is a single "instruction
 * set" (enum nft_thread_req_type), but any number of worker threads can be run to split the actual work.
 *
 * At the time of writing, there are two worker threads: one worker thread does all the nftables chain and rule
 * additions and removals (see static struct nft_thread nft_maintenance), and a second worker does all and only the
 * counter retrieval (static struct nft_thread nft_counters); the main thread decides which worker does what.
 *
 * The main thread dispatches requests to worker threads via an osmo_it_q, and receives the responses via another
 * osmo_it_q in reverse direction. The response is the exact same request struct simply sent back to the main thread.
 * (It is important that a talloc object is freed by the same thread that allocated it.)
 *
 * The response yields nft_thread_req->rc == 0 on success, and may also communicate other data; see nft_thread_req.
 * It is always the main thread that allocates and deallocates these struct nft_thread_req instances.
 * Not to be confused with the struct nft_counter[] cache in nft_thread_req->get_counters, owned by a worker, s.b..
 *
 * Maintenance: some nftables items are identified by name (the "persistent" named counters use the cell id string).
 * Others are unnamed rules that require a "handle" returned from nftables, so that we can remove them later. These
 * handles are sent back to the main thread via nft_thread_req, see nft_thread_req.hnb_start.
 *
 * Retrieving counters from nft: the nftables response is parsed to a cache (array of struct nft_counter), which is
 * allocated by a worker thread and kept for re-use; it is only reallocated to make room for more hNodeB counters, and
 * never shrinks or deallocates.
 *
 * nftables ruleset:
 * - one table per osmo-hnbgw process, the table name is configurable by VTY cfg.
 * - a global set of chains implements matching GTP-U packets (UDP port 2152).
 * - for each hnb_persistent (for each umts_cell_id), there is a named counter, accumulating packets and bytes for the
 *   entire lifetime of the hnb_persistent.
 * - rules are added for each connected hNodeB, to increment the named counters for that cell id. When an hNodeB
 *   disconnects from Iuh, the named counter for the cell id remains in nftables, but the UL and DL rules that feed to
 *   the named counter are deleted: a counter only increments when osmo-hnbgw regards the hNodeB as currently active.
 */

/* "Cache" for counters read from an nft response, to be forwarded to the main thread.
 * Each cell id has two of these, one for uplink (ul == true) and one for downlink. */
struct nft_counter {
	struct umts_cell_id cell_id;
	bool ul;
	struct nft_kpi_val val;
};

/* State for one nft worker thread. Provided and initialized by the main thread, then passed on to the nft_thread_main()
 * function via pthread_create(). */
struct nft_thread {
	/* Label for logging about the thread. */
	const char *label;

	/* nftables table name, a copy of the table name passed to nft_kpi_init(). */
	const char *table_name;

	/* request/response queues: main to worker thread, and worker thread to main. */
	struct osmo_it_q *m2t;
	struct osmo_it_q *t2m;

	pthread_t thread;

	/* nftables context to dispatch nftables rulesets. Accessed only from worker thread functions. */
	struct nft_ctx *nft_ctx;
	/* Just a number for logging, to help figure out possibly concurrent nft commands from different threads. */
	unsigned int cmd_log_id;

	/* Persistent memory re-used for the NFT_THREAD_GET_COUNTERS request. Thread workers that don't read counters
	 * leave this empty/NULL. */
	struct nft_counter *counters;
	size_t counters_len;
	size_t counters_alloc;
};

/* If a thread can run nftables commands, this points at a struct nft_thread containing its inter-thread queues and
 * nft_ctx. Set by nft_thread_main(). */
static __thread struct nft_thread *g_nft_thread = NULL;

/* worker thread: Run an nftables rule set and optionally handle the nftables response string. */
static int nft_run_now(const char *cmd,
		       int (*handle_result)(const char *result, void *arg), void *handle_result_arg)
{
	int rc;
	unsigned int nft_cmd_log_id;
	struct nft_ctx *nft_ctx;
	const int logmax = 256;
	bool dbg = log_check_level(DNFT, LOGL_DEBUG);

	OSMO_ASSERT(g_nft_thread && g_nft_thread->nft_ctx);
	nft_ctx = g_nft_thread->nft_ctx;

	nft_cmd_log_id = g_nft_thread->cmd_log_id++;

	if (handle_result) {
		rc = nft_ctx_buffer_output(nft_ctx);
		if (rc) {
			LOGP(DNFT, LOGL_ERROR, "error: nft_ctx_buffer_output() returned failure: rc=%d\n", rc);
			return rc;
		}
	}

	if (dbg) {
		size_t l = strlen(cmd);
		LOGP(DNFT, LOGL_DEBUG, "running nft cmd %s#%u, %zu chars: \"%s%s\"\n",
		     g_nft_thread->label, nft_cmd_log_id, l,
		     osmo_escape_cstr_c(OTC_SELECT, cmd, OSMO_MIN(logmax, l)),
		     l > logmax ? "..." : "");
	}

	rc = nft_run_cmd_from_buffer(nft_ctx, cmd);
	if (rc < 0) {
		LOGP(DNFT, LOGL_ERROR, "error running nft cmd %s#%u: rc=%d cmd=%s\n",
		     g_nft_thread->label, nft_cmd_log_id, rc, osmo_quote_str_c(OTC_SELECT, cmd, -1));
	} else if (handle_result) {
		const char *output = nft_ctx_get_output_buffer(nft_ctx);

		if (dbg) {
			size_t l = strlen(output);
			LOGP(DNFT, LOGL_DEBUG, "got response for nft cmd %s#%u: %zu chars: \"%s%s\"\n",
			     g_nft_thread->label, nft_cmd_log_id, l,
			     osmo_escape_cstr_c(OTC_SELECT, output, OSMO_MIN(logmax, l)),
			     l > logmax ? "..." : "");
		}

		rc = handle_result(output, handle_result_arg);
	} else if (dbg) {
		/* Make sure some dbg logging marks the end of running the nft cmd, to be able to investigate timing. */
		LOGP(DNFT, LOGL_DEBUG, "done running nft cmd %s#%u\n", g_nft_thread->label, nft_cmd_log_id);
	}

	if (handle_result)
		nft_ctx_unbuffer_output(nft_ctx);

	return rc;
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
	while (*found && isspace(*found) && (!end || found < end))
		found++;
	token_end = found;
	while (!isspace(*token_end) && (!end || token_end < end))
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

enum nft_thread_req_type {
	NFT_THREAD_INIT_TABLE,

	NFT_THREAD_HNB_PERSISTENT_INIT,
	NFT_THREAD_HNB_PERSISTENT_REMOVE,
	NFT_THREAD_HNB_START,
	NFT_THREAD_HNB_STOP,

	NFT_THREAD_GET_COUNTERS,
};

/* enum nft_thread_req_type lives only within this .c file, so use direct array access instead of value_string
 * iteration, only used for logging. */
static const char * const nft_thread_req_type_name[] = {
	[NFT_THREAD_INIT_TABLE] = "INIT_TABLE",
	[NFT_THREAD_HNB_PERSISTENT_INIT] = "HNB_PERSISTENT_INIT",
	[NFT_THREAD_HNB_PERSISTENT_REMOVE] = "HNB_PERSISTENT_REMOVE",
	[NFT_THREAD_HNB_START] = "HNB_START",
	[NFT_THREAD_HNB_STOP] = "HNB_STOP",
	[NFT_THREAD_GET_COUNTERS] = "GET_COUNTERS",
};

/* One request dispatched in an inter-thread queue to a worker thread, and then passed back to the main thread. The main
 * thread allocates this; it makes a roundtrip to a worker thread and back via the two it-queues, to be freed again by
 * the main thread. */
struct nft_thread_req {
	struct llist_head it_q_entry;

	enum nft_thread_req_type type;
	union {
		struct {
			const char *table_name;
		} init;

		struct {
			/* request: */
			struct umts_cell_id cell_id;

			/* no response items */
		} hnbp_init_remove;

		struct {
			/* request: */
			struct umts_cell_id cell_id;
			struct osmo_sockaddr_str gtpu_remote;

			/* response: */
			struct nft_kpi_handle ul;
			struct nft_kpi_handle dl;
		} hnb_start;

		struct {
			/* request: pass same handles as returned earlier by hnb_start. */
			struct nft_kpi_handle ul;
			struct nft_kpi_handle dl;

			/* no response items */
		} hnb_stop;

		struct {
			/* no request items */

			/* response: */
			struct nft_counter *counters;
			size_t counters_len;
		} get_counters;
	};

	/* Return code indicating failure or success, from worker thread back to main. */
	int rc;
};

/* worker thread: initialize the per-thread nft ctx */
static void do_nft_ctx_init(void)
{
	OSMO_ASSERT(g_nft_thread);
	OSMO_ASSERT(!g_nft_thread->nft_ctx);

	g_nft_thread->nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!g_nft_thread->nft_ctx) {
		LOGP(DNFT, LOGL_FATAL, "thread %s: Failed to initialize nft ctx\n", g_nft_thread->label);
		/* This only happens at program startup. Make sure the user is aware of broken counters and exit the
		 * program. */
		OSMO_ASSERT(false);
	}
	nft_ctx_output_set_flags(g_nft_thread->nft_ctx, NFT_CTX_OUTPUT_HANDLE | NFT_CTX_OUTPUT_ECHO);
	LOGP(DNFT, LOGL_DEBUG, "thread %s: successfully allocated nft ctx\n", g_nft_thread->label);
}

/* worker thread */
static int do_init_table(void)
{
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };

	/* add global nftables structures */
	OSMO_STRBUF_PRINTF(sb, "add table inet %s { flags owner; };\n", g_nft_thread->table_name);
	OSMO_STRBUF_PRINTF(sb,
			   "add chain inet %s gtpu-ul {"
			   " type filter hook prerouting priority 0; policy accept;"
			   " ip protocol != udp accept;"
			   " udp dport != 2152 accept;"
			   "};\n",
			   g_nft_thread->table_name);
	OSMO_STRBUF_PRINTF(sb,
			   "add chain inet %s gtpu-dl {"
			   " type filter hook postrouting priority 0; policy accept;"
			   " ip protocol != udp accept;"
			   " udp dport != 2152 accept;"
			   "};\n",
			   g_nft_thread->table_name);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));

	return nft_run_now(cmd, NULL, NULL);
}

/* worker thread */
static void nft_t2m_enqueue(struct nft_thread *t, struct nft_thread_req *req)
{
	LOGP(DNFT, LOGL_DEBUG, "main() <- %s: %s rc=%d\n", t->label, nft_thread_req_type_name[req->type], req->rc);
	osmo_it_q_enqueue(t->t2m, req, it_q_entry);
}

/* worker thread */
static int do_hnbp_init(struct nft_thread_req *req)
{
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };
	const char *cell_id_str = umts_cell_id_to_str(&req->hnbp_init_remove.cell_id);
	OSMO_STRBUF_PRINTF(sb,
			   "add counter inet %s ul-%s;\n"
			   "add counter inet %s dl-%s;\n",
			   g_nft_thread->table_name, cell_id_str,
			   g_nft_thread->table_name, cell_id_str);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));
	return nft_run_now(cmd, NULL, NULL);
}

/* worker thread */
static int do_hnbp_remove(struct nft_thread_req *req)
{
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };
	const char *cell_id_str = umts_cell_id_to_str(&req->hnbp_init_remove.cell_id);
	OSMO_STRBUF_PRINTF(sb,
			   "delete counter inet %s ul-%s;\n"
			   "delete counter inet %s dl-%s;\n",
			   g_nft_thread->table_name, cell_id_str,
			   g_nft_thread->table_name, cell_id_str);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));
	return nft_run_now(cmd, NULL, NULL);
}

/* worker thread */
static int do_hnb_start__read_handle(const char *result, void *arg)
{
	struct nft_kpi_handle *h = arg;
	char buf[128];
	const char *pos = result;
	if (!get_token_after(buf, sizeof(buf), &pos, NULL, "# handle "))
		return -ENOENT;
	int rc;
	rc = osmo_str_to_int64(&h->handle, buf, 10, 0, INT64_MAX);
	if (!rc)
		h->handle_present = true;
	return rc;
}

/* worker thread */
static int do_hnb_start(struct nft_thread_req *req)
{
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };
	const char *cell_id_str = umts_cell_id_to_str(&req->hnb_start.cell_id);
	int rc;

	OSMO_STRBUF_PRINTF(sb,
			   "add rule inet %s gtpu-ul ip saddr %s counter name ul-%s;\n",
			   g_nft_thread->table_name,
			   req->hnb_start.gtpu_remote.ip,
			   cell_id_str);
	rc = nft_run_now(cmd, do_hnb_start__read_handle, &req->hnb_start.ul);

	if (!rc && req->hnb_start.ul.handle_present) {
		LOGP(DNFT, LOGL_DEBUG, "nft rule handle for %s UL: %"PRId64"\n",
		     cell_id_str,
		     req->hnb_start.ul.handle);
	} else {
		LOGP(DNFT, LOGL_ERROR, "failed to parse rule handle for %s UL from nft response\n",
		     cell_id_str);
		if (!rc)
			rc = -EINVAL;
		return rc;
	}

	/* new cmd */
	sb = (struct osmo_strbuf){ .buf = cmd, .len = sizeof(cmd) };
	OSMO_STRBUF_PRINTF(sb,
			   "add rule inet %s gtpu-dl ip daddr %s counter name dl-%s;\n",
			   g_nft_thread->table_name,
			   req->hnb_start.gtpu_remote.ip,
			   cell_id_str);
	rc = nft_run_now(cmd, do_hnb_start__read_handle, &req->hnb_start.dl);

	if (!rc && req->hnb_start.dl.handle_present) {
		LOGP(DNFT, LOGL_DEBUG, "nft rule handle for %s DL: %"PRId64"\n",
		     cell_id_str,
		     req->hnb_start.dl.handle);
	} else {
		LOGP(DNFT, LOGL_ERROR, "failed to parse rule handle for %s DL from nft response\n",
		     cell_id_str);
		if (!rc)
			rc = -EINVAL;
	}
	return rc;
}

/* worker thread */
static int do_hnb_stop(struct nft_thread_req *req)
{
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };

	if (req->hnb_stop.ul.handle_present)
		OSMO_STRBUF_PRINTF(sb,
				   "delete rule inet %s gtpu-ul handle %"PRId64";\n",
				   g_nft_thread->table_name,
				   req->hnb_stop.ul.handle);

	if (req->hnb_stop.dl.handle_present)
		OSMO_STRBUF_PRINTF(sb,
				   "delete rule inet %s gtpu-dl handle %"PRId64";\n",
				   g_nft_thread->table_name,
				   req->hnb_stop.dl.handle);
	if (!sb.chars_needed)
		return 0;

	return nft_run_now(cmd, NULL, NULL);
}

/* worker thread */
static void nft_thread_cache_counter_val(const struct umts_cell_id *cell_id, bool ul, int64_t packets, int64_t bytes)
{
	struct nft_counter *tgt;

	OSMO_ASSERT(g_nft_thread);

	/* Make sure the counters cache is large enough */
	if (g_nft_thread->counters_len + 1 > g_nft_thread->counters_alloc) {
		/* allocate much more than needed now, to limit number of reallocations. */
		size_t want = g_nft_thread->counters_len + 64;

		if (g_nft_thread->counters_len) {
			g_nft_thread->counters = talloc_realloc(OTC_GLOBAL, g_nft_thread->counters, struct nft_counter,
								want);
		} else {
			if (g_nft_thread->counters)
				talloc_free(g_nft_thread->counters);
			g_nft_thread->counters = talloc_array(OTC_GLOBAL, struct nft_counter, want);
		}
	}

	tgt = &g_nft_thread->counters[g_nft_thread->counters_len];
	*tgt = (struct nft_counter){
		.cell_id = *cell_id,
		.ul = ul,
		.val = {
			.packets = packets,
			.total_bytes = bytes,

			/* Assuming an IP header of 20 bytes, derive the GTP-U payload size:
			 *
			 *  [...]             \              \
			 *  [ UDP ][ TCP ]    | UE payload   | nft reports these bytes
			 *  [ IP ]            /              |
			 *  -- payload --                    |
			 *  [ GTP-U 8 bytes ]                |   \
			 *  [ UDP 8 bytes ]                  |   | need to subtract these, 20 + 8 + 8
			 *  [ IP 20 bytes ]                  /   /
			 */
			.ue_bytes = bytes - OSMO_MIN(bytes, packets * (20 + 8 + 8)),
		},
	};

	g_nft_thread->counters_len++;
}

/* worker thread */
static int parse_counters_response(const char *result, void *arg)
{
	const char *pos;
	char buf[128];
	char cell_id_str_buf[128];
	int count = 0;

	/* find and parse all occurences of strings like:
	 *
	 *    counter ul-001-01-L1-R2-S3-C4 { # handle 123
	 *            packets 123 bytes 4567
	 *    }
	 *    counter dl-001-01-L1-R2-S3-C4 { # handle 124
	 *            packets 789 bytes 101112
	 *    }
	 */
	pos = result;
	while (*pos) {
		const char *counter_end;
		const char *cell_id_str;
		struct umts_cell_id cell_id;
		int64_t packets;
		int64_t bytes;
		bool ul;

		if (!get_token_after(cell_id_str_buf, sizeof(cell_id_str_buf), &pos, NULL, "\tcounter "))
			break;
		counter_end = strstr(pos, "\t}");

		if (osmo_str_startswith(cell_id_str_buf, "ul-"))
			ul = true;
		else if (osmo_str_startswith(cell_id_str_buf, "dl-"))
			ul = false;
		else
			continue;
		cell_id_str = cell_id_str_buf + 3;
		if (umts_cell_id_from_str(&cell_id, cell_id_str))
			continue;

		if (!get_token_after(buf, sizeof(buf), &pos, counter_end, "\tpackets "))
			continue;
		if (osmo_str_to_int64(&packets, buf, 10, 0, INT64_MAX))
			continue;

		if (!get_token_after(buf, sizeof(buf), &pos, counter_end, " bytes "))
			continue;
		if (osmo_str_to_int64(&bytes, buf, 10, 0, INT64_MAX))
			continue;

		nft_thread_cache_counter_val(&cell_id, ul, packets, bytes);
		count++;
	}

	LOGP(DNFT, LOGL_DEBUG, "thread %s read %d counters from nft table %s\n",
	     g_nft_thread->label, count, g_nft_thread->table_name);
	return 0;
}

/* worker thread */
static int do_get_counters(void)
{
	char cmd[1024];
	struct osmo_strbuf sb = { .buf = cmd, .len = sizeof(cmd) };

	OSMO_ASSERT(g_nft_thread);

	OSMO_STRBUF_PRINTF(sb, "list counters table inet %s", g_nft_thread->table_name);
	OSMO_ASSERT(sb.chars_needed < sizeof(cmd));

	return nft_run_now(cmd, parse_counters_response, NULL);
}

/* worker thread, handling requests from the main thread */
static void nft_thread_m2t_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct nft_thread_req *req = (void *)item;
	switch (req->type) {
	case NFT_THREAD_INIT_TABLE:
		req->rc = do_init_table();
		break;

	case NFT_THREAD_HNB_PERSISTENT_INIT:
		req->rc = do_hnbp_init(req);
		break;

	case NFT_THREAD_HNB_PERSISTENT_REMOVE:
		req->rc = do_hnbp_remove(req);
		break;

	case NFT_THREAD_HNB_START:
		req->rc = do_hnb_start(req);
		break;
	case NFT_THREAD_HNB_STOP:
		req->rc = do_hnb_stop(req);
		break;

	case NFT_THREAD_GET_COUNTERS:
		/* "clear" the counters cache, keeping the memory allocated. */
		g_nft_thread->counters_len = 0;

		req->rc = do_get_counters();
		if (!req->rc) {
			/* From here on, until we receive the next NFT_THREAD_GET_COUNTERS in this thread, the
			 * g_nft_thread->counters are left untouched, for the main thread to read. IOW the main thread
			 * must not issue another NFT_THREAD_GET_COUNTERS command before it is done reading these. */
			req->get_counters.counters = g_nft_thread->counters;
			req->get_counters.counters_len = g_nft_thread->counters_len;
		}
		break;

	default:
		OSMO_ASSERT(false);
	}

	/* respond */
	nft_t2m_enqueue(g_nft_thread, req);
}

/* worker thread: main loop for both of the nft threads */
static void *nft_thread_main(void *thread)
{
	g_nft_thread = thread;

	osmo_ctx_init(g_nft_thread->label);
	osmo_select_init();
	OSMO_ASSERT(osmo_ctx_init(g_nft_thread->label) == 0);

	do_nft_ctx_init();

	OSMO_ASSERT(g_nft_thread->m2t);
	osmo_fd_register(&g_nft_thread->m2t->event_ofd);

	while (1)
		osmo_select_main_ctx(0);
}

static struct nft_thread nft_maintenance = { .label = "nft_maintenance", };
static struct nft_thread nft_counters = { .label = "nft_counters", };

static void nft_thread_t2m_cb(struct osmo_it_q *q, struct llist_head *item);

/* main thread */
static void nft_m2t_enqueue(struct nft_thread *t, struct nft_thread_req *req)
{
	LOGP(DNFT, LOGL_DEBUG, "main() -> %s: %s\n", t->label, nft_thread_req_type_name[req->type]);
	osmo_it_q_enqueue(t->m2t, req, it_q_entry);
}

/* timer in main() thread: ask for the next batch of counters from nft */
static void nft_kpi_get_counters_cb(void *data)
{
	struct nft_thread_req *req;

	/* When nft is disabled, no use asking for counters. */
	if (!g_hnbgw->nft_kpi.active)
		return;

	req = talloc_zero(g_hnbgw, struct nft_thread_req);
	*req = (struct nft_thread_req){
		.type = NFT_THREAD_GET_COUNTERS,
	};

	nft_m2t_enqueue(&nft_counters, req);
	/* Will evaluate the response in nft_thread_t2m_cb(), case NFT_THREAD_GET_COUNTERS. */
}

/* main thread */
static void nft_kpi_get_counters_schedule(void)
{
	struct timespec now;
	struct timespec period;
	struct timespec diff;
	struct timespec *next = &g_hnbgw->nft_kpi.next_timer;
	unsigned long period_us = osmo_tdef_get(hnbgw_T_defs, -34, OSMO_TDEF_US, 1000000);

	period.tv_sec = period_us / 1000000;
	period.tv_nsec = (period_us % 1000000) * 1000;

	/* Try to keep the period of getting counters close to the configured period, i.e. don't drift by the time it
	 * takes to read counters. */
	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	if (!next->tv_sec && !next->tv_nsec) {
		/* Not yet initialized. Schedule to get counters one 'period' from 'now':
		 * Set 'next' to 'now', and the period is added by timespecadd() below.
		 * (We could retrieve counters immediately -- but at startup counters are then queried even before the
		 * nft table was created by the maintenance thread. That is not harmful, but it causes an ugly error
		 * message in the logs. So rather wait one period.)
		 */
		*next = now;
	}
	timespecadd(next, &period, next);
	if (timespeccmp(next, &now, <)) {
		/* The time that has elapsed since last scheduling counter retrieval is already more than the configured
		 * period. Continue counting the time period from 'now', and ask for counters right now. */
		timespecsub(&now, next, &diff);
		LOGP(DNFT, LOGL_NOTICE, "nft-kpi: retrieving counters took %ld.%06ld s longer"
		     " than the timeout configured in timer hnbgw X34.\n", diff.tv_sec, diff.tv_nsec / 1000);
		*next = now;
		nft_kpi_get_counters_cb(NULL);
		return;
	}

	/* next > now, wait for the remaining time. */
	timespecsub(next, &now, &diff);
	LOGP(DNFT, LOGL_DEBUG, "nft-kpi: scheduling timer: period is %ld.%06ld s, next occurrence in %ld.%06ld s\n",
	     period.tv_sec, period.tv_nsec / 1000,
	     diff.tv_sec, diff.tv_nsec / 1000);
	osmo_timer_setup(&g_hnbgw->nft_kpi.get_counters_timer, nft_kpi_get_counters_cb, NULL);
	osmo_timer_schedule(&g_hnbgw->nft_kpi.get_counters_timer, diff.tv_sec, diff.tv_nsec / 1000);
}

/* from main(), initialize all worker threads and other nft state. */
void nft_kpi_init(const char *table_name)
{
	struct nft_thread_req *req;

	/* When nft is disabled, no need to set up counters. */
	if (!g_hnbgw->config.nft_kpi.enable)
		return;

	if (!table_name || !*table_name)
		table_name = "osmo-hnbgw";

	table_name = talloc_strdup(OTC_GLOBAL, table_name);
	nft_maintenance.table_name = table_name;
	nft_counters.table_name = table_name;

	/* Launch two threads for interaction with nftables. One thread will be asked to perform hNodeB
	 * registration/deregistration maintenance, the other thread will be asked to retrieve counters. */
	nft_maintenance.m2t = osmo_it_q_alloc(g_hnbgw, "nft_maintenance_m2t", 4096, nft_thread_m2t_cb, NULL);
	nft_maintenance.t2m = osmo_it_q_alloc(g_hnbgw, "nft_maintenance_t2m", 4096, nft_thread_t2m_cb, NULL);

	nft_counters.m2t = osmo_it_q_alloc(g_hnbgw, "nft_counters_m2t", 1, nft_thread_m2t_cb, NULL);
	nft_counters.t2m = osmo_it_q_alloc(g_hnbgw, "nft_counters_t2m", 1, nft_thread_t2m_cb, NULL);

	/* register t2m queues in main()'s select loop */
	osmo_fd_register(&nft_maintenance.t2m->event_ofd);
	osmo_fd_register(&nft_counters.t2m->event_ofd);

	if (pthread_create(&nft_maintenance.thread, NULL, nft_thread_main, &nft_maintenance)
	    || pthread_create(&nft_counters.thread, NULL, nft_thread_main, &nft_counters)) {
		LOGP(DNFT, LOGL_ERROR, "Failed to start nftables-KPI threads\n");
		OSMO_ASSERT(false);
	}

	/* Set up nftables table */
	req = talloc_zero(g_hnbgw, struct nft_thread_req);
	*req = (struct nft_thread_req){
		.type = NFT_THREAD_INIT_TABLE,
	};
	nft_m2t_enqueue(&nft_maintenance, req);

	g_hnbgw->nft_kpi.active = true;

	nft_kpi_get_counters_schedule();
}

/* main thread: Ask the nft maintenance thread to set up a persistent named counter for this new hnbp */
void nft_kpi_hnb_persistent_add(struct hnb_persistent *hnbp)
{
	/* When nft is disabled, no need to set up counters. */
	if (!g_hnbgw->nft_kpi.active)
		return;

	struct nft_thread_req *req = talloc_zero(g_hnbgw, struct nft_thread_req);
	*req = (struct nft_thread_req){
		.type = NFT_THREAD_HNB_PERSISTENT_INIT,
		.hnbp_init_remove = {
			.cell_id = hnbp->id,
		},
	};
	nft_m2t_enqueue(&nft_maintenance, req);
}

/* main thread: Ask the nft maintenance thread to drop up a persistent named counter for this EOL hnbp */
void nft_kpi_hnb_persistent_remove(struct hnb_persistent *hnbp)
{
	/* When nft is disabled, no need to set up counters. */
	if (!g_hnbgw->nft_kpi.active)
		return;

	struct nft_thread_req *req = talloc_zero(g_hnbgw, struct nft_thread_req);
	*req = (struct nft_thread_req){
		.type = NFT_THREAD_HNB_PERSISTENT_REMOVE,
		.hnbp_init_remove = {
			.cell_id = hnbp->id,
		},
	};
	nft_m2t_enqueue(&nft_maintenance, req);
}

static void nft_kpi_hnb_drop_rules(struct hnb_persistent *hnbp);

/* main thread: Ask the nft maintenance thread to start counting for this hNodeB */
int nft_kpi_hnb_start(struct hnb_persistent *hnbp, const struct osmo_sockaddr_str *gtpu_remote)
{
	struct nft_thread_req *req;

	/* When nft is disabled, no need to set up counters. */
	if (!g_hnbgw->nft_kpi.active)
		return 0;

	if (!osmo_sockaddr_str_is_nonzero(gtpu_remote)) {
		LOGP(DNFT, LOGL_ERROR, "HNB %s: invalid remote GTP-U address: " OSMO_SOCKADDR_STR_FMT "\n",
		     hnbp->id_str, OSMO_SOCKADDR_STR_FMT_ARGS(gtpu_remote));
		return -EINVAL;
	}

	if (!osmo_sockaddr_str_cmp(gtpu_remote, &hnbp->nft_kpi.addr_remote)) {
		/* The remote address is unchanged, no need to update the nft probe */
		return 0;
	}

	/* When switching to a new remote address without an explicit nft_kpi_hnb_stop(), handles for the previous rules
	 * might still be active, remove them first. */
	nft_kpi_hnb_drop_rules(hnbp);

	/* Ask nft thread to start counting UL and DL packets. This adds rules that will increment the named counters
	 * added on NFT_THREAD_HNB_PERSISTENT_INIT earlier. */
	req = talloc_zero(g_hnbgw, struct nft_thread_req);
	*req = (struct nft_thread_req){
		.type = NFT_THREAD_HNB_START,
		.hnb_start = {
			.cell_id = hnbp->id,
			.gtpu_remote = *gtpu_remote,
		},
	};

	nft_m2t_enqueue(&nft_maintenance, req);

	/* Remember which address we last sent to the nft thread. */
	hnbp->nft_kpi.addr_remote = *gtpu_remote;
	return 0;
}

/* main thread: Stop counting for this HNB */
void nft_kpi_hnb_stop(struct hnb_persistent *hnbp)
{
	/* When nft is disabled, no need to set up counters. */
	if (!g_hnbgw->nft_kpi.active)
		return;

	/* Remember which address we last sent to the nft thread -- a zero address means the HNB is "stopped". */
	hnbp->nft_kpi.addr_remote = (struct osmo_sockaddr_str){};

	nft_kpi_hnb_drop_rules(hnbp);

	/* Corner case:
	 * When nft_kpi_hnb_stop() is called before nft_kpi_hnb_start() has responded with the nft handles needed for
	 * nft_kpi_hnb_drop_rules() to work:
	 * - above, we zero hnbp->nft_kpi.addr_remote.
	 * - in main_thread_handle_hnb_start_resp(), when addr_remote is zero, we directly drop the handles again.
	 */
}

/* main thread: ask for dropping counter rules by handle */
static void nft_kpi_hnb_drop_rules(struct hnb_persistent *hnbp)
{
	struct nft_thread_req *req;

	/* No handles known means nothing to send. */
	if (!hnbp->nft_kpi.ul.h.handle_present && !hnbp->nft_kpi.dl.h.handle_present)
		return;

	req = talloc_zero(g_hnbgw, struct nft_thread_req);
	*req = (struct nft_thread_req){
		.type = NFT_THREAD_HNB_STOP,
		.hnb_stop = {
			.ul = hnbp->nft_kpi.ul.h,
			.dl = hnbp->nft_kpi.dl.h,
		},
	};

	nft_m2t_enqueue(&nft_maintenance, req);

	/* mark the nft handles as removed in the main thread's state. */
	hnbp->nft_kpi.ul.h = (struct nft_kpi_handle){};
	hnbp->nft_kpi.dl.h = (struct nft_kpi_handle){};
}

/* main thread */
static int update_ctr(struct rate_ctr_group *ctrg, int ctrg_idx, uint64_t *last_val, uint64_t new_val)
{
	int updated = 0;
	if (new_val > *last_val) {
		rate_ctr_add2(ctrg, ctrg_idx, new_val - *last_val);
		updated++;
	}
	*last_val = new_val;
	return updated;
}

/* main thread */
static int hnb_update_counters(struct hnb_persistent *hnbp, struct nft_counter *c)
{
	struct nft_kpi_val *tgt = (c->ul ? &hnbp->nft_kpi.ul.v : &hnbp->nft_kpi.dl.v);
	int updated = 0;

	updated += update_ctr(hnbp->ctrs,
			      c->ul ? HNB_CTR_GTPU_PACKETS_UL : HNB_CTR_GTPU_PACKETS_DL,
			      &tgt->packets, c->val.packets);
	updated += update_ctr(hnbp->ctrs,
			      c->ul ? HNB_CTR_GTPU_TOTAL_BYTES_UL : HNB_CTR_GTPU_TOTAL_BYTES_DL,
			      &tgt->total_bytes, c->val.total_bytes);
	updated += update_ctr(hnbp->ctrs,
			      c->ul ? HNB_CTR_GTPU_UE_BYTES_UL : HNB_CTR_GTPU_UE_BYTES_DL,
			      &tgt->ue_bytes, c->val.ue_bytes);
	return updated;
}

/* main thread: After hnb_start, store the nft handles of the newly added rules that we'll need to remove them on
 * hnb_stop, when the hNodeB disconnects from RUA. */
static void main_thread_handle_hnb_start_resp(struct nft_thread_req *req)
{
	struct hnb_persistent *hnbp = hnb_persistent_find_by_id(&req->hnb_start.cell_id);
	bool drop_again = false;

	if (!hnbp) {
		/* Paranoid corner case: while we added the rules for this hNodeB, it was apparently removed and does
		 * not exist anymore. We need to just drop the rules again right away. */
		LOGP(DNFT, LOGL_ERROR, "Added nft rules for unknown cell %s; removing rules again\n",
		     umts_cell_id_to_str(&req->hnb_start.cell_id));
		drop_again = true;
	}

	if (!osmo_sockaddr_str_is_nonzero(&hnbp->nft_kpi.addr_remote)) {
		/* Paranoid corner case: while we added the rules for this hNodeB, nft_kpi_hnb_stop() was invoked and
		 * did not have these handles yet. It cleared out remote_addr for us to detect this. We need to just
		 * drop the rules again right away. */
		LOGP(DNFT, LOGL_INFO,
		     "Cell %s disconnected before adding counter rules completed. removing rules again\n",
		     umts_cell_id_to_str(&req->hnb_start.cell_id));
		drop_again = true;
	}

	if (drop_again) {
		struct nft_thread_req *req2;
		req2 = talloc_zero(g_hnbgw, struct nft_thread_req);
		*req2 = (struct nft_thread_req){
			.type = NFT_THREAD_HNB_STOP,
			.hnb_stop = {
				.ul = req->hnb_start.ul,
				.dl = req->hnb_start.dl,
			},
		};
		nft_m2t_enqueue(&nft_maintenance, req2);
		return;
	}

	hnbp->nft_kpi.ul.h = req->hnb_start.ul;
	hnbp->nft_kpi.dl.h = req->hnb_start.dl;
}

/* main thread */
static void main_thread_handle_get_counters_resp(struct nft_thread_req *req)
{
	struct nft_counter *c = req->get_counters.counters;
	struct nft_counter *end = c + req->get_counters.counters_len;
	struct hnb_persistent *hnbp = NULL;
	int count = 0;

	LOGP(DNFT, LOGL_DEBUG, "main thread: updating %zu rate counters from nft response (2 counters per hNodeB)\n",
	     req->get_counters.counters_len);

	for (; c < end; c++) {
		/* optimize: the counters usually come in pairs, two for the same cell id. Avoid to do the same
		 * hnb_persistent lookup twice. */
		if (!hnbp || !umts_cell_id_equal(&hnbp->id, &c->cell_id))
			hnbp = hnb_persistent_find_by_id(&c->cell_id);
		if (!hnbp)
			continue;
		if (hnb_update_counters(hnbp, c))
			count++;
	}

	LOGP(DNFT, LOGL_DEBUG, "main thread: %d of %zu rate counters have incremented (2 counters per hNodeB)\n",
	     count, req->get_counters.counters_len);
}

/* main thread: handle responses from a worker thread */
static void nft_thread_t2m_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct nft_thread_req *req = (void *)item;

	/* handle any actions required for specific responses */
	switch (req->type) {

	case NFT_THREAD_INIT_TABLE:
		if (req->rc) {
			LOGP(DNFT, LOGL_FATAL,
			     "Failed to initialize nft KPI (missing cap_net_admin? nft table name collision?)\n");
			OSMO_ASSERT(false);
		}
		break;

	case NFT_THREAD_HNB_START:
		main_thread_handle_hnb_start_resp(req);
		break;

	case NFT_THREAD_GET_COUNTERS:
		if (req->rc) {
			/* Maybe we requested counters before the table was created by the maintenance thread. If so,
			 * it's not harmful and we can just try again next time. */
			LOGP(DNFT, LOGL_ERROR, "Retrieving counters from nftables failed. Trying again (timer X34).\n");
		} else {
			main_thread_handle_get_counters_resp(req);
		}
		/* Schedule the next counter retrieval. */
		nft_kpi_get_counters_schedule();
		break;

	default:
		break;
	}

	/* Anything coming back thread-to-main is a response to an earlier request, to free the req allocation. */
	talloc_free(req);
}

#endif // ENABLE_NFTABLES
