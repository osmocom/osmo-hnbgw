/* IuCS/IuPS Core Network interface of HNB-GW */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
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

#include <arpa/inet.h>
#include <errno.h>

#include <asn1c/asn1helpers.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stats.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_sccp.h>
#include <osmocom/hnbgw/hnbgw_ranap.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>

void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool)
{
	struct osmo_nri_range *r;

	cnpool->use.nri_bitlen = cnpool->vty.nri_bitlen;

	osmo_nri_ranges_free(cnpool->use.null_nri_ranges);
	cnpool->use.null_nri_ranges = osmo_nri_ranges_alloc(cnpool);
	llist_for_each_entry(r, &cnpool->vty.null_nri_ranges->entries, entry)
		osmo_nri_ranges_add(cnpool->use.null_nri_ranges, r);
}

void hnbgw_cnpool_cnlinks_start_or_restart(struct hnbgw_cnpool *cnpool)
{
	struct hnbgw_cnlink *cnlink;
	hnbgw_cnpool_apply_cfg(cnpool);
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		hnbgw_cnlink_start_or_restart(cnlink);
	}
}

void hnbgw_cnpool_start(struct hnbgw_cnpool *cnpool)
{
	/* Legacy compat: when there is no 'msc N' at all in the config file, set up 'msc 0' with default values (or
	 * 'sgsn' depending on cnpool). */
	if (llist_empty(&cnpool->cnlinks))
		cnlink_get_nr(cnpool, 0, true);
	hnbgw_cnpool_cnlinks_start_or_restart(cnpool);
}

struct hnbgw_cnlink *cnlink_get_nr(struct hnbgw_cnpool *cnpool, int nr, bool create_if_missing)
{
	struct hnbgw_cnlink *cnlink;
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		if (cnlink->nr == nr)
			return cnlink;
	}

	if (!create_if_missing)
		return NULL;

	return hnbgw_cnlink_alloc(cnpool, nr);
}

static bool is_cnlink_usable(struct hnbgw_cnlink *cnlink, bool is_emerg)
{
	if (is_emerg && !cnlink->allow_emerg)
		return false;
	if (!cnlink->hnbgw_sccp_user || !cnlink->hnbgw_sccp_user->sccp_user)
		return false;
	if (!cnlink_is_conn_ready(cnlink))
		return false;
	return true;
}

/* Decide which MSC/SGSN to forward this Complete Layer 3 request to. The current Layer 3 Info is passed in map->l3.
 * a) If the subscriber was previously paged from a particular CN link, that CN link shall receive the Paging Response.
 * b) If the message contains an NRI indicating a particular CN link that is currently connected, that CN link shall
 *    handle this conn.
 * c) All other cases distribute the messages across connected CN links in a round-robin fashion.
 */
struct hnbgw_cnlink *hnbgw_cnlink_select(struct hnbgw_context_map *map)
{
	struct hnbgw_cnpool *cnpool = map->is_ps ? g_hnbgw->sccp.cnpool_iups : g_hnbgw->sccp.cnpool_iucs;
	struct hnbgw_cnlink *cnlink;
	struct hnbgw_cnlink *round_robin_next = NULL;
	struct hnbgw_cnlink *round_robin_first = NULL;
	unsigned int round_robin_next_nr;
	int16_t nri_v = -1;
	bool is_null_nri = false;
	uint8_t nri_bitlen = cnpool->use.nri_bitlen;

	/* Match IMSI with previous Paging */
	if (map->l3.gsm48_msg_type == GSM48_MT_RR_PAG_RESP) {
		cnlink = cnlink_find_by_paging_mi(cnpool, &map->l3.mi);
		if (cnlink) {
			LOG_MAP(map, DCN, LOGL_INFO, "CN link paging response record selects %s %d\n", cnpool->peer_name,
				cnlink->nr);
			CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_SUBSCR_PAGED);
			return cnlink;
		}
		LOG_MAP(map, DCN, LOGL_INFO, "CN link paging response didn't match any record on %s\n", cnpool->peer_name);
		/* If there is no match, go on with other ways */
	}

#define LOG_NRI(LOGLEVEL, FORMAT, ARGS...) \
	LOG_MAP(map, DCN, LOGLEVEL, "%s NRI(%dbit)=0x%x=%d: " FORMAT, osmo_mobile_identity_to_str_c(OTC_SELECT, &map->l3.mi), \
		nri_bitlen, nri_v, nri_v, ##ARGS)

	/* Get the NRI bits either from map->l3.nri, or extract NRI bits from TMSI.
	 * The NRI possibly indicates which MSC is responsible. */
	if (map->l3.gmm_nri_container >= 0) {
		nri_v = map->l3.gmm_nri_container;
		/* The 'TMSI based NRI container' is always 10 bits long. If the relevant NRI length is configured to be
		 * less than that, ignore the lower bits. */
		if (nri_bitlen < 10)
			nri_v >>= 10 - nri_bitlen;
	} else if (map->l3.mi.type == GSM_MI_TYPE_TMSI) {
		if (osmo_tmsi_nri_v_get(&nri_v, map->l3.mi.tmsi, nri_bitlen)) {
			LOG_NRI(LOGL_ERROR, "Unable to retrieve NRI from TMSI 0x%x, nri_bitlen == %u\n", map->l3.mi.tmsi,
				nri_bitlen);
			nri_v = -1;
		}
	}

	if (map->l3.from_other_plmn && nri_v >= 0) {
		/* If a subscriber was previously attached to a different PLMN, it might still send the other
		 * PLMN's TMSI identity in an IMSI Attach. The LU sends a LAI indicating the previous PLMN. If
		 * it mismatches our PLMN, ignore the NRI. */
		LOG_NRI(LOGL_DEBUG,
			"This Complete Layer 3 message indicates a switch from another PLMN. Ignoring the NRI.\n");
		nri_v = -1;
	}

	if (nri_v >= 0)
		is_null_nri = osmo_nri_v_matches_ranges(nri_v, cnpool->use.null_nri_ranges);
	if (is_null_nri)
		LOG_NRI(LOGL_DEBUG, "this is a NULL-NRI\n");

	/* Iterate CN links to find one that matches the extracted NRI, and the next round-robin target for the case no
	 * NRI match is found. */
	round_robin_next_nr = (map->l3.is_emerg ? cnpool->round_robin_next_emerg_nr : cnpool->round_robin_next_nr);
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		bool nri_matches_cnlink = (nri_v >= 0 && osmo_nri_v_matches_ranges(nri_v, cnlink->use.nri_ranges));

		if (!is_cnlink_usable(cnlink, map->l3.is_emerg)) {
			if (nri_matches_cnlink) {
				LOG_NRI(LOGL_DEBUG, "NRI matches %s %d, but this %s is currently not connected\n",
					cnpool->peer_name, cnlink->nr, cnpool->peer_name);
				CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_SUBSCR_ATTACH_LOST);
			}
			continue;
		}

		/* Return CN link if it matches this NRI, with some debug logging. */
		if (nri_matches_cnlink) {
			if (is_null_nri) {
				LOG_NRI(LOGL_DEBUG, "NRI matches %s %d, but this NRI is also configured as NULL-NRI\n",
					cnpool->peer_name, cnlink->nr);
			} else {
				LOG_NRI(LOGL_INFO, "NRI match selects %s %d\n", cnpool->peer_name, cnlink->nr);
				CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_SUBSCR_KNOWN);
				if (map->l3.is_emerg) {
					CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_EMERG_FORWARDED);
					CNPOOL_CTR_INC(cnpool, CNPOOL_CTR_EMERG_FORWARDED);
				}
				return cnlink;
			}
		}

		/* Figure out the next round-robin MSC. The MSCs may appear unsorted in net->mscs. Make sure to linearly
		 * round robin the MSCs by number: pick the lowest msc->nr >= round_robin_next_nr, and also remember the
		 * lowest available msc->nr to wrap back to that in case no next MSC is left.
		 *
		 * MSCs configured with `no allow-attach` do not accept new subscribers and hence must not be picked by
		 * round-robin. Such an MSC still provides service for already attached subscribers: those that
		 * successfully performed IMSI-Attach and have a TMSI with an NRI pointing at that MSC. We only avoid
		 * adding IMSI-Attach of new subscribers. The idea is that the MSC is in a mode of off-loading
		 * subscribers, and the MSC decides when each subscriber is off-loaded, by assigning the NULL-NRI in a
		 * new TMSI (at the next periodical LU). So until the MSC decides to offload, an attached subscriber
		 * remains attached to that MSC and is free to use its services.
		 */
		if (!cnlink->allow_attach)
			continue;
		/* Find the allowed cnlink with the lowest nr */
		if (!round_robin_first || cnlink->nr < round_robin_first->nr)
			round_robin_first = cnlink;
		/* Find the allowed cnlink with the lowest nr >= round_robin_next_nr */
		if (cnlink->nr >= round_robin_next_nr
		    && (!round_robin_next || cnlink->nr < round_robin_next->nr))
			round_robin_next = cnlink;
	}

	if (nri_v >= 0 && !is_null_nri)
		LOG_NRI(LOGL_DEBUG, "No %s found for this NRI, doing round-robin\n", cnpool->peer_name);

	/* No dedicated CN link found. Choose by round-robin.
	 * If round_robin_next is NULL, there are either no more CN links at/after round_robin_next_nr, or none of
	 * them are usable -- wrap to the start. */
	cnlink = round_robin_next ? : round_robin_first;
	if (!cnlink) {
		CNPOOL_CTR_INC(cnpool, CNPOOL_CTR_SUBSCR_NO_CNLINK);
		if (map->l3.is_emerg)
			CNPOOL_CTR_INC(cnpool, CNPOOL_CTR_EMERG_LOST);
		return NULL;
	}

	LOG_MAP(map, DCN, LOGL_INFO, "CN link round-robin selects %s %d\n", cnpool->peer_name, cnlink->nr);

	if (is_null_nri)
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_SUBSCR_REATTACH);
	else
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_SUBSCR_NEW);

	if (map->l3.is_emerg) {
		CNLINK_CTR_INC(cnlink, CNLINK_CTR_CNPOOL_EMERG_FORWARDED);
		CNPOOL_CTR_INC(cnpool, CNPOOL_CTR_EMERG_FORWARDED);
	}

	/* A CN link was picked by round-robin, so update the next round-robin nr to pick */
	if (map->l3.is_emerg)
		cnpool->round_robin_next_emerg_nr = cnlink->nr + 1;
	else
		cnpool->round_robin_next_nr = cnlink->nr + 1;
	return cnlink;
#undef LOG_NRI
}

static const struct rate_ctr_desc cnpool_ctr_description[] = {
	[CNPOOL_CTR_SUBSCR_NO_CNLINK] = {
		"cnpool:subscr:no_cnlink",
		"Complete Layer 3 requests lost because no connected CN link is found available",
	},
	[CNPOOL_CTR_EMERG_FORWARDED] = {
		"cnpool:emerg:forwarded",
		"Emergency call requests forwarded to a CN link (see also per-CN-link counters)",
	},
	[CNPOOL_CTR_EMERG_LOST] = {
		"cnpool:emerg:lost",
		"Emergency call requests lost because no CN link was found available",
	},
};

const struct rate_ctr_group_desc iucs_ctrg_desc = {
	"iucs",
	"IuCS",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(cnpool_ctr_description),
	cnpool_ctr_description,
};

const struct rate_ctr_group_desc iups_ctrg_desc = {
	"iups",
	"IuPS",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(cnpool_ctr_description),
	cnpool_ctr_description,
};

static int hnbgw_cnpool_talloc_destructor(struct hnbgw_cnpool *cnpool)
{
	struct hnbgw_cnlink *cnlink;
	osmo_nri_ranges_free(cnpool->vty.null_nri_ranges);
	cnpool->vty.null_nri_ranges = NULL;

	while ((cnlink = llist_first_entry_or_null(&cnpool->cnlinks, struct hnbgw_cnlink, entry)))
		hnbgw_cnlink_term_and_free(cnlink);
	return 0;
}

struct hnbgw_cnpool *hnbgw_cnpool_alloc(RANAP_CN_DomainIndicator_t domain)
{
	struct hnbgw_cnpool *cnpool = talloc_zero(g_hnbgw, struct hnbgw_cnpool);
	OSMO_ASSERT(cnpool);

	cnpool->domain = domain;
	cnpool->vty = (struct hnbgw_cnpool_cfg){
		.nri_bitlen = OSMO_NRI_BITLEN_DEFAULT,
		.null_nri_ranges = osmo_nri_ranges_alloc(cnpool),
	};
	OSMO_ASSERT(cnpool->vty.null_nri_ranges);
	INIT_LLIST_HEAD(&cnpool->cnlinks);

	talloc_set_destructor(cnpool, hnbgw_cnpool_talloc_destructor);

	switch (domain) {
	case DOMAIN_CS:
		cnpool->pool_name = "iucs";
		cnpool->peer_name = "msc";
		cnpool->default_remote_pc = DEFAULT_PC_MSC;
		cnpool->default_addr_name = DEFAULT_ADDR_NAME_MSC;
		cnpool->ctrs = rate_ctr_group_alloc(cnpool, &iucs_ctrg_desc, 0);
		break;
	case DOMAIN_PS:
		cnpool->pool_name = "iups";
		cnpool->peer_name = "sgsn";
		cnpool->default_remote_pc = DEFAULT_PC_SGSN;
		cnpool->default_addr_name = DEFAULT_ADDR_NAME_SGSN;
		cnpool->ctrs = rate_ctr_group_alloc(cnpool, &iups_ctrg_desc, 0);
		break;
	default:
		OSMO_ASSERT(0);
	}

	return cnpool;
}
