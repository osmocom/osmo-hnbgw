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

/***********************************************************************
 * Incoming primitives from SCCP User SAP
 ***********************************************************************/

static bool addr_has_pc_and_ssn(const struct osmo_sccp_addr *addr)
{
	if (!(addr->presence & OSMO_SCCP_ADDR_T_SSN))
		return false;
	if (!(addr->presence & OSMO_SCCP_ADDR_T_PC))
		return false;
	return true;
}

static int resolve_addr_name(struct osmo_sccp_addr *dest, struct osmo_ss7_instance **ss7,
			     const char *addr_name, const char *label,
			     uint32_t default_pc)
{
	if (!addr_name) {
		osmo_sccp_make_addr_pc_ssn(dest, default_pc, OSMO_SCCP_SSN_RANAP);
		if (label)
			LOGP(DCN, LOGL_INFO, "%s remote addr not configured, using default: %s\n", label,
			     osmo_sccp_addr_name(*ss7, dest));
		return 0;
	}

	*ss7 = osmo_sccp_addr_by_name(dest, addr_name);
	if (!*ss7) {
		if (label)
			LOGP(DCN, LOGL_ERROR, "%s remote addr: no such SCCP address book entry: '%s'\n",
			     label, addr_name);
		return -1;
	}

	osmo_sccp_addr_set_ssn(dest, OSMO_SCCP_SSN_RANAP);

	if (!addr_has_pc_and_ssn(dest)) {
		if (label)
			LOGP(DCN, LOGL_ERROR, "Invalid/incomplete %s remote-addr: %s\n",
			     label, osmo_sccp_addr_name(*ss7, dest));
		return -1;
	}

	return 0;
}

void hnbgw_cnpool_apply_cfg(struct hnbgw_cnpool *cnpool)
{
	struct osmo_nri_range *r;

	cnpool->use.nri_bitlen = cnpool->vty.nri_bitlen;

	osmo_nri_ranges_free(cnpool->use.null_nri_ranges);
	cnpool->use.null_nri_ranges = osmo_nri_ranges_alloc(g_hnbgw);
	llist_for_each_entry(r, &cnpool->vty.null_nri_ranges->entries, entry)
		osmo_nri_ranges_add(cnpool->use.null_nri_ranges, r);
}

static void hnbgw_cnlink_cfg_copy(struct hnbgw_cnlink *cnlink)
{
	struct osmo_nri_range *r;

	osmo_talloc_replace_string(cnlink, &cnlink->use.remote_addr_name, cnlink->vty.remote_addr_name);

	osmo_nri_ranges_free(cnlink->use.nri_ranges);
	cnlink->use.nri_ranges = osmo_nri_ranges_alloc(cnlink);
	llist_for_each_entry(r, &cnlink->vty.nri_ranges->entries, entry)
		osmo_nri_ranges_add(cnlink->use.nri_ranges, r);
}

static bool hnbgw_cnlink_sccp_cfg_changed(struct hnbgw_cnlink *cnlink)
{
	bool changed = false;

	if (cnlink->vty.remote_addr_name && cnlink->use.remote_addr_name) {
		struct osmo_ss7_instance *ss7;
		struct osmo_sccp_addr remote_addr = {};

		/* Instead of comparing whether the address book entry names are different, actually resolve the
		 * resulting SCCP address, and only restart the cnlink if the resulting address changed. */
		resolve_addr_name(&remote_addr, &ss7, cnlink->vty.remote_addr_name, NULL, DEFAULT_PC_HNBGW);
		if (osmo_sccp_addr_cmp(&remote_addr, &cnlink->remote_addr, OSMO_SCCP_ADDR_T_PC | OSMO_SCCP_ADDR_T_SSN))
			changed = true;
	} else if (cnlink->vty.remote_addr_name != cnlink->use.remote_addr_name) {
		/* One of them is NULL, the other is not. */
		changed = true;
	}

	/* if more cnlink configuration is added in the future, it needs to be compared here. */

	return changed;
}

static void hnbgw_cnlink_log_self(struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_instance *ss7 = cnlink->hnbgw_sccp_user->ss7;
	LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "using: cs7-%u %s <-> %s %s %s\n",
		   osmo_ss7_instance_get_id(ss7),
		   /* printing the entire SCCP address is quite long, rather just print the point-code */
		   osmo_ss7_pointcode_print(ss7, cnlink->hnbgw_sccp_user->local_addr.pc),
		   osmo_ss7_pointcode_print2(ss7, cnlink->remote_addr.pc),
		   cnlink->name, cnlink->use.remote_addr_name ? : "(default remote point-code)");
}

/* If not present yet, set up all of osmo_ss7_instance, osmo_sccp_instance and hnbgw_sccp_user for the given cnlink.
 * The cs7 instance nr to use is determined by cnlink->remote_addr_name, or cs7 instance 0 if that is not present.
 * Set cnlink->hnbgw_sccp_user to the new SCCP instance. Return 0 on success, negative on error. */
int hnbgw_cnlink_start_or_restart(struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_instance *ss7 = NULL;
	struct hnbgw_sccp_user *hsu;

	/* If a hnbgw_sccp_user has already been set up, use that. */
	if (cnlink->hnbgw_sccp_user) {
		if (hnbgw_cnlink_sccp_cfg_changed(cnlink)) {
			LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "config changed, restarting SCCP\n");
			hnbgw_cnlink_drop_sccp(cnlink);
		} else {
			LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "SCCP instance already set up, using %s\n",
				   cnlink->hnbgw_sccp_user->name);
			return 0;
		}
	} else {
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "no SCCP instance selected yet\n");
	}

	/* Copy the current configuration: cnlink->use = cnlink->vty */
	hnbgw_cnlink_cfg_copy(cnlink);

	/* Figure out which cs7 instance to use. If cnlink->remote_addr_name is set, it points to an address book entry
	 * in a specific cs7 instance. If it is not set, leave ss7 == NULL to use cs7 instance 0. */
	if (cnlink->use.remote_addr_name) {
		if (resolve_addr_name(&cnlink->remote_addr, &ss7, cnlink->use.remote_addr_name, cnlink->name,
				      DEFAULT_PC_HNBGW)) {
			LOG_CNLINK(cnlink, DCN, LOGL_ERROR, "cannot initialize SCCP: there is no SCCP address named '%s'\n",
				   cnlink->use.remote_addr_name);
			return -ENOENT;
		}

		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "remote-addr is '%s', using cs7 instance %u\n",
			   cnlink->use.remote_addr_name, osmo_ss7_instance_get_id(ss7));
	} else {
		/* If no address is configured, use the default remote CN address, according to legacy behavior. */
		osmo_sccp_make_addr_pc_ssn(&cnlink->remote_addr, cnlink->pool->default_remote_pc, OSMO_SCCP_SSN_RANAP);
	}

	/* If no 'cs7 instance' has been selected by the address, see if there already is a cs7 0 we can use by default.
	 * If it doesn't exist, it will get created by osmo_sccp_simple_client_on_ss7_id(). */
	if (!ss7) {
		ss7 = osmo_ss7_instance_find(0);
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "Using default 'cs7 instance 0' (%s)\n", ss7 ? "already exists" : "will create");
	}

	if (ss7) {
		/* Has another cnlink already set up an SCCP instance for this ss7? */
		llist_for_each_entry(hsu, &g_hnbgw->sccp.users, entry) {
			if (hsu->ss7 != ss7)
				continue;
			LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "using existing SCCP instance %s on cs7 instance %u\n",
				hsu->name, osmo_ss7_instance_get_id(ss7));
			cnlink->hnbgw_sccp_user = hsu;
			hnbgw_sccp_user_get(cnlink->hnbgw_sccp_user, HSU_USE_CNLINK);
			hnbgw_cnlink_log_self(cnlink);
			return 0;
		}
		/* else cnlink->hnbgw_sccp_user stays NULL and is set up below. */
		LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "cs7 instance %u has no configured SCCP instance yet\n", osmo_ss7_instance_get_id(ss7));
	}

	/* No SCCP instance yet for this ss7. Create it. If no address name is given that resolves to a
	 * particular cs7 instance above, use 'cs7 instance 0'. */
	cnlink->hnbgw_sccp_user = hnbgw_sccp_user_alloc(ss7 ? osmo_ss7_instance_get_id(ss7) : 0);
	hnbgw_sccp_user_get(cnlink->hnbgw_sccp_user, HSU_USE_CNLINK);
	hnbgw_cnlink_log_self(cnlink);
	return 0;
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

	return cnlink_alloc(cnpool, nr);
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
	struct hnbgw_cnpool *cnpool = map->is_ps ? &g_hnbgw->sccp.cnpool_iups : &g_hnbgw->sccp.cnpool_iucs;
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

char *cnlink_sccp_addr_to_str(struct hnbgw_cnlink *cnlink, const struct osmo_sccp_addr *addr)
{
	struct osmo_sccp_instance *sccp = cnlink_sccp(cnlink);
	if (!sccp)
		return osmo_sccp_addr_dump(addr);
	return osmo_sccp_inst_addr_to_str_c(OTC_SELECT, sccp, addr);
}

static const struct rate_ctr_desc cnlink_ctr_description[] = {
	[CNLINK_CTR_RANAP_RX_UDT_RESET] = {
		"ranap:rx:udt:reset",
		"RANAP Unitdata RESET messages received"
	},
	[CNLINK_CTR_RANAP_RX_UDT_RESET_ACK] = {
		"ranap:rx:udt:reset_ack",
		"RANAP Unitdata RESET ACK messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_PAGING] = {
		"ranap:rx:udt:paging",
		"RANAP Unitdata PAGING messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_UNKNOWN] = {
		"ranap:rx:udt:unknown",
		"Unknown RANAP Unitdata messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_UNSUPPORTED] = {
		"ranap:rx:udt:unsupported",
		"Unsupported RANAP Unitdata messages received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_OVERLOAD_IND] = {
		"ranap:rx:udt:overload_ind",
		"RANAP Unitdata Overload Indications received",
	},
	[CNLINK_CTR_RANAP_RX_UDT_ERROR_IND] = {
		"ranap:rx:udt:error_ind",
		"RANAP Unitdata Error Indications received",
	},

	[CNLINK_CTR_RANAP_TX_UDT_RESET] = {
		"ranap:tx:udt:reset",
		"RANAP Unitdata RESET messages transmitted",
	},
	[CNLINK_CTR_RANAP_TX_UDT_RESET_ACK] = {
		"ranap:tx:udt:reset_ack",
		"RANAP Unitdata RESET ACK messages transmitted",
	},

	/* Indicators for CN pool usage */
	[CNLINK_CTR_CNPOOL_SUBSCR_NEW] = {
		"cnpool:subscr:new",
		"Complete Layer 3 requests assigned to this CN link by round-robin (no NRI was assigned yet).",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_REATTACH] = {
		"cnpool:subscr:reattach",
		"Complete Layer 3 requests assigned to this CN link by round-robin because the subscriber indicates a"
		" NULL-NRI (previously assigned by another CN link).",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_KNOWN] = {
		"cnpool:subscr:known",
		"Complete Layer 3 requests directed to this CN link because the subscriber indicates an NRI of this CN link.",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_PAGED] = {
		"cnpool:subscr:paged",
		"Paging Response directed to this CN link because the subscriber was recently paged by this CN link.",
	},
	[CNLINK_CTR_CNPOOL_SUBSCR_ATTACH_LOST] = {
		"cnpool:subscr:attach_lost",
		"A subscriber indicates an NRI value matching this CN link, but the CN link is not connected:"
		" a re-attach to another CN link (if available) was forced, with possible service failure.",
	},
	[CNLINK_CTR_CNPOOL_EMERG_FORWARDED] = {
		"cnpool:emerg:forwarded",
		"Emergency call requests forwarded to this CN link.",
	},
};

const struct rate_ctr_group_desc msc_ctrg_desc = {
	"msc",
	"MSC",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(cnlink_ctr_description),
	cnlink_ctr_description,
};

const struct rate_ctr_group_desc sgsn_ctrg_desc = {
	"sgsn",
	"SGSN",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(cnlink_ctr_description),
	cnlink_ctr_description,
};

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
