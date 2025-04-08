/* RANAP Paging of HNB-GW */
/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <errno.h>
#include <sys/types.h>

#include <asn1c/asn1helpers.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/tdefs.h>

/***************
 * This module manages the list of "struct cnlink_paging" items in (struct
 * hnbgw_cnlink *)->paging.
 * Every time a new RANAP Paging Cmd arrives from some cnlink,
 * cnlink_paging_add_ranap() is called to potentially store the paging command
 * for a while.
 * When a paging response is received from HNB, cnlink_find_by_paging_mi() is
 * called to obtain the cnlink it should be routed back to.
 */

struct cnlink_paging {
	struct llist_head entry;

	struct osmo_mobile_identity mi;
	struct osmo_mobile_identity mi2;
	time_t timestamp;
};

static int cnlink_paging_destructor(struct cnlink_paging *p)
{
	llist_del(&p->entry);
	return 0;
}


/* Return current timestamp in *timestamp, and the oldest still valid timestamp according to T3113 timeout. */
static const char *cnlink_paging_gettime(time_t *timestamp_p, time_t *timeout_p)
{
	struct timespec now;
	time_t timestamp;

	/* get timestamp */
	if (osmo_clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return "cannot get timestamp";
	timestamp = now.tv_sec;

	if (timestamp_p)
		*timestamp_p = timestamp;
	if (timeout_p)
		*timeout_p = timestamp - osmo_tdef_get(hnbgw_T_defs, 3113, OSMO_TDEF_S, 15);
	return NULL;
}

static const char *cnlink_paging_add(struct hnbgw_cnlink *cnlink, const struct osmo_mobile_identity *mi,
				     const struct osmo_mobile_identity *mi2)
{
	struct cnlink_paging *p, *p2;
	time_t timestamp;
	time_t timeout;
	const char *errmsg;

	errmsg = cnlink_paging_gettime(&timestamp, &timeout);
	if (errmsg)
		return errmsg;

	/* Prune all paging records that are older than the configured timeout. */
	llist_for_each_entry_safe(p, p2, &cnlink->paging, entry) {
		if (p->timestamp >= timeout)
			continue;
		talloc_free(p);
	}

	/* Add new entry */
	p = talloc_zero(cnlink, struct cnlink_paging);
	*p = (struct cnlink_paging){
		.timestamp = timestamp,
		.mi = *mi,
		.mi2 = *mi2,
	};
	llist_add_tail(&p->entry, &cnlink->paging);
	talloc_set_destructor(p, cnlink_paging_destructor);

	LOG_CNLINK(cnlink, DCN, LOGL_INFO, "Rx Paging from CN for %s %s\n",
		   osmo_mobile_identity_to_str_c(OTC_SELECT, mi),
		   osmo_mobile_identity_to_str_c(OTC_SELECT, mi2));
	return NULL;
}

static const char *omi_from_ranap_ue_id(struct osmo_mobile_identity *mi, const RANAP_PermanentNAS_UE_ID_t *ranap_mi)
{
	if (!ranap_mi)
		return "null UE ID";

	if (ranap_mi->present != RANAP_PermanentNAS_UE_ID_PR_iMSI)
		return talloc_asprintf(OTC_SELECT, "unsupported UE ID type %u in RANAP Paging", ranap_mi->present);

	if (ranap_mi->choice.iMSI.size > sizeof(mi->imsi))
		return talloc_asprintf(OTC_SELECT, "invalid IMSI size %d > %zu",
				       ranap_mi->choice.iMSI.size, sizeof(mi->imsi));

	*mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_IMSI,
	};
	ranap_bcd_decode(mi->imsi, sizeof(mi->imsi), ranap_mi->choice.iMSI.buf, ranap_mi->choice.iMSI.size);
	LOGP(DCN, LOGL_DEBUG, "ranap MI %s = %s\n", osmo_hexdump(ranap_mi->choice.iMSI.buf, ranap_mi->choice.iMSI.size),
	     mi->imsi);
	return NULL;
}

static const char *omi_from_ranap_temp_ue_id(struct osmo_mobile_identity *mi, const RANAP_TemporaryUE_ID_t *ranap_tmsi)
{
	const OCTET_STRING_t *tmsi_str;

	if (!ranap_tmsi)
		return "null UE ID";

	switch (ranap_tmsi->present) {
	case RANAP_TemporaryUE_ID_PR_tMSI:
		tmsi_str = &ranap_tmsi->choice.tMSI;
		break;
	case RANAP_TemporaryUE_ID_PR_p_TMSI:
		tmsi_str = &ranap_tmsi->choice.p_TMSI;
		break;
	default:
		return talloc_asprintf(OTC_SELECT, "unsupported Temporary UE ID type %u in RANAP Paging", ranap_tmsi->present);
	}

	*mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_TMSI,
		.tmsi = asn1str_to_u32(tmsi_str),
	};
	LOGP(DCN, LOGL_DEBUG, "ranap temp UE ID = %s\n", osmo_mobile_identity_to_str_c(OTC_SELECT, mi));
	return NULL;
}

const char *cnlink_paging_add_ranap(struct hnbgw_cnlink *cnlink, RANAP_InitiatingMessage_t *imsg)
{
	RANAP_PagingIEs_t ies;
	struct osmo_mobile_identity mi = {};
	struct osmo_mobile_identity mi2 = {};
	RANAP_CN_DomainIndicator_t domain;
	const char *errmsg;

	if (ranap_decode_pagingies(&ies, &imsg->value) < 0)
		return "decoding RANAP IEs failed";

	domain = ies.cN_DomainIndicator;
	errmsg = omi_from_ranap_ue_id(&mi, &ies.permanentNAS_UE_ID);

	if (!errmsg && (ies.presenceMask & PAGINGIES_RANAP_TEMPORARYUE_ID_PRESENT))
		errmsg = omi_from_ranap_temp_ue_id(&mi2, &ies.temporaryUE_ID);

	ranap_free_pagingies(&ies);
	LOG_CNLINK(cnlink, DCN, LOGL_DEBUG, "Decoded Paging: %s %s %s%s%s\n",
		   ranap_domain_name(domain), osmo_mobile_identity_to_str_c(OTC_SELECT, &mi),
		   mi2.type ? osmo_mobile_identity_to_str_c(OTC_SELECT, &mi2) : "-",
		   errmsg ? " -- MI error: " : "",
		   errmsg ? : "");

	if (cnlink->pool->domain != domain)
		return talloc_asprintf(OTC_SELECT, "message indicates domain %s, but this is %s on domain %s\n",
				       ranap_domain_name(domain), cnlink->name, ranap_domain_name(cnlink->pool->domain));

	if (errmsg)
		return errmsg;

	return cnlink_paging_add(cnlink, &mi, &mi2);
}

/* If this cnlink has a recent Paging for the given MI, return true and drop the Paging record.
 * Else return false. */
static bool cnlink_match_paging_mi(struct hnbgw_cnlink *cnlink, const struct osmo_mobile_identity *mi, time_t timeout)
{
	struct cnlink_paging *p, *p2;
	llist_for_each_entry_safe(p, p2, &cnlink->paging, entry) {
		if (p->timestamp < timeout) {
			talloc_free(p);
			continue;
		}
		if (osmo_mobile_identity_cmp(&p->mi, mi)
		    && osmo_mobile_identity_cmp(&p->mi2, mi))
			continue;
		talloc_free(p);
		return true;
	}
	return false;
}

struct hnbgw_cnlink *cnlink_find_by_paging_mi(struct hnbgw_cnpool *cnpool, const struct osmo_mobile_identity *mi)
{
	struct hnbgw_cnlink *cnlink;
	time_t timeout = 0;
	const char *errmsg;

	errmsg = cnlink_paging_gettime(NULL, &timeout);
	if (errmsg)
		LOGP(DCN, LOGL_ERROR, "%s\n", errmsg);

	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry) {
		if (!cnlink_match_paging_mi(cnlink, mi, timeout))
			continue;
		return cnlink;
	}
	return NULL;
}

