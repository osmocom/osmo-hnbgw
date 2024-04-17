/* KPI (statistics, counters) at DTAP level */
/* (C) 2024 by Harald Welte <laforge@osmocom.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
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
 */

#include "config.h"

#include <osmocom/core/utils.h>

#include <osmocom/ranap/ranap_common_ran.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/kpi.h>

/***********************************************************************
 * DOWNLINK messages
 ***********************************************************************/

void kpi_dtap_process_dl(struct hnbgw_context_map *map, const uint8_t *buf, unsigned int len,
			 uint8_t sapi)
{
	struct hnb_persistent *hnbp = map->hnb_ctx->persistent;
	const struct gsm48_hdr *gh = (const struct gsm48_hdr *)buf;
	if (len < sizeof(*gh))
		return;

	/* if you make use of any data beyond the fixed-size gsm48_hdr, you must make sure the underlying
	 * buffer length is actually long enough! */

	if (map->is_ps) {
		/* Packet Switched Domain (from SGSN) */
		switch (gsm48_hdr_msg_type(gh)) {
		case GSM48_MT_GMM_ATTACH_ACK:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_PS_ATT_ACK);
			break;
		case GSM48_MT_GMM_ATTACH_REJ:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_PS_ATT_REJ);
			break;
		case GSM48_MT_GMM_RA_UPD_ACK:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_PS_RAU_ACK);
			break;
		case GSM48_MT_GMM_RA_UPD_REJ:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_PS_RAU_REJ);
			break;
		}
	} else {
		/* Circuit Switched Domain (from MSC) */
		switch (gsm48_hdr_msg_type(gh)) {
		case GSM48_MT_MM_LOC_UPD_ACCEPT:
			/* FIXME: many LU are acknwoeldged implicitly with TMSI allocation */
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_CS_LU_ACC);
			break;
		case GSM48_MT_MM_LOC_UPD_REJECT:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_CS_LU_REJ);
			break;
		}
	}
}

/***********************************************************************
 * UPLINK messages
 ***********************************************************************/

void kpi_dtap_process_ul(struct hnbgw_context_map *map, const uint8_t *buf, unsigned int len,
			 uint8_t sapi)
{
	struct hnb_persistent *hnbp = map->hnb_ctx->persistent;
	const struct gsm48_hdr *gh = (const struct gsm48_hdr *)buf;
	if (len < sizeof(*gh))
		return;

	/* if you make use of any data beyond the fixed-size gsm48_hdr, you must make sure the underlying
	 * buffer length is actually long enough! */

	if (map->is_ps) {
		/* Packet Switched Domain (to SGSN) */
		switch (gsm48_hdr_msg_type(gh)) {
		case GSM48_MT_GMM_ATTACH_REQ:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_PS_ATT_REQ);
			break;
		case GSM48_MT_GMM_RA_UPD_REQ:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_PS_RAU_REQ);
			break;
		}
	} else {
		/* Circuit Switched Domain (to MSC) */
		switch (gsm48_hdr_msg_type(gh)) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
			HNBP_CTR_INC(hnbp, HNB_CTR_DTAP_CS_LU_REQ);
			break;
		}
	}
}
