/* OsmoHNBGW implementation of CS and PS Level3 message decoding (NAS PDU) */

/* Copyright 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include "asn1helpers.h"

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_rua.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/ranap/ranap_ies_defs.h>

static const struct tlv_definition gsm48_gmm_att_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_FIXED, 1 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_TMSI_BASED_NRI_C]	= { TLV_TYPE_TLV },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
	},
};

static void decode_gmm_tlv(struct osmo_mobile_identity *mi,
			  struct osmo_routing_area_id *old_ra,
			  int *nri,
			  const uint8_t *tlv_data, size_t tlv_len, bool allow_hex)
{
	struct tlv_parsed tp;
	struct tlv_p_entry *e;

	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, tlv_data, tlv_len, 0, 0);

	e = TLVP_GET(&tp, GSM48_IE_GMM_TMSI_BASED_NRI_C);
	if (e) {
		*nri = e->val[0];
		*nri <<= 2;
		*nri |= e->val[1] >> 6;
	}
}

static int mobile_identity_decode_from_gmm_att_req(struct osmo_mobile_identity *mi,
						   struct osmo_routing_area_id *old_ra,
						   int *nri,
						   const uint8_t *l3_data, size_t l3_len, bool allow_hex)
{
	const struct gsm48_hdr *gh = (void *)l3_data;
	const uint8_t *cur = gh->data;
	const uint8_t *end = l3_data + l3_len;
	const uint8_t *mi_data;
	uint8_t mi_len;
	uint8_t msnc_len;
	uint8_t ms_ra_acc_cap_len;
	int rc;

	/* MS network capability 10.5.5.12 */
	msnc_len = *cur++;
	cur += msnc_len;

	/* aTTACH Type 10.5.5.2 */
	cur++;

	/* DRX parameter 10.5.5.6 */
	cur += 2;

	/* Mobile Identity (P-TMSI or IMSI) 10.5.1.4 */
	mi_len = *cur++;
	mi_data = cur;
	cur += mi_len;

	if (cur >= end)
		return -ENOSPC;

	rc = osmo_mobile_identity_decode(mi, mi_data, mi_len, allow_hex);
	if (rc)
		return rc;

	/* Old routing area identification 10.5.5.15. */
	rc = osmo_routing_area_id_decode(old_ra, cur, end - cur);
	if (rc < 0)
		return rc;
	cur += rc;

	/* MS Radio Access Capability 10.5.5.12a */
	ms_ra_acc_cap_len = *cur++;
	cur += ms_ra_acc_cap_len;

	if (cur > end)
		return -ENOSPC;

	decode_gmm_tlv(mi, old_ra, nri, cur, end - cur, allow_hex);
	return 0;
}

static int mobile_identity_decode_from_gmm_rau_req(struct osmo_mobile_identity *mi,
						   struct osmo_routing_area_id *old_ra,
						   int *nri,
						   const uint8_t *l3_data, size_t l3_len, bool allow_hex)
{
	const struct gsm48_hdr *gh = (void *)l3_data;
	const uint8_t *cur = gh->data;
	const uint8_t *end = l3_data + l3_len;
	uint8_t ms_ra_acc_cap_len;
	int rc;

	/* Update Type 10.5.5.18 */
	cur++;
	if (cur >= end)
		return -ENOSPC;

	/* Old routing area identification 10.5.5.15 */
	rc = osmo_routing_area_id_decode(old_ra, cur, end - cur);
	if (rc < 0)
		return rc;
	cur += rc;
	if (cur >= end)
		return -ENOSPC;

	/* MS Radio Access Capability 10.5.5.12a */
	ms_ra_acc_cap_len = *cur++;
	cur += ms_ra_acc_cap_len;

	if (cur > end)
		return -ENOSPC;

	decode_gmm_tlv(mi, old_ra, nri, cur, end - cur, allow_hex);
	return 0;
}

/* CS MM: Determine mobile identity, from_other_plmn, is_emerg. */
static int peek_l3_ul_nas_cs(struct hnbgw_context_map *map, const uint8_t *nas_pdu, size_t len,
			     const struct osmo_plmn_id *local_plmn)
{
	const struct gsm48_hdr *gh = (const struct gsm48_hdr *)nas_pdu;
	struct osmo_location_area_id old_lai;
	const struct gsm48_loc_upd_req *lu;
	struct gsm48_service_request *cm;

	osmo_mobile_identity_decode_from_l3_buf(&map->l3.mi, nas_pdu, len, false);

	switch (map->l3.gsm48_pdisc) {
	case GSM48_PDISC_MM:
		/* Get is_emerg and from_other_plmn */
		switch (map->l3.gsm48_msg_type) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
			if (len < sizeof(*gh) + sizeof(*lu)) {
				LOGP(DCN, LOGL_ERROR, "LU Req message too short\n");
				break;
			}
			lu = (struct gsm48_loc_upd_req *)gh->data;
			gsm48_decode_lai2(&lu->lai, &old_lai);
			map->l3.from_other_plmn = (osmo_plmn_cmp(&old_lai.plmn, local_plmn) != 0);
			if (map->l3.from_other_plmn)
				LOGP(DRUA, LOGL_INFO, "LU from other PLMN: old LAI=%s my PLMN=%s\n",
				     osmo_plmn_name_c(OTC_SELECT, &old_lai.plmn),
				     osmo_plmn_name_c(OTC_SELECT, local_plmn));
			return 0;

		case GSM48_MT_MM_CM_SERV_REQ:
			if (len < sizeof(*gh) + sizeof(*cm)) {
				LOGP(DRUA, LOGL_ERROR, "CM Service Req message too short\n");
				break;
			}
			cm = (struct gsm48_service_request *)&gh->data[0];
			map->l3.is_emerg = (cm->cm_service_type == GSM48_CMSERV_EMERGENCY);
			LOGP(DRUA, LOGL_DEBUG, "CM Service is_emerg=%d\n", map->l3.is_emerg);
			return 0;
		}
		break;
	}

	return 0;
}

/* PS GMM: Determine mobile identity, gmm_nri_container, from_other_plmn and is_emerg */
static int peek_l3_ul_nas_ps(struct hnbgw_context_map *map, const uint8_t *nas_pdu, size_t len,
			     const struct osmo_plmn_id *local_plmn)
{
	struct osmo_routing_area_id old_ra = {};
	int nri = -1;

	switch (map->l3.gsm48_pdisc) {
	case GSM48_PDISC_MM_GPRS:
		switch (map->l3.gsm48_msg_type) {
		case GSM48_MT_GMM_ATTACH_REQ:
			mobile_identity_decode_from_gmm_att_req(&map->l3.mi, &old_ra, &nri, nas_pdu, len, false);
			LOGP(DRUA, LOGL_DEBUG, "GMM Attach Req mi=%s old_ra=%s nri:%d=0x%x\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &map->l3.mi),
			     osmo_rai_name2_c(OTC_SELECT, &old_ra),
			     nri, nri);
			if (old_ra.lac.plmn.mcc && osmo_plmn_cmp(&old_ra.lac.plmn, local_plmn)) {
				map->l3.from_other_plmn = true;
				LOGP(DRUA, LOGL_INFO, "GMM Attach Req from other PLMN: old RAI=%s my PLMN=%s\n",
				     osmo_rai_name2_c(OTC_SELECT, &old_ra),
				     osmo_plmn_name_c(OTC_SELECT, local_plmn));
			}
			if (nri >= 0)
				map->l3.gmm_nri_container = nri;
			return 0;

		case GSM48_MT_GMM_RA_UPD_REQ:
			mobile_identity_decode_from_gmm_rau_req(&map->l3.mi, &old_ra, &nri, nas_pdu, len, false);
			LOGP(DRUA, LOGL_DEBUG, "GMM Routing Area Upd Req mi=%s old_ra=%s nri:%d=0x%x\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &map->l3.mi),
			     osmo_rai_name2_c(OTC_SELECT, &old_ra),
			     nri, nri);
			if (old_ra.lac.plmn.mcc && osmo_plmn_cmp(&old_ra.lac.plmn, local_plmn)) {
				map->l3.from_other_plmn = true;
				LOGP(DRUA, LOGL_INFO, "GMM Routing Area Upd Req from other PLMN: old RAI=%s my PLMN=%s\n",
				     osmo_rai_name2_c(OTC_SELECT, &old_ra),
				     osmo_plmn_name_c(OTC_SELECT, local_plmn));
			}
			if (nri >= 0)
				map->l3.gmm_nri_container = nri;
			return 0;
		}
		break;
	}

	return 0;
}

static int peek_l3_ul_nas(struct hnbgw_context_map *map, const uint8_t *nas_pdu, size_t len,
			  const struct osmo_plmn_id *local_plmn)
{
	const struct gsm48_hdr *gh = (const struct gsm48_hdr *)nas_pdu;

	map->l3 = (struct hnbgw_l3_peek){
		.gmm_nri_container = -1,
		.mi = {
			.type = GSM_MI_TYPE_NONE,
			.tmsi = GSM_RESERVED_TMSI,
		},
	};

	if (len < sizeof(*gh)) {
		LOGP(DCN, LOGL_ERROR, "Layer 3 message too short for header\n");
		return -EINVAL;
	}

	map->l3.gsm48_pdisc = gsm48_hdr_pdisc(gh);
	map->l3.gsm48_msg_type = gsm48_hdr_msg_type(gh);

	if (map->is_ps)
		return peek_l3_ul_nas_ps(map, nas_pdu, len, local_plmn);
	return peek_l3_ul_nas_cs(map, nas_pdu, len, local_plmn);
}

static int peek_l3_ul_initial_ue(struct hnbgw_context_map *map, const RANAP_InitialUE_MessageIEs_t *ies)
{
	struct osmo_plmn_id local_plmn;

	if (g_hnbgw->config.plmn.mcc) {
		/* The user has configured a PLMN */
		local_plmn = g_hnbgw->config.plmn;
	} else {
		/* The user has not configured a PLMN, guess from the InitialUE message's LAI IE's PLMN */
		if (ies->lai.pLMNidentity.size < 3) {
			LOGP(DCN, LOGL_ERROR, "Missing PLMN in RANAP InitialUE message\n");
			return -EINVAL;
		}
		osmo_plmn_from_bcd(ies->lai.pLMNidentity.buf, &local_plmn);
	}

	return peek_l3_ul_nas(map, ies->nas_pdu.buf, ies->nas_pdu.size, &local_plmn);
}

/* Extract a Layer 3 message (NAS PDU) from the uplink RANAP message, and put the info obtained in map->l3.
 * This is relevant for CN pooling, to decide which CN link to map the RUA context to. */
int hnbgw_peek_l3_ul(struct hnbgw_context_map *map, struct msgb *ranap_msg)
{
	ranap_message *message = hnbgw_decode_ranap_co(ranap_msg);
	if (!message) {
		LOGP(DCN, LOGL_ERROR, "Failed to decode RANAP PDU\n");
		return -EINVAL;
	}

	switch (message->procedureCode) {
	case RANAP_ProcedureCode_id_InitialUE_Message:
		return peek_l3_ul_initial_ue(map, &message->msg.initialUE_MessageIEs);
	default:
		LOGP(DCN, LOGL_ERROR, "unexpected RANAP PDU in RUA Connect message: %s\n",
		     get_value_string(ranap_procedure_code_vals, message->procedureCode));
		return -ENOTSUP;
	}
}
