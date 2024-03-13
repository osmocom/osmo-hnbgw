/* KPI (statistics, counters) at RANAP level */
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

#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/kpi.h>


/***********************************************************************
 * DOWNLINK messages
 ***********************************************************************/

static void kpi_ranap_process_dl_iu_rel_cmd(struct hnbgw_context_map *map, const ranap_message *ranap)
{
	OSMO_ASSERT(ranap->procedureCode == RANAP_ProcedureCode_id_Iu_Release);

	/* When Iu is released, all RABs are released implicitly */
	/* FIXME: increment RAB_REL_IMPLICIT */

	bitvec_zero(&map->rab_active_mask.bv);
}

static void kpi_ranap_process_dl_rab_ass_req(struct hnbgw_context_map *map, ranap_message *ranap)
{
	struct hnb_persistent *hnbp = map->hnb_ctx->persistent;
	RANAP_RAB_AssignmentRequestIEs_t *ies;
	int rc;

	OSMO_ASSERT(ranap->procedureCode == RANAP_ProcedureCode_id_RAB_Assignment);

	ies = &ranap->msg.raB_AssignmentRequestIEs;

	if (ies->presenceMask & RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_SETUPORMODIFYLIST_PRESENT) {
		RANAP_RAB_SetupOrModifyList_t *som_list = &ies->raB_SetupOrModifyList;
		for (unsigned int i = 0; i < som_list->list.count; i++) {
			RANAP_ProtocolIE_ContainerPair_t *container_pair = som_list->list.array[i];
			RANAP_ProtocolIE_FieldPair_t *field_pair = container_pair->list.array[0];
			RANAP_RAB_SetupOrModifyItemFirst_t _rab_setup_or_modify_item_first = {};
			RANAP_RAB_SetupOrModifyItemFirst_t *rab_setup_or_modify_item_first = &_rab_setup_or_modify_item_first;
			uint8_t rab_id;

			if (!field_pair)
				continue;

			if (field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem)
				continue;

			rc = ranap_decode_rab_setupormodifyitemfirst(rab_setup_or_modify_item_first, &field_pair->firstValue);
			if (rc < 0)
				continue;

			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_setup_or_modify_item_first->rAB_ID.buf[0];

			/* the only way to distinguish a "setup" from a "modify" is to know which RABs are
			 * already established. If it's already established, it is a modification; if it's
			 * new, it is a setup */
			if (bitvec_get_bit_pos(&map->rab_active_mask.bv, rab_id))
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_MOD_REQ : HNB_CTR_RANAP_CS_RAB_MOD_REQ);
			else {
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_ACT_REQ : HNB_CTR_RANAP_CS_RAB_ACT_REQ);
				/* FIXME: only set on confirm? */
				bitvec_set_bit_pos(&map->rab_active_mask.bv, rab_id, 1);
			}

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, rab_setup_or_modify_item_first);
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_RELEASELIST_PRESENT) {
		RANAP_RAB_ReleaseList_t *r_list = &ies->raB_ReleaseList;
		/* increment number of released RABs, we don't need to do that individually during iteration */
		HNBP_CTR_ADD(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_REQ : HNB_CTR_RANAP_CS_RAB_REL_REQ,
			     r_list->raB_ReleaseList_ies.list.count);

		for (unsigned int i = 0; i < r_list->raB_ReleaseList_ies.list.count; i++) {
			RANAP_IE_t *release_list_ie = r_list->raB_ReleaseList_ies.list.array[i];
			RANAP_RAB_ReleaseItemIEs_t _rab_rel_item_ies = {};
			RANAP_RAB_ReleaseItemIEs_t *rab_rel_item_ies = &_rab_rel_item_ies;
			RANAP_RAB_ReleaseItem_t *rab_rel_item;
			uint8_t rab_id;

			if (!release_list_ie)
				continue;

			if (release_list_ie-> id != RANAP_ProtocolIE_ID_id_RAB_ReleaseItem)
				continue;

			rc = ranap_decode_rab_releaseitemies_fromlist(rab_rel_item_ies, &release_list_ie->value);
			if (rc < 0)
				continue;

			rab_rel_item = &rab_rel_item_ies->raB_ReleaseItem;
			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_rel_item->rAB_ID.buf[0];

			/* mark that RAB as released - FIXME: now or when the HNB confirms? */
			bitvec_set_bit_pos(&map->rab_active_mask.bv, rab_id, 0);

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_ReleaseItem, rab_rel_item_ies);
		}
	}
}

void kpi_ranap_process_dl(struct hnbgw_context_map *map, ranap_message *ranap)
{
	switch (ranap->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:			/* RAB ASSIGNMENT REQ (8.2) */
		kpi_ranap_process_dl_rab_ass_req(map, ranap);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		kpi_ranap_process_dl_iu_rel_cmd(map, ranap);		/* IU RELEASE CMD (8.5) */
		break;
	default:
		break;
	}
}

/***********************************************************************
 * UPLINK messages
 ***********************************************************************/

static void kpi_ranap_process_ul_rab_ass_resp(struct hnbgw_context_map *map, ranap_message *ranap)
{
	struct hnb_persistent *hnbp = map->hnb_ctx->persistent;
	RANAP_RAB_AssignmentResponseIEs_t *ies;

	OSMO_ASSERT(ranap->procedureCode == RANAP_ProcedureCode_id_RAB_Assignment);

	ies = &ranap->msg.raB_AssignmentResponseIEs;

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT) {
		RANAP_RAB_SetupOrModifiedList_t *som_list = &ies->raB_SetupOrModifiedList;
		for (unsigned int i = 0; i < som_list->raB_SetupOrModifiedList_ies.list.count; i++) {
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_RELEASEDLIST_PRESENT) {
		RANAP_RAB_ReleasedList_t *r_list = &ies->raB_ReleasedList;
		/* increment number of released RABs, we don't need to do that individually during iteration */
		HNBP_CTR_ADD(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_CNF : HNB_CTR_RANAP_CS_RAB_REL_CNF,
			     r_list->raB_ReleasedList_ies.list.count);
		for (unsigned int i = 0; i < r_list->raB_ReleasedList_ies.list.count; i++) {
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_QUEUEDLIST_PRESENT)
		LOGHNB(map->hnb_ctx, FIXME);

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_FAILEDLIST_PRESENT) {
		RANAP_RAB_FailedList_t *f_list = &ies->raB_FailedList;
		for (unsigned int i = 0; i < f_list->raB_FailedList_ies.list.count; i++) {
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_RELEASEFAILEDLIST_PRESENT) {
		RANAP_RAB_ReleaseFailedList_t *rf_list = &ies->raB_ReleaseFailedList;
		for (unsigned int i = 0; i < rf_list->raB_FailedList_ies.list.count; i++) {
		}
	}
}

void kpi_ranap_process_ul(struct hnbgw_context_map *map, ranap_message *ranap)
{
	switch (ranap->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:			/* RAB ASSIGNMENT REQ (8.2) */
		kpi_ranap_process_ul_rab_ass_resp(map, ranap);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		//kpi_ranap_process_dl_iu_rel_cmpl(map, ranap);		/* IU RELEASE COMPLETE (8.5) */
		break;
	default:
		break;
	}
}
