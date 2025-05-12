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

#include <osmocom/hnbgw/hnb_persistent.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/kpi.h>

const struct value_string hnbgw_rab_state_names[] = {
	{ RAB_STATE_INACTIVE,	"INACTIVE" },
	{ RAB_STATE_ACT_REQ,	"ACT_REQ" },
	{ RAB_STATE_ACTIVE,	"ACTIVE" },
	{ RAB_STATE_REL_REQ,	"REL_REQ" },
	{}
};

/***********************************************************************
 * DOWNLINK messages
 ***********************************************************************/

static void kpi_ranap_process_dl_iu_rel_cmd(struct hnbgw_context_map *map, const ranap_message *ranap)
{
	struct hnb_persistent *hnbp = map->hnb_ctx->persistent;
	const RANAP_Cause_t *cause;

	OSMO_ASSERT(ranap->procedureCode == RANAP_ProcedureCode_id_Iu_Release);

	cause = &ranap->msg.iu_ReleaseCommandIEs.cause;

	/* When Iu is released, all RABs are released implicitly */
	for (unsigned int i = 0; i < ARRAY_SIZE(map->rab_state); i++) {
		switch (map->rab_state[i]) {
		case RAB_STATE_ACTIVE:
			if (cause->present == RANAP_Cause_PR_nAS ||
			    cause->choice.nAS == RANAP_CauseNAS_normal_release) {
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT :
								HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT);
			} else {
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_IMPLICIT_ABNORMAL :
								HNB_CTR_RANAP_CS_RAB_REL_IMPLICIT_ABNORMAL);
			}
			break;
		}
	}
	/* clear all RAB state */
	memset(map->rab_state, 0, sizeof(map->rab_state));
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
			switch (map->rab_state[rab_id]) {
			case RAB_STATE_ACTIVE:
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_MOD_REQ : HNB_CTR_RANAP_CS_RAB_MOD_REQ);
				break;
			case RAB_STATE_INACTIVE:
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_ACT_REQ : HNB_CTR_RANAP_CS_RAB_ACT_REQ);
				map->rab_state[rab_id] = RAB_STATE_ACT_REQ;
				break;
			default:
				LOG_MAP(map, DRANAP, LOGL_NOTICE,
					"Unexpected RAB Activation/Modification Req for RAB in state %s\n",
					hnbgw_rab_state_name(map->rab_state[rab_id]));
				break;
			}

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, rab_setup_or_modify_item_first);
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_RELEASELIST_PRESENT) {
		RANAP_RAB_ReleaseList_t *r_list = &ies->raB_ReleaseList;
		for (unsigned int i = 0; i < r_list->raB_ReleaseList_ies.list.count; i++) {
			RANAP_IE_t *release_list_ie = r_list->raB_ReleaseList_ies.list.array[i];
			RANAP_RAB_ReleaseItemIEs_t _rab_rel_item_ies = {};
			RANAP_RAB_ReleaseItemIEs_t *rab_rel_item_ies = &_rab_rel_item_ies;
			RANAP_RAB_ReleaseItem_t *rab_rel_item;
			uint8_t rab_id;

			if (!release_list_ie)
				continue;

			if (release_list_ie->id != RANAP_ProtocolIE_ID_id_RAB_ReleaseItem)
				continue;

			rc = ranap_decode_rab_releaseitemies_fromlist(rab_rel_item_ies, &release_list_ie->value);
			if (rc < 0)
				continue;

			rab_rel_item = &rab_rel_item_ies->raB_ReleaseItem;
			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_rel_item->rAB_ID.buf[0];

			switch (map->rab_state[rab_id]) {
			case RAB_STATE_ACTIVE:
				if (rab_rel_item->cause.present == RANAP_Cause_PR_nAS &&
				    rab_rel_item->cause.choice.nAS == RANAP_CauseNAS_normal_release) {
					HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_REQ :
									HNB_CTR_RANAP_CS_RAB_REL_REQ);
				} else {
					HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_REQ_ABNORMAL :
									HNB_CTR_RANAP_CS_RAB_REL_REQ_ABNORMAL);
				}
				break;
			default:
				LOG_MAP(map, DRANAP, LOGL_NOTICE,
					"Unexpected RAB Release Req in state %s\n",
					hnbgw_rab_state_name(map->rab_state[rab_id]));
				break;
			}
			/* mark that RAB as release requested */
			map->rab_state[rab_id] = RAB_STATE_REL_REQ;

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_ReleaseItem, rab_rel_item_ies);
		}
	}
}

static void kpi_ranap_process_dl_direct_transfer(struct hnbgw_context_map *map, ranap_message *ranap)
{
	const RANAP_DirectTransferIEs_t *dt_ies = &ranap->msg.directTransferIEs;
	uint8_t sapi = 0;

	if (dt_ies->presenceMask & DIRECTTRANSFERIES_RANAP_SAPI_PRESENT) {
		if (dt_ies->sapi == RANAP_SAPI_sapi_3)
			sapi = 3;
	}
	kpi_dtap_process_dl(map, dt_ies->nas_pdu.buf, dt_ies->nas_pdu.size, sapi);
}

void kpi_ranap_process_dl(struct hnbgw_context_map *map, ranap_message *ranap)
{
	if (map->hnb_ctx == NULL) {
		/* This can happen if the HNB has disconnected and we are processing downlink messages
		 * from the CN which were already in flight before the CN side has realized the HNB
		 * is gone. */
		return;
	}

	switch (ranap->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:			/* RAB ASSIGNMENT REQ (8.2) */
		kpi_ranap_process_dl_rab_ass_req(map, ranap);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		kpi_ranap_process_dl_iu_rel_cmd(map, ranap);		/* IU RELEASE CMD (8.5) */
		break;
	case RANAP_ProcedureCode_id_DirectTransfer:
		kpi_ranap_process_dl_direct_transfer(map, ranap);
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
	int rc;

	OSMO_ASSERT(ranap->procedureCode == RANAP_ProcedureCode_id_RAB_Assignment);

	ies = &ranap->msg.raB_AssignmentResponseIEs;

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT) {
		RANAP_RAB_SetupOrModifiedList_t *som_list = &ies->raB_SetupOrModifiedList;
		for (unsigned int i = 0; i < som_list->raB_SetupOrModifiedList_ies.list.count; i++) {
			RANAP_IE_t *som_list_ie = som_list->raB_SetupOrModifiedList_ies.list.array[i];
			RANAP_RAB_SetupOrModifiedItemIEs_t _rab_som_item_ies = {};
			RANAP_RAB_SetupOrModifiedItemIEs_t *rab_som_item_ies = &_rab_som_item_ies;
			RANAP_RAB_SetupOrModifiedItem_t *rab_som_item;
			uint8_t rab_id;

			if (!som_list_ie)
				continue;

			if (som_list_ie->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifiedItem)
				continue;

			rc = ranap_decode_rab_setupormodifieditemies_fromlist(rab_som_item_ies, &som_list_ie->value);
			if (rc < 0)
				continue;

			rab_som_item = &rab_som_item_ies->raB_SetupOrModifiedItem;
			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_som_item->rAB_ID.buf[0];

			/* differentiate modify / activate */
			switch (map->rab_state[rab_id]) {
			case RAB_STATE_ACT_REQ:
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_ACT_CNF : HNB_CTR_RANAP_CS_RAB_ACT_CNF);
				map->rab_state[rab_id] = RAB_STATE_ACTIVE;
				break;
			case RAB_STATE_ACTIVE:
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_MOD_CNF : HNB_CTR_RANAP_CS_RAB_MOD_CNF);
				break;
			default:
				LOG_MAP(map, DRANAP, LOGL_NOTICE,
					"Unexpected RAB Activation/Modification Conf for RAB in state %s\n",
					hnbgw_rab_state_name(map->rab_state[rab_id]));
				break;
			}

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, rab_som_item_ies);
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_RELEASEDLIST_PRESENT) {
		RANAP_RAB_ReleasedList_t *r_list = &ies->raB_ReleasedList;
		/* increment number of released RABs, we don't need to do that individually during iteration */
		HNBP_CTR_ADD(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_CNF : HNB_CTR_RANAP_CS_RAB_REL_CNF,
			     r_list->raB_ReleasedList_ies.list.count);
		for (unsigned int i = 0; i < r_list->raB_ReleasedList_ies.list.count; i++) {
			RANAP_IE_t *released_list_ie = r_list->raB_ReleasedList_ies.list.array[i];
			RANAP_RAB_ReleasedItemIEs_t _rab_rel_item_ies = {};
			RANAP_RAB_ReleasedItemIEs_t *rab_rel_item_ies = &_rab_rel_item_ies;
			RANAP_RAB_ReleasedItem_t *rab_rel_item;
			uint8_t rab_id;

			if (!released_list_ie)
				continue;

			if (released_list_ie->id != RANAP_ProtocolIE_ID_id_RAB_ReleasedItem)
				continue;

			rc = ranap_decode_rab_releaseditemies_fromlist(rab_rel_item_ies, &released_list_ie->value);
			if (rc < 0)
				continue;

			rab_rel_item = &rab_rel_item_ies->raB_ReleasedItem;
			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_rel_item->rAB_ID.buf[0];

			switch (map->rab_state[rab_id]) {
			case RAB_STATE_REL_REQ:
				break;
			default:
				LOG_MAP(map, DRANAP, LOGL_NOTICE,
					"Unexpected RAB Release Conf for RAB in state %s\n",
					hnbgw_rab_state_name(map->rab_state[rab_id]));
				break;
			}
			/* mark that RAB as released */
			map->rab_state[rab_id] = RAB_STATE_INACTIVE;

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_ReleasedItem, rab_rel_item_ies);
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_QUEUEDLIST_PRESENT)
		LOG_MAP(map, DRANAP, LOGL_NOTICE, "RAB Activation has been queued; we don't support KPIs for this\n");

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_FAILEDLIST_PRESENT) {
		RANAP_RAB_FailedList_t *f_list = &ies->raB_FailedList;
		for (unsigned int i = 0; i < f_list->raB_FailedList_ies.list.count; i++) {
			RANAP_IE_t *failed_list_ie = f_list->raB_FailedList_ies.list.array[i];
			RANAP_RAB_FailedItemIEs_t _rab_failed_item_ies = {};
			RANAP_RAB_FailedItemIEs_t *rab_failed_item_ies = &_rab_failed_item_ies;
			RANAP_RAB_FailedItem_t *rab_failed_item;
			uint8_t rab_id;

			if (!failed_list_ie)
				continue;

			if (failed_list_ie->id != RANAP_ProtocolIE_ID_id_RAB_FailedItem)
				continue;

			rc = ranap_decode_rab_faileditemies_fromlist(rab_failed_item_ies, &failed_list_ie->value);
			if (rc < 0)
				continue;

			rab_failed_item = &rab_failed_item_ies->raB_FailedItem;
			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_failed_item->rAB_ID.buf[0];

			/* differentiate modify / activate */
			switch (map->rab_state[rab_id]) {
			case RAB_STATE_ACT_REQ:
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_ACT_FAIL : HNB_CTR_RANAP_CS_RAB_ACT_FAIL);
				map->rab_state[rab_id] = RAB_STATE_INACTIVE;
				break;
			case RAB_STATE_ACTIVE:
				HNBP_CTR_INC(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_MOD_FAIL : HNB_CTR_RANAP_CS_RAB_MOD_FAIL);
				// FIXME: does it remain active after modification failure?
				break;
			default:
				LOG_MAP(map, DRANAP, LOGL_NOTICE,
					"Unexpected RAB Activation/Modification Failed for RAB in state %s\n",
					hnbgw_rab_state_name(map->rab_state[rab_id]));
				break;
			}

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_FailedItem, rab_failed_item_ies);
		}
	}

	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_RELEASEFAILEDLIST_PRESENT) {
		RANAP_RAB_ReleaseFailedList_t *rf_list = &ies->raB_ReleaseFailedList;
		/* increment number of released RABs, we don't need to do that individually during iteration */
		HNBP_CTR_ADD(hnbp, map->is_ps ? HNB_CTR_RANAP_PS_RAB_REL_FAIL : HNB_CTR_RANAP_CS_RAB_REL_FAIL,
			     rf_list->raB_FailedList_ies.list.count);
		for (unsigned int i = 0; i < rf_list->raB_FailedList_ies.list.count; i++) {
			RANAP_IE_t *failed_list_ie = rf_list->raB_FailedList_ies.list.array[i];
			RANAP_RAB_FailedItemIEs_t _rab_failed_item_ies = {};
			RANAP_RAB_FailedItemIEs_t *rab_failed_item_ies = &_rab_failed_item_ies;
			RANAP_RAB_FailedItem_t *rab_failed_item;
			uint8_t rab_id;

			if (!failed_list_ie)
				continue;

			if (failed_list_ie->id != RANAP_ProtocolIE_ID_id_RAB_FailedItem)
				continue;

			rc = ranap_decode_rab_faileditemies_fromlist(rab_failed_item_ies, &failed_list_ie->value);
			if (rc < 0)
				continue;

			rab_failed_item = &rab_failed_item_ies->raB_FailedItem;
			/* RAB-ID is an 8-bit bit-string, so it's the first byte */
			rab_id = rab_failed_item->rAB_ID.buf[0];

			/* differentiate modify / activate */
			switch (map->rab_state[rab_id]) {
			case RAB_STATE_ACT_REQ:
				map->rab_state[rab_id] = RAB_STATE_INACTIVE;
				break;
			case RAB_STATE_ACTIVE:
				// FIXME: does it remain active after modification failure?
				break;
			default:
				LOG_MAP(map, DRANAP, LOGL_NOTICE,
					"Unexpected RAB Release Failed for RAB in state %s\n",
					hnbgw_rab_state_name(map->rab_state[rab_id]));
				break;
			}

			ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_FailedItem, rab_failed_item_ies);

		}
	}
}

static void kpi_ranap_process_ul_initial_ue(struct hnbgw_context_map *map, ranap_message *ranap)
{
	const RANAP_InitialUE_MessageIEs_t *iue_ies = &ranap->msg.initialUE_MessageIEs;
	kpi_dtap_process_ul(map, iue_ies->nas_pdu.buf, iue_ies->nas_pdu.size, 0);
}

static void kpi_ranap_process_ul_direct_transfer(struct hnbgw_context_map *map, ranap_message *ranap)
{
	const RANAP_DirectTransferIEs_t *dt_ies = &ranap->msg.directTransferIEs;
	uint8_t sapi = 0;

	if (dt_ies->presenceMask & DIRECTTRANSFERIES_RANAP_SAPI_PRESENT) {
		if (dt_ies->sapi == RANAP_SAPI_sapi_3)
			sapi = 3;
	}
	kpi_dtap_process_ul(map, dt_ies->nas_pdu.buf, dt_ies->nas_pdu.size, sapi);
}

void kpi_ranap_process_ul(struct hnbgw_context_map *map, ranap_message *ranap)
{
	/* we should never be processing uplink messages from a non-existant HNB */
	OSMO_ASSERT(map->hnb_ctx);

	switch (ranap->procedureCode) {
	case RANAP_ProcedureCode_id_RAB_Assignment:			/* RAB ASSIGNMENT REQ (8.2) */
		kpi_ranap_process_ul_rab_ass_resp(map, ranap);
		break;
	case RANAP_ProcedureCode_id_Iu_Release:
		/* TODO: We might want to parse the list of released RABs here and then mark each of those as
		 * released.  For now we simply assume that all RABs are released in IU RELEASE during
		 * processing of the downlink Iu Release Command.  It's not like the RNC/HNB has any way to
		 * refuse the release anyway. */
		break;
	case RANAP_ProcedureCode_id_InitialUE_Message:
		kpi_ranap_process_ul_initial_ue(map, ranap);
		break;
	case RANAP_ProcedureCode_id_DirectTransfer:
		kpi_ranap_process_ul_direct_transfer(map, ranap);
		break;
	default:
		break;
	}
}
