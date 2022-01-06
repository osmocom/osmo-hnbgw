/* (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* Note: This files contains tools to decode and re-encode the RAB-AssignmentRequest. This set of tools is used by
 * mgcp_fsm.c to extract and manipulate the transportLayerAddress. */

#include <errno.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_common_ran.h>
#include <osmocom/ranap/iu_helpers.h>
#include <asn1c/asn1helpers.h>

/*! Encode RABAP RAB AssignmentRequest from RANAP_RAB_AssignmentRequestIEs.
 *  \ptmap[out] data user provided memory to store resulting ASN.1 encoded message.
 *  \ptmap[in] len length of user provided memory to store resulting ASN.1 encoded message.
 *  \ptmap[in] ies user provided memory with RANAP_RAB_AssignmentRequestIEs.
 *  \returns resulting message length on success; negative on error. */
int ranap_rab_ass_req_encode(uint8_t *data, unsigned int len,
			     RANAP_RAB_AssignmentRequestIEs_t *rab_assignment_request_ies)
{
	int rc;
	struct msgb *msg;
	RANAP_RAB_AssignmentRequest_t _rab_assignment_request;
	RANAP_RAB_AssignmentRequest_t *rab_assignment_request = &_rab_assignment_request;

	memset(data, 0, len);
	memset(rab_assignment_request, 0, sizeof(*rab_assignment_request));

	rc = ranap_encode_rab_assignmentrequesties(rab_assignment_request, rab_assignment_request_ies);
	if (rc < 0)
		return -EINVAL;

	/* generate an Initiating Mesasage */
	msg = ranap_generate_initiating_message(RANAP_ProcedureCode_id_RAB_Assignment,
						RANAP_Criticality_reject,
						&asn_DEF_RANAP_RAB_AssignmentRequest, rab_assignment_request);

	/* 'msg' has been generated, we cann now release the input 'out' */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_AssignmentRequest, rab_assignment_request);

	if (!msg)
		return -EINVAL;
	if (msg->len > len)
		return -EINVAL;

	memcpy(data, msg->data, msg->len);
	rc = msg->len;
	msgb_free(msg);
	return rc;
}

/*! Encode RABAP RAB AssignmentRequest from RANAP_RAB_AssignmentResponseIEs.
 *  \ptmap[out] data user provided memory to store resulting ASN.1 encoded message.
 *  \ptmap[in] len length of user provided memory to store resulting ASN.1 encoded message.
 *  \ptmap[in] ies user provided memory with RANAP_RAB_AssignmentResponseIEs.
 *  \returns resulting message length on success; negative on error. */
int ranap_rab_ass_resp_encode(uint8_t *data, unsigned int len,
			      RANAP_RAB_AssignmentResponseIEs_t *rab_assignment_response_ies)
{
	int rc;
	struct msgb *msg;

	RANAP_RAB_AssignmentResponse_t _rab_assignment_response;
	RANAP_RAB_AssignmentResponse_t *rab_assignment_response = &_rab_assignment_response;

	memset(data, 0, len);
	memset(rab_assignment_response, 0, sizeof(*rab_assignment_response));

	rc = ranap_encode_rab_assignmentresponseies(rab_assignment_response, rab_assignment_response_ies);
	if (rc < 0)
		return -EINVAL;

	/* generate an outcome mesasage */
	msg = ranap_generate_outcome(RANAP_ProcedureCode_id_RAB_Assignment,
				     RANAP_Criticality_reject,
				     &asn_DEF_RANAP_RAB_AssignmentResponse, rab_assignment_response);

	/* 'msg' has been generated, we cann now release the input 'out' */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_AssignmentResponse, rab_assignment_response);

	if (!msg)
		return -EINVAL;
	if (msg->len > len)
		return -EINVAL;

	memcpy(data, msg->data, msg->len);
	rc = msg->len;
	msgb_free(msg);
	return rc;
}

/* Pick the indexed item from the RAB setup-or-modify list and return the first protocol-ie-field-pair. */
static RANAP_ProtocolIE_FieldPair_t *prot_ie_field_pair_from_ass_req_ies(const RANAP_RAB_AssignmentRequestIEs_t *ies, unsigned int index)
{
	RANAP_ProtocolIE_ContainerPair_t *protocol_ie_container_pair;
	RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;

	/* Make sure we indeed deal with a setup-or-modify list */
	if (!(ies->presenceMask & RAB_ASSIGNMENTREQUESTIES_RANAP_RAB_SETUPORMODIFYLIST_PRESENT)) {
		RANAP_DEBUG
		    ("Decoding failed, the RANAP RAB AssignmentRequest did not contain a setup-or-modify list!\n");
		return NULL;
	}

	/* Detect the end of the list */
	if (index >= ies->raB_SetupOrModifyList.list.count)
		return NULL;

	protocol_ie_container_pair = ies->raB_SetupOrModifyList.list.array[index];
	protocol_ie_field_pair = protocol_ie_container_pair->list.array[0];

	return protocol_ie_field_pair;
}

/* See also comment above prot_ie_field_pair_from_ass_req_ies */
static RANAP_IE_t *setup_or_modif_item_from_rab_ass_resp(const RANAP_RAB_AssignmentResponseIEs_t * ies,
							 unsigned int index)
{
	/* Make sure we indeed deal with a setup-or-modified list */
	if (!(ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT)) {
		RANAP_DEBUG
		    ("Decoding failed, the RANAP RAB AssignmentResponse did not contain a setup-or-modified list!\n");
		return NULL;
	}

	/* Detect the end of the list */
	if (index >= ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.count)
		return NULL;

	return ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.array[index];
}

/* find the RAB specified by rab_id in ies and when found, decode the result into items_ies */
static int decode_rab_smditms_from_resp_ies(RANAP_RAB_SetupOrModifiedItemIEs_t * items_ies,
					    RANAP_RAB_AssignmentResponseIEs_t * ies, uint8_t rab_id)
{
	RANAP_IE_t *setup_or_modified_list_ie;
	RANAP_RAB_SetupOrModifiedItem_t *rab_setup_or_modified_item;
	int rc;
	uint8_t rab_id_decoded;
	unsigned int index = 0;

	while (1) {
		setup_or_modified_list_ie = setup_or_modif_item_from_rab_ass_resp(ies, index);
		if (!setup_or_modified_list_ie)
			return -EINVAL;

		rc = ranap_decode_rab_setupormodifieditemies_fromlist(items_ies, &setup_or_modified_list_ie->value);
		if (rc < 0)
			return -EINVAL;

		rab_setup_or_modified_item = &items_ies->raB_SetupOrModifiedItem;
		/* The RAB-ID is defined as a bitstring with a size of 8 (1 byte),
		 * See also RANAP-IEs.asn, RAB-ID ::= BIT STRING (SIZE (8)) */
		rab_id_decoded = rab_setup_or_modified_item->rAB_ID.buf[0];
		if (rab_id_decoded == rab_id)
			return index;

		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, items_ies);
		index++;
	}
}

/* find the RAB specified by rab_id in ies and when found, decode the result into item */
static int decode_rab_smditms_from_req_ies(RANAP_RAB_SetupOrModifyItemFirst_t * item,
					   RANAP_RAB_AssignmentRequestIEs_t * ies, uint8_t rab_id)
{
	RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;
	int rc;
	uint8_t rab_id_decoded;
	unsigned int index = 0;

	while (1) {
		protocol_ie_field_pair = prot_ie_field_pair_from_ass_req_ies(ies, index);
		if (!protocol_ie_field_pair)
			return -EINVAL;

		if (protocol_ie_field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem) {
			RANAP_DEBUG
			    ("Decoding failed, the protocol IE field-pair is not of type RANAP RAB setup-or-modify-item!\n");
			return -EINVAL;
		}

		rc = ranap_decode_rab_setupormodifyitemfirst(item, &protocol_ie_field_pair->firstValue);
		if (rc < 0)
			return -EINVAL;

		rab_id_decoded = item->rAB_ID.buf[0];
		if (rab_id_decoded == rab_id)
			return index;
	}
}

/*! Extract IP address and port from RANAP_RAB_AssignmentRequestIEs.
 *  \ptmap[out] addr user provided memory to store extracted RTP stream IP-Address and port number.
 *  \ptmap[out] rab_id pointer to store RAB-ID (optional, can be NULL).
 *  \ptmap[in] ies user provided memory with RANAP_RAB_AssignmentRequestIEs.
 *  \returns 0 on success; negative on error. */
int ranap_rab_ass_req_ies_extract_inet_addr(struct osmo_sockaddr *addr, uint8_t *rab_id,
					    RANAP_RAB_AssignmentRequestIEs_t *ies)
{
	RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;
	RANAP_RAB_SetupOrModifyItemFirst_t _rab_setup_or_modify_item_first;
	RANAP_RAB_SetupOrModifyItemFirst_t *rab_setup_or_modify_item_first = &_rab_setup_or_modify_item_first;
	RANAP_TransportLayerAddress_t *trasp_layer_addr;
	RANAP_IuTransportAssociation_t *transp_assoc;
	uint16_t port;
	int rc;

	protocol_ie_field_pair = prot_ie_field_pair_from_ass_req_ies(ies, 0);
	if (!protocol_ie_field_pair)
		return -EINVAL;

	if (protocol_ie_field_pair->id != RANAP_ProtocolIE_ID_id_RAB_SetupOrModifyItem) {
		RANAP_DEBUG
		    ("Decoding failed, the protocol IE field-pair is not of type RANAP RAB setup-or-modify-item!\n");
		return -EINVAL;
	}

	rc = ranap_decode_rab_setupormodifyitemfirst(rab_setup_or_modify_item_first,
						     &protocol_ie_field_pair->firstValue);
	if (rc < 0)
		return -EINVAL;

	if (rab_id) {
		/* The RAB-ID is defined as a bitstring with a size of 8 (1 byte),
		 * See also RANAP-IEs.asn, RAB-ID ::= BIT STRING (SIZE (8)) */
		*rab_id = rab_setup_or_modify_item_first->rAB_ID.buf[0];
	}

	/* Decode IP-Address */
	trasp_layer_addr = &rab_setup_or_modify_item_first->transportLayerInformation->transportLayerAddress;
	rc = ranap_transp_layer_addr_decode2(addr, NULL, trasp_layer_addr);
	if (rc < 0) {
		rc = -EINVAL;
		goto error;
	}

	/* Decode port number */
	transp_assoc = &rab_setup_or_modify_item_first->transportLayerInformation->iuTransportAssociation;
	rc = ranap_transp_assoc_decode(&port, transp_assoc);
	if (rc < 0) {
		rc = -EINVAL;
		goto error;
	}

	switch (addr->u.sin.sin_family) {
	case AF_INET:
		addr->u.sin.sin_port = htons(port);
		break;
	case AF_INET6:
		addr->u.sin6.sin6_port = htons(port);
		break;
	default:
		rc = -EINVAL;
		goto error;
	}

	rc = 0;
error:
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, rab_setup_or_modify_item_first);
	return rc;
}

/*! Extract IP address and port from RANAP_RAB_AssignmentResponseIEs.
 *  \ptmap[out] addr user provided memory to store extracted RTP stream IP-Address and port number.
 *  \ptmap[in] ies user provided memory with RANAP_RAB_AssignmentResponseIEs.
 *  \ptmap[in] rab_id expected rab id to look for.
 *  \returns 0 on success; negative on error. */
int ranap_rab_ass_resp_ies_extract_inet_addr(struct osmo_sockaddr *addr, RANAP_RAB_AssignmentResponseIEs_t *ies, uint8_t rab_id)
{
	RANAP_RAB_SetupOrModifiedItemIEs_t _rab_setup_or_modified_items_ies;
	RANAP_RAB_SetupOrModifiedItemIEs_t *rab_setup_or_modified_items_ies = &_rab_setup_or_modified_items_ies;
	RANAP_RAB_SetupOrModifiedItem_t *rab_setup_or_modified_item;
	uint16_t port;
	int rc;

        rc = decode_rab_smditms_from_resp_ies(rab_setup_or_modified_items_ies, ies, rab_id);
	if (rc < 0)
		return -EINVAL;

	rab_setup_or_modified_item = &rab_setup_or_modified_items_ies->raB_SetupOrModifiedItem;

	/* Decode IP-Address */
	rc = ranap_transp_layer_addr_decode2(addr, NULL, rab_setup_or_modified_item->transportLayerAddress);
	if (rc < 0) {
		rc = -EINVAL;
		goto error;
	}

	/* Decode port number */
	rc = ranap_transp_assoc_decode(&port, rab_setup_or_modified_item->iuTransportAssociation);
	if (rc < 0) {
		rc = -EINVAL;
		goto error;
	}

	switch (addr->u.sin.sin_family) {
	case AF_INET:
		addr->u.sin.sin_port = htons(port);
		break;
	case AF_INET6:
		addr->u.sin6.sin6_port = htons(port);
		break;
	default:
		rc = -EINVAL;
		goto error;
	}

	rc = 0;
error:
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, rab_setup_or_modified_items_ies);
	return rc;
}

/*! Replace IP address and port in RANAP_RAB_AssignmentRequestIEs.
 *  \ptmap[inout] ies user provided memory with RANAP_RAB_AssignmentRequestIEs.
 *  \ptmap[in] addr user provided memory that contains the new RTP stream IP-Address and port number.
 *  \ptmap[in] rab_id expected rab id to look for.
 *  \returns 0 on success; negative on error. */
int ranap_rab_ass_req_ies_replace_inet_addr(RANAP_RAB_AssignmentRequestIEs_t *ies, struct osmo_sockaddr *addr, uint8_t rab_id)
{
	RANAP_ProtocolIE_FieldPair_t *protocol_ie_field_pair;
	RANAP_RAB_SetupOrModifyItemFirst_t _rab_setup_or_modify_item_first;
	RANAP_RAB_SetupOrModifyItemFirst_t *rab_setup_or_modify_item_first = &_rab_setup_or_modify_item_first;
	RANAP_TransportLayerInformation_t *old_transport_layer_information = NULL;
	RANAP_TransportLayerInformation_t *new_transport_layer_information = NULL;
	struct osmo_sockaddr addr_old;
	bool uses_x213_nsap;
	int rc;
	int index;

	index = decode_rab_smditms_from_req_ies(rab_setup_or_modify_item_first, ies, rab_id);
	if (index < 0)
		return -EINVAL;

	/* Replace transport-layer-information */
	if (rab_setup_or_modify_item_first->transportLayerInformation->iuTransportAssociation.present ==
	    RANAP_IuTransportAssociation_PR_bindingID) {
		old_transport_layer_information = rab_setup_or_modify_item_first->transportLayerInformation;

		/* Before we can re-encode the transport layer information, we need to know the format it was
		 * encoded in. */
		rc = ranap_transp_layer_addr_decode2(&addr_old, &uses_x213_nsap,
						     &old_transport_layer_information->transportLayerAddress);
		if (rc < 0) {
			rc = -EINVAL;
			goto error;
		}

		/* Encode a new transport layer information field */
		new_transport_layer_information = ranap_new_transp_info_rtp(addr, uses_x213_nsap);
		if (!new_transport_layer_information) {
			rc = -EINVAL;
			goto error;
		}

		rab_setup_or_modify_item_first->transportLayerInformation = new_transport_layer_information;
	} else {
		RANAP_DEBUG("Rewriting transport layer information failed, no bindingID (port)!\n");
		rc = -EINVAL;
		goto error;
	}

	/* Reencode transport-layer-information */
	protocol_ie_field_pair = prot_ie_field_pair_from_ass_req_ies(ies, index);
	rc = ANY_fromType_aper(&protocol_ie_field_pair->firstValue, &asn_DEF_RANAP_RAB_SetupOrModifyItemFirst,
			       rab_setup_or_modify_item_first);
	if (rc < 0) {
		RANAP_DEBUG("Rewriting transport layer information failed, could not reencode\n");
		rc = -EINVAL;
		goto error;
	}

error:
	/* Restore original state of the modified ASN.1 struct so that the asn1c free mechanisms can work properly */
	if (old_transport_layer_information)
		rab_setup_or_modify_item_first->transportLayerInformation = old_transport_layer_information;

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifyItemFirst, rab_setup_or_modify_item_first);
	if (new_transport_layer_information)
		ASN_STRUCT_FREE(asn_DEF_RANAP_TransportLayerInformation, new_transport_layer_information);
	return rc;
}

/*! Replace IP address and port in RANAP_RAB_AssignmentResponseIEs.
 *  \ptmap[inout] ies user provided memory with RANAP_RAB_AssignmentResponseIEs.
 *  \ptmap[in] addr user provided memory that contains the new RTP stream IP-Address and port number.
 *  \ptmap[in] rab_id expected rab id to look for.
 *  \returns 0 on success; negative on error. */
int ranap_rab_ass_resp_ies_replace_inet_addr(RANAP_RAB_AssignmentResponseIEs_t *ies, struct osmo_sockaddr *addr, uint8_t rab_id)
{
	RANAP_IE_t *setup_or_modified_list_ie;
	RANAP_RAB_SetupOrModifiedItemIEs_t _rab_setup_or_modified_items_ies;
	RANAP_RAB_SetupOrModifiedItemIEs_t *rab_setup_or_modified_items_ies = &_rab_setup_or_modified_items_ies;
	RANAP_RAB_SetupOrModifiedItem_t *rab_setup_or_modified_item;
	RANAP_TransportLayerInformation_t *temp_transport_layer_information = NULL;
	RANAP_TransportLayerAddress_t *old_transport_layer_address = NULL;
	RANAP_IuTransportAssociation_t *old_iu_transport_association = NULL;
	struct osmo_sockaddr addr_old;
	bool uses_x213_nsap;
	int rc;
	int index;

        index = decode_rab_smditms_from_resp_ies(rab_setup_or_modified_items_ies, ies, rab_id);
	if (index < 0)
		return -EINVAL;

	rab_setup_or_modified_item = &rab_setup_or_modified_items_ies->raB_SetupOrModifiedItem;

	/* Before we can re-encode the transport layer address, we need to know the format it was encoded in. */
	rc = ranap_transp_layer_addr_decode2(&addr_old, &uses_x213_nsap,
					     rab_setup_or_modified_item->transportLayerAddress);
	if (rc < 0) {
		rc = -EINVAL;
		goto error;
	}

	/* Generate a temporary transport layer information, from which we can use the transport layer address and
	 * the iu transport association to update the setup or modified item */
	temp_transport_layer_information = ranap_new_transp_info_rtp(addr, uses_x213_nsap);
	if (!temp_transport_layer_information) {
		rc = -EINVAL;
		goto error;
	}

	/* Replace transport layer address and iu transport association */
	old_transport_layer_address = rab_setup_or_modified_item->transportLayerAddress;
	old_iu_transport_association = rab_setup_or_modified_item->iuTransportAssociation;
	rab_setup_or_modified_item->transportLayerAddress = &temp_transport_layer_information->transportLayerAddress;
	rab_setup_or_modified_item->iuTransportAssociation = &temp_transport_layer_information->iuTransportAssociation;

	/* Reencode modified setup or modified list */
	setup_or_modified_list_ie = setup_or_modif_item_from_rab_ass_resp(ies, index);
	rc = ANY_fromType_aper(&setup_or_modified_list_ie->value, &asn_DEF_RANAP_RAB_SetupOrModifiedItem,
			       rab_setup_or_modified_items_ies);
	if (rc < 0) {
		RANAP_DEBUG("Rewriting transport layer address failed, could not reencode\n");
		rc = -EINVAL;
		goto error;
	}

error:
	/* Restore original state of the modified ASN.1 struct so that the asn1c free mechanisms can work properly */
	if (old_transport_layer_address)
		rab_setup_or_modified_item->transportLayerAddress = old_transport_layer_address;
	if (old_iu_transport_association)
		rab_setup_or_modified_item->iuTransportAssociation = old_iu_transport_association;
	if (temp_transport_layer_information)
		ASN_STRUCT_FREE(asn_DEF_RANAP_TransportLayerInformation, temp_transport_layer_information);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RANAP_RAB_SetupOrModifiedItem, rab_setup_or_modified_items_ies);

	return rc;
}
