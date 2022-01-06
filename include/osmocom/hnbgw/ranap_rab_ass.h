#pragma once

int ranap_rab_ass_req_encode(uint8_t *data, unsigned int len,
			     RANAP_RAB_AssignmentRequestIEs_t *rab_assignment_request_ies);
int ranap_rab_ass_resp_encode(uint8_t *data, unsigned int len,
			      RANAP_RAB_AssignmentResponseIEs_t *rab_assignment_response_ies);

int ranap_rab_ass_req_ies_extract_inet_addr(struct osmo_sockaddr *addr, uint8_t *rab_id,
					    RANAP_RAB_AssignmentRequestIEs_t *ies);
int ranap_rab_ass_resp_ies_extract_inet_addr(struct osmo_sockaddr *addr, RANAP_RAB_AssignmentResponseIEs_t *ies,
					     uint8_t rab_id);

int ranap_rab_ass_req_ies_replace_inet_addr(RANAP_RAB_AssignmentRequestIEs_t *ies, struct osmo_sockaddr *addr,
					    uint8_t rab_id);
int ranap_rab_ass_resp_ies_replace_inet_addr(RANAP_RAB_AssignmentResponseIEs_t *ies, struct osmo_sockaddr *addr,
					     uint8_t rab_id);
