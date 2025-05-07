#pragma once

#include <stdint.h>
#include <unistd.h>
#include <osmocom/gsm/gsm23003.h>

struct umts_cell_id {
	struct osmo_plmn_id plmn;	/*!< Mobile Country Code and Mobile Network Code (000-00 to 999-999) */
	uint16_t lac;	/*!< Locaton Area Code (1-65534) */
	uint8_t rac;	/*!< Routing Area Code (0-255) */
	uint16_t sac;	/*!< Service Area Code */
	uint32_t cid;	/*!< Cell ID */
};
int umts_cell_id_to_str_buf(char *buf, size_t buflen, const struct umts_cell_id *ucid);
char *umts_cell_id_to_str_c(void *ctx, const struct umts_cell_id *ucid);
const char *umts_cell_id_to_str(const struct umts_cell_id *ucid);
int umts_cell_id_from_str(struct umts_cell_id *ucid, const char *instr);
uint32_t umts_cell_id_hash(const struct umts_cell_id *ucid);

/*! are both given umts_cell_id euqal? */
static inline bool umts_cell_id_equal(const struct umts_cell_id *a, const struct umts_cell_id *b)
{
	if (osmo_plmn_cmp(&a->plmn, &b->plmn))
		return false;
	if (a->lac != b->lac)
		return false;
	if (a->rac != b->rac)
		return false;
	if (a->sac != b->sac)
		return false;
	if (a->cid != b->cid)
		return false;
	return true;
}
