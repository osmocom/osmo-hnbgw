/* UMTS Cell ID */

/* (C) 2015,2024 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/jhash.h>

#include <osmocom/gsm/gsm23003.h>

#include <osmocom/hnbgw/umts_cell_id.h>

int umts_cell_id_to_str_buf(char *buf, size_t buflen, const struct umts_cell_id *ucid)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_APPEND_NOLEN(sb, osmo_plmn_name_buf, &ucid->plmn);
	OSMO_STRBUF_PRINTF(sb, "-L%u-R%u-S%u-C%u", ucid->lac, ucid->rac, ucid->sac, ucid->cid);
	return sb.chars_needed;
}

char *umts_cell_id_to_str_c(void *ctx, const struct umts_cell_id *ucid)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", umts_cell_id_to_str_buf, ucid)
}

const char *umts_cell_id_to_str(const struct umts_cell_id *ucid)
{
	return umts_cell_id_to_str_c(OTC_SELECT, ucid);
}

/* Useful to index a hash table by struct umts_cell_id. */
uint32_t umts_cell_id_hash(const struct umts_cell_id *ucid)
{
	return osmo_jhash(ucid, sizeof(*ucid), 0x423423);
}

/* parse a string representation of an umts_cell_id into its decoded representation */
int umts_cell_id_from_str(struct umts_cell_id *ucid, const char *instr)
{
	int rc;
	char buf[4];
	const char *pos = instr;
	const char *end;

	/* We want to use struct umts_cell_id as hashtable key. If it ever happens to contain any padding bytes, make
	 * sure everything is deterministically zero. */
	memset(ucid, 0, sizeof(*ucid));

	/* read MCC */
	end = strchr(pos, '-');
	if (!end || end <= pos || (end - pos) >= sizeof(buf))
		return -EINVAL;
	osmo_strlcpy(buf, pos, end - pos + 1);
	if (osmo_mcc_from_str(buf, &ucid->plmn.mcc))
		return -EINVAL;
	pos = end + 1;

	/* read MNC -- here the number of leading zeros matters. */
	end = strchr(pos, '-');
	if (!end || end == pos || (end - pos) >= sizeof(buf))
		return -EINVAL;
	osmo_strlcpy(buf, pos, end - pos + 1);
	if (osmo_mnc_from_str(buf, &ucid->plmn.mnc, &ucid->plmn.mnc_3_digits))
		return -EINVAL;
	pos = end + 1;

	/* parse the rest, where leading zeros do not matter */
	rc = sscanf(pos, "L%" SCNu16 "-R%" SCNu8 "-S%" SCNu16 "-C%" SCNu32 "",
		    &ucid->lac, &ucid->rac, &ucid->sac, &ucid->cid);
	if (rc < 0)
		return -errno;

	if (rc != 4)
		return -EINVAL;

	if (ucid->lac == 0 || ucid->lac == 0xffff)
		return -EINVAL;

	/* CellIdentity in the ASN.1 syntax is a bit-string of 28 bits length */
	if (ucid->cid >= (1 << 28))
		return -EINVAL;

	return 0;
}
