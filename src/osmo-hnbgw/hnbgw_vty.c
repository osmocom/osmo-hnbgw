/* HNB-GW interface to quagga VTY */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <string.h>

#include <osmocom/core/socket.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/tdef_vty.h>

#include <osmocom/gsm/gsm23236.h>

#include <osmocom/hnbgw/vty.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/context_map.h>
#include <osmocom/hnbgw/tdefs.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/netif/stream.h>

#include <osmocom/mgcp_client/mgcp_client.h>

static struct cmd_node hnbgw_node = {
	HNBGW_NODE,
	"%s(config-hnbgw)# ",
	1,
};

DEFUN(cfg_hnbgw, cfg_hnbgw_cmd,
      "hnbgw", "Configure HNBGW options")
{
	vty->node = HNBGW_NODE;
	return CMD_SUCCESS;
}

static struct cmd_node iuh_node = {
	IUH_NODE,
	"%s(config-hnbgw-iuh)# ",
	1,
};

DEFUN(cfg_hnbgw_iuh, cfg_hnbgw_iuh_cmd,
      "iuh", "Configure Iuh options")
{
	vty->node = IUH_NODE;
	return CMD_SUCCESS;
}

static struct cmd_node iucs_node = {
	IUCS_NODE,
	"%s(config-hnbgw-iucs)# ",
	1,
};

DEFUN(cfg_hnbgw_iucs, cfg_hnbgw_iucs_cmd,
      "iucs", "Configure IuCS options")
{
	vty->node = IUCS_NODE;
	vty->index = &g_hnbgw->sccp.cnpool_iucs;
	return CMD_SUCCESS;
}

static struct cmd_node iups_node = {
	IUPS_NODE,
	"%s(config-hnbgw-iups)# ",
	1,
};

DEFUN(cfg_hnbgw_iups, cfg_hnbgw_iups_cmd,
      "iups", "Configure IuPS options")
{
	vty->node = IUPS_NODE;
	vty->index = &g_hnbgw->sccp.cnpool_iups;
	return CMD_SUCCESS;
}

static struct cmd_node mgcp_node = {
	MGCP_NODE,
	"%s(config-hnbgw-mgcp)# ",
	1,
};

DEFUN(cfg_hnbgw_mgcp, cfg_hnbgw_mgcp_cmd,
      "mgcp", "Configure MGCP client")
{
	vty->node = MGCP_NODE;
	return CMD_SUCCESS;
}

int hnbgw_vty_go_parent(struct vty *vty)
{
	osmo_ss7_vty_go_parent(vty);
	return vty->node;
}

static void _show_cnlink(struct vty *vty, struct hnbgw_cnlink *cnlink)
{
	struct osmo_ss7_route *rt;
	struct osmo_ss7_instance *ss7;

	if (!cnlink) {
		vty_out(vty, "NULL%s", VTY_NEWLINE);
		return;
	}

	if (!cnlink->hnbgw_sccp_inst) {
		vty_out(vty, "no SCCP instance%s", VTY_NEWLINE);
		return;
	}

	if (!cnlink->hnbgw_sccp_inst->sccp_user) {
		vty_out(vty, "no SCCP user%s", VTY_NEWLINE);
		return;
	}

	ss7 = osmo_sccp_get_ss7(cnlink->hnbgw_sccp_inst->sccp);
#define GUARD(STR) \
	STR ? STR : "", \
	STR ? ":" : ""

	vty_out(vty, "%s <->",
		osmo_sccp_user_name(cnlink->hnbgw_sccp_inst->sccp_user));
	vty_out(vty, " %s%s%s%s",
		GUARD(cnlink->use.remote_addr_name),
		osmo_sccp_inst_addr_name(cnlink->hnbgw_sccp_inst->sccp, &cnlink->remote_addr),
		VTY_NEWLINE);

	rt = osmo_ss7_route_lookup(ss7, cnlink->remote_addr.pc);
	vty_out(vty, "      SS7 route: %s%s", osmo_ss7_route_name(rt, true), VTY_NEWLINE);

#undef GUARD
}

DEFUN(show_cnlink, show_cnlink_cmd, "show cnlink",
      SHOW_STR "Display information on core network link\n")
{
	struct hnbgw_cnlink *cnlink;
	vty_out(vty, "IuCS: ");
	llist_for_each_entry(cnlink, &g_hnbgw->sccp.cnpool_iucs.cnlinks, entry)
		_show_cnlink(vty, cnlink);
	vty_out(vty, "IuPS: ");
	llist_for_each_entry(cnlink, &g_hnbgw->sccp.cnpool_iups.cnlinks, entry)
		_show_cnlink(vty, cnlink);
	return CMD_SUCCESS;
}

static void vty_out_ofd_addr(struct vty *vty, struct osmo_fd *ofd)
{
	char *name;
	if (!ofd || ofd->fd < 0
	|| !(name = osmo_sock_get_name(vty, ofd->fd))) {
	    vty_out(vty, "(no addr)");
	    return;
	}
	vty_out(vty, "%s", name);
	talloc_free(name);
}

static void vty_dump_hnb_info__map_states(struct vty *vty, const char *name, unsigned int count,
					  unsigned int state_count[])
{
	unsigned int i;
	if (!count)
		return;
	vty_out(vty, "    %s: %u contexts:", name, count);
	for (i = 0; i <= MAP_S_NUM_STATES; i++) {
		if (!state_count[i])
			continue;
		vty_out(vty, " %s:%u", hnbgw_context_map_state_name(i), state_count[i]);
	}
	vty_out(vty, VTY_NEWLINE);
}

static void vty_dump_hnb_info(struct vty *vty, struct hnb_context *hnb)
{
	struct hnbgw_context_map *map;
	unsigned int map_count[2] = {};
	unsigned int state_count[2][MAP_S_NUM_STATES + 1] = {};

	vty_out(vty, "HNB ");
	vty_out_ofd_addr(vty, hnb->conn? osmo_stream_srv_get_ofd(hnb->conn) : NULL);
	vty_out(vty, " \"%s\"%s", hnb->identity_info, VTY_NEWLINE);
	vty_out(vty, "    MCC %u MNC %u LAC %u RAC %u SAC %u CID %u SCTP-stream:HNBAP=%u,RUA=%u%s",
		hnb->id.mcc, hnb->id.mnc, hnb->id.lac, hnb->id.rac, hnb->id.sac, hnb->id.cid,
		hnb->hnbap_stream, hnb->rua_stream, VTY_NEWLINE);

	llist_for_each_entry(map, &hnb->map_list, hnb_list) {
		map_count[map->is_ps ? 1 : 0]++;
		state_count[map->is_ps ? 1 : 0][context_map_get_state(map)]++;
	}
	vty_dump_hnb_info__map_states(vty, "IuCS", map_count[0], state_count[0]);
	vty_dump_hnb_info__map_states(vty, "IuPS", map_count[1], state_count[1]);
}

static void vty_dump_ue_info(struct vty *vty, struct ue_context *ue)
{
	vty_out(vty, "UE IMSI \"%s\" context ID %u HNB %s%s", ue->imsi, ue->context_id,
		hnb_context_name(ue->hnb), VTY_NEWLINE);
}

#define SHOW_HNB_STR SHOW_STR "Display information about HNB\n"

DEFUN(show_hnb, show_hnb_cmd, "show hnb all",
      SHOW_HNB_STR "All HNB\n")
{
	struct hnb_context *hnb;
	unsigned int count = 0;

	if (llist_empty(&g_hnbgw->hnb_list)) {
		vty_out(vty, "No HNB connected%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(hnb, &g_hnbgw->hnb_list, list) {
		vty_dump_hnb_info(vty, hnb);
		count++;
	}

	vty_out(vty, "%u HNB connected%s", count, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(show_one_hnb, show_one_hnb_cmd, "show hnb NAME ",
      SHOW_HNB_STR "HNB name\n")
{
	struct hnb_context *hnb;
	const char *identity_info = argv[0];

	if (llist_empty(&g_hnbgw->hnb_list)) {
		vty_out(vty, "No HNB connected%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	hnb = hnb_context_by_identity_info(identity_info);
	if (hnb == NULL) {
		vty_out(vty, "No HNB found with identity '%s'%s", identity_info, VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	vty_dump_hnb_info(vty, hnb);
	return CMD_SUCCESS;
}

DEFUN(show_ue, show_ue_cmd, "show ue all",
      SHOW_STR "Display HNBAP information about UE\n" "All UE\n")
{
	struct ue_context *ue;

	llist_for_each_entry(ue, &g_hnbgw->ue_list, list) {
		vty_dump_ue_info(vty, ue);
	}

	return CMD_SUCCESS;
}

DEFUN(show_talloc, show_talloc_cmd, "show talloc", SHOW_STR "Display talloc info")
{
	talloc_report_full(g_hnbgw, stderr);

	return CMD_SUCCESS;
}

DEFUN(cfg_hnbgw_plmn, cfg_hnbgw_plmn_cmd,
      "plmn <1-999> <0-999>",
      "Configure the HNBGW's PLMN. The PLMN is transmitted in RANAP RESET towards the CN.\n"
      "MCC, Mobile Country Code\n"
      "MNC, Mobile Network Code\n")
{
	struct osmo_plmn_id plmn;

	if (osmo_mcc_from_str(argv[0], &plmn.mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_mnc_from_str(argv[1], &plmn.mnc, &plmn.mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hnbgw->config.plmn = plmn;
	return CMD_SUCCESS;
}

DEFUN(cfg_hnbgw_rnc_id, cfg_hnbgw_rnc_id_cmd,
      "rnc-id <0-65535>",
      "Configure the HNBGW's RNC Id, the common RNC Id used for all connected hNodeB. It is sent to"
      " each hNodeB upon HNBAP HNB-Register-Accept, and the hNodeB will subsequently send this as"
      " RANAP InitialUE Messages' GlobalRNC-ID IE. Takes effect as soon as the hNodeB re-registers.\n"
      "RNC Id value\n")
{
	g_hnbgw->config.rnc_id = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hnbgw_iuh_local_ip, cfg_hnbgw_iuh_local_ip_cmd, "local-ip A.B.C.D",
      "Accept Iuh connections on local interface\n"
      "Local interface IP address (default: " HNBGW_LOCAL_IP_DEFAULT ")")
{
	talloc_free((void *)g_hnbgw->config.iuh_local_ip);
	g_hnbgw->config.iuh_local_ip = talloc_strdup(g_hnbgw, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hnbgw_iuh_local_port, cfg_hnbgw_iuh_local_port_cmd, "local-port <1-65535>",
      "Accept Iuh connections on local port\n"
      "Local interface port (default: 29169)")
{
	g_hnbgw->config.iuh_local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hnbgw_iuh_hnbap_allow_tmsi, cfg_hnbgw_iuh_hnbap_allow_tmsi_cmd,
      "hnbap-allow-tmsi (0|1)",
      "Allow HNBAP UE Register messages with TMSI or PTMSI identity\n"
      "Only accept IMSI identity, reject TMSI or PTMSI\n"
      "Accept IMSI, TMSI or PTMSI as UE identity\n")
{
	g_hnbgw->config.hnbap_allow_tmsi = (*argv[0] == '1');
	return CMD_SUCCESS;
}

DEFUN(cfg_hnbgw_log_prefix, cfg_hnbgw_log_prefix_cmd,
      "log-prefix (hnb-id|umts-cell-id)",
      "Configure the log message prefix\n"
      "Use the hNB-ID as log message prefix\n"
      "Use the UMTS Cell ID as log message prefix\n")
{
	if (!strcmp(argv[0], "hnb-id"))
		g_hnbgw->config.log_prefix_hnb_id = true;
	else
		g_hnbgw->config.log_prefix_hnb_id = false;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_hnbgw_max_sccp_cr_payload_len, cfg_hnbgw_max_sccp_cr_payload_len_cmd,
      "sccp cr max-payload-len <0-999999>",
      "Configure SCCP behavior\n"
      "Configure SCCP Connection Request\n"
      "DEPRECATED: The maximum SCCP CR PDU length of 130 is now enforced in libosmo-sccp v1.7.0. This config item no"
      " longer has any effect.\n"
      "ignored\n")
{
	vty_out(vty, "%% deprecated, ignored: remove this from your config file: 'sccp cr max-payload-len N'%s",
		VTY_NEWLINE);
	/* Still return success to not break osmo-hnbgw startup for users with old config files. */
	return CMD_SUCCESS;
}

#define NRI_STR "Mapping of Network Resource Indicators to this CN peer, for CN pooling\n"
#define NULL_NRI_STR "Define NULL-NRI values that cause re-assignment of an MS to a different CN peer, for CN pooling.\n"
#define NRI_FIRST_LAST_STR "First value of the NRI value range, should not surpass the configured 'nri bitlen'.\n" \
       "Last value of the NRI value range, should not surpass the configured 'nri bitlen' and be larger than the" \
       " first value; if omitted, apply only the first value.\n"
#define NRI_ARGS_TO_STR_FMT "%s%s%s"
#define NRI_ARGS_TO_STR_ARGS(ARGC, ARGV) ARGV[0], (ARGC>1)? ".." : "", (ARGC>1)? ARGV[1] : ""

#define NRI_WARN(CNLINK, FORMAT, args...) do { \
		vty_out(vty, "%% Warning: %s %d: " FORMAT "%s", CNLINK->pool->peer_name, CNLINK->nr, ##args, \
			VTY_NEWLINE); \
		LOGP(DCN, LOGL_ERROR, "%s %d: " FORMAT "\n", CNLINK->pool->peer_name, CNLINK->nr, ##args); \
	} while (0)


/* hnbgw/iucs/nri ... AND hnbgw/iups/nri ... */
DEFUN(cfg_hnbgw_cnpool_nri_bitlen,
      cfg_hnbgw_cnpool_nri_bitlen_cmd,
      "nri bitlen <1-15>",
      NRI_STR
      "Set number of bits that an NRI has, to extract from TMSI identities (always starting just after the TMSI's most significant octet).\n"
      "bit count (default: " OSMO_STRINGIFY_VAL(OSMO_NRI_BITLEN_DEFAULT) ")\n")
{
	struct hnbgw_cnpool *cnpool = vty->index;
	cnpool->vty.nri_bitlen = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* hnbgw/iucs/nri ... AND hnbgw/iups/nri ... */
DEFUN(cfg_hnbgw_cnpool_nri_null_add, cfg_hnbgw_cnpool_nri_null_add_cmd,
      "nri null add <0-32767> [<0-32767>]",
      NRI_STR NULL_NRI_STR "Add NULL-NRI value (or range)\n"
      NRI_FIRST_LAST_STR)
{
	int rc;
	const char *message;
	struct hnbgw_cnpool *cnpool = vty->index;
	rc = osmo_nri_ranges_vty_add(&message, NULL, cnpool->vty.null_nri_ranges, argc, argv, cnpool->vty.nri_bitlen);
	if (message)
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

/* hnbgw/iucs/nri ... AND hnbgw/iups/nri ... */
DEFUN(cfg_hnbgw_cnpool_nri_null_del, cfg_hnbgw_cnpool_nri_null_del_cmd,
      "nri null del <0-32767> [<0-32767>]",
      NRI_STR NULL_NRI_STR "Remove NRI value or range from the NRI mapping for this CN link\n"
      NRI_FIRST_LAST_STR)
{
	int rc;
	const char *message;
	struct hnbgw_cnpool *cnpool = vty->index;
	rc = osmo_nri_ranges_vty_del(&message, NULL, cnpool->vty.null_nri_ranges, argc, argv);
	if (message)
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT "%s", message, NRI_ARGS_TO_STR_ARGS(argc, argv),
			VTY_NEWLINE);
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

/* Legacy from when there was only one IuCS and one IuPS peer. Instead, there are now 'msc 123' / 'sgsn 123' sub nodes.
 * To yield legacy behavior, set the first cnlink config in this pool ('msc 0' / 'sgsn 0'). */
DEFUN_DEPRECATED(cfg_hnbgw_cnpool_remote_addr,
		 cfg_hnbgw_cnpool_remote_addr_cmd,
		 "remote-addr NAME",
		 "Deprecated command: same as '{msc,sgsn} 0' / 'remote-addr NAME'\n-\n")
{
	const char *logmsg;
	struct hnbgw_cnpool *cnpool = vty->index;
	struct hnbgw_cnlink *cnlink = cnlink_get_nr(cnpool, 0, true);
	OSMO_ASSERT(cnlink);
	cnlink->vty.remote_addr_name = talloc_strdup(cnlink, argv[0]);

	logmsg = talloc_asprintf(OTC_SELECT,
				 "Deprecated: instead of hnbgw/%s/remote-addr,"
				 " use '%s 0'/remote-addr",
				 cnpool->pool_name,
				 cnpool->peer_name);
	vty_out(vty, "%% %s%s", logmsg, VTY_NEWLINE);
	LOGP(DLGLOBAL, LOGL_ERROR, "config: %s\n", logmsg);
	return CMD_SUCCESS;
}

#define CNLINK_NR_RANGE "<0-1000>"

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

static struct cmd_node sgsn_node = {
	SGSN_NODE,
	"%s(config-sgsn)# ",
	1,
};

/* Commands that are common for 'msc 0' and 'sgsn 0' */

static int cnlink_nr(struct vty *vty, struct hnbgw_cnpool *cnpool, int argc, const char **argv)
{
	int nr = atoi(argv[0]);
	struct hnbgw_cnlink *cnlink = cnlink_get_nr(cnpool, nr, true);
	OSMO_ASSERT(cnlink);
	switch (cnpool->domain) {
	case DOMAIN_CS:
		vty->node = MSC_NODE;
		break;
	case DOMAIN_PS:
		vty->node = SGSN_NODE;
		break;
	default:
		OSMO_ASSERT(false);
	}
	vty->index = cnlink;
	return CMD_SUCCESS;
}

/* 'msc 0' */
DEFUN(cfg_msc_nr, cfg_msc_nr_cmd,
      "msc " CNLINK_NR_RANGE,
      "Configure an IuCS link to an MSC\n"
      "MSC nr\n")
{
	return cnlink_nr(vty, &g_hnbgw->sccp.cnpool_iucs, argc, argv);
}

/* 'sgsn 0' */
DEFUN(cfg_sgsn_nr, cfg_sgsn_nr_cmd,
      "sgsn " CNLINK_NR_RANGE,
      "Configure an IuPS link to an SGSN\n"
      "SGSN nr\n")
{
	return cnlink_nr(vty, &g_hnbgw->sccp.cnpool_iups, argc, argv);
}

/* 'msc 0'  / 'remote-addr my-msc'  and
 * 'sgsn 0' / 'remote-addr my-sgsn'
 */
DEFUN(cfg_cnlink_remote_addr,
      cfg_cnlink_remote_addr_cmd,
      "remote-addr NAME",
      "SCCP address to send RANAP/SCCP to\n"
      "SCCP address book entry name (see 'cs7 instance' / 'sccp-address')\n")
{
	struct hnbgw_cnlink *cnlink = vty->index;
	cnlink->vty.remote_addr_name = talloc_strdup(cnlink, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_cnlink_nri_add, cfg_cnlink_nri_add_cmd,
	   "nri add <0-32767> [<0-32767>]",
	   NRI_STR "Add NRI value or range to the NRI mapping for this CN link\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	struct hnbgw_cnlink *other_cnlink;
	bool before;
	int rc;
	const char *message;
	struct osmo_nri_range added_range;

	rc = osmo_nri_ranges_vty_add(&message, &added_range, cnlink->vty.nri_ranges, argc, argv, cnlink->pool->vty.nri_bitlen);
	if (message) {
		NRI_WARN(cnlink, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;

	/* Issue a warning about NRI range overlaps (but still allow them).
	 * Overlapping ranges will map to whichever CN link comes fist in the llist,
	 * which is not necessarily in the order of increasing cnlink->nr. */
	before = true;
	llist_for_each_entry(other_cnlink, &cnlink->pool->cnlinks, entry) {
		if (other_cnlink == cnlink) {
			before = false;
			continue;
		}
		if (osmo_nri_range_overlaps_ranges(&added_range, other_cnlink->vty.nri_ranges)) {
			NRI_WARN(cnlink, "NRI range [%d..%d] overlaps between %s %d and %s %d."
				 " For overlaps, %s %d has higher priority than %s %d",
				 added_range.first, added_range.last, cnlink->pool->peer_name, cnlink->nr,
				 other_cnlink->pool->peer_name, other_cnlink->nr,
				 (before ? other_cnlink : cnlink)->pool->peer_name,
				 (before ? other_cnlink : cnlink)->nr,
				 (before ? cnlink : other_cnlink)->pool->peer_name,
				 (before ? cnlink : other_cnlink)->nr);
		}
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_cnlink_nri_del, cfg_cnlink_nri_del_cmd,
	   "nri del <0-32767> [<0-32767>]",
	   NRI_STR "Remove NRI value or range from the NRI mapping for this CN link\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	int rc;
	const char *message;

	rc = osmo_nri_ranges_vty_del(&message, NULL, cnlink->vty.nri_ranges, argc, argv);
	if (message) {
		NRI_WARN(cnlink, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_cnlink_allow_attach, cfg_cnlink_allow_attach_cmd,
	   "allow-attach",
	   "Allow this CN link to attach new subscribers (default).\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	cnlink->allow_attach = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_cnlink_no_allow_attach, cfg_cnlink_no_allow_attach_cmd,
	   "no allow-attach",
	   NO_STR
	   "Do not assign new subscribers to this CN link."
	   " Useful if an CN link in an CN link pool is configured to off-load subscribers."
	   " The CN link will still be operational for already IMSI-Attached subscribers,"
	   " but the NAS node selection function will skip this CN link for new subscribers\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	cnlink->allow_attach = false;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_cnlink_allow_emerg,
	   cfg_cnlink_allow_emerg_cmd,
	   "allow-emergency",
	   "Allow CM ServiceRequests with type emergency on this CN link\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	cnlink->allow_emerg = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_cnlink_no_allow_emerg,
	   cfg_cnlink_no_allow_emerg_cmd,
	   "no allow-emergency",
	   NO_STR
	   "Do not serve CM ServiceRequests with type emergency on this CN link\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	cnlink->allow_emerg = false;
	return CMD_SUCCESS;
}

static void cnlink_write_nri(struct vty *vty, struct hnbgw_cnlink *cnlink, bool verbose)
{
	struct osmo_nri_range *r;

	if (verbose) {
		vty_out(vty, "%s %d%s", cnlink->pool->peer_name, cnlink->nr, VTY_NEWLINE);
		if (llist_empty(&cnlink->vty.nri_ranges->entries)) {
			vty_out(vty, " %% no NRI mappings%s", VTY_NEWLINE);
			return;
		}
	}

	llist_for_each_entry(r, &cnlink->vty.nri_ranges->entries, entry) {
		if (osmo_nri_range_validate(r, 255))
			vty_out(vty, " %% INVALID RANGE:");
		vty_out(vty, " nri add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (!cnlink->allow_attach)
		vty_out(vty, " no allow-attach%s", VTY_NEWLINE);
	if (cnlink->allow_emerg)
		vty_out(vty, " allow-emergency%s", VTY_NEWLINE);
}

DEFUN(cfg_cnlink_show_nri, cfg_cnlink_show_nri_cmd,
      "show nri",
      SHOW_STR NRI_STR)
{
	struct hnbgw_cnlink *cnlink = vty->index;
	cnlink_write_nri(vty, cnlink, true);
	return CMD_SUCCESS;
}

void cnlinks_write_nri(struct vty *vty, struct hnbgw_cnpool *cnpool, bool verbose)
{
	struct hnbgw_cnlink *cnlink;
	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry)
		cnlink_write_nri(vty, cnlink, verbose);
}

void cnpool_write_nri(struct vty *vty, struct hnbgw_cnpool *cnpool, bool verbose)
{
	struct osmo_nri_range *r;

	if (verbose)
		vty_out(vty, " %s%s", cnpool->pool_name, VTY_NEWLINE);

	if (verbose || cnpool->vty.nri_bitlen != OSMO_NRI_BITLEN_DEFAULT)
		vty_out(vty, "  nri bitlen %u%s", cnpool->vty.nri_bitlen, VTY_NEWLINE);

	llist_for_each_entry(r, &cnpool->vty.null_nri_ranges->entries, entry) {
		vty_out(vty, "  nri null add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (verbose && llist_empty(&cnpool->vty.null_nri_ranges->entries))
		vty_out(vty, "  %% No NULL-NRI entries%s", VTY_NEWLINE);
}

DEFUN(show_nri, show_nri_cmd,
      "show nri",
      SHOW_STR NRI_STR)
{
	/* hnbgw
	 *  iucs
	 *   nri null add ...
	 */
	vty_out(vty, "hnbgw%s", VTY_NEWLINE);
	cnpool_write_nri(vty, &g_hnbgw->sccp.cnpool_iucs, true);
	cnpool_write_nri(vty, &g_hnbgw->sccp.cnpool_iups, true);

	/* msc 0
	 *   nri add ...
	 */
	cnlinks_write_nri(vty, &g_hnbgw->sccp.cnpool_iucs, true);
	cnlinks_write_nri(vty, &g_hnbgw->sccp.cnpool_iups, true);
	return CMD_SUCCESS;
}

/* Hidden since it exists only for use by ttcn3 tests */
DEFUN_HIDDEN(cnpool_roundrobin_next, cnpool_roundrobin_next_cmd,
	     "cnpool roundrobin next (msc|sgsn) " CNLINK_NR_RANGE,
	     "CN pooling: load balancing across multiple CN links.\n"
	     "Adjust current state of the CN link round-robin algorithm (for testing).\n"
	     "Set the CN link nr to direct the next new subscriber to (for testing).\n"
	     "Set next MSC or next SGSN number\n"
	     "CN link number, as in the config file; if the number does not exist,"
	     " the round-robin continues to the next valid number.\n")
{
	struct hnbgw_cnpool *cnpool;
	if (!strcmp("msc", argv[0]))
		cnpool = &g_hnbgw->sccp.cnpool_iucs;
	else
		cnpool = &g_hnbgw->sccp.cnpool_iups;
	cnpool->round_robin_next_nr = atoi(argv[1]);
	return CMD_SUCCESS;
}

DEFUN(cnlink_ranap_reset, cnlink_ranap_reset_cmd,
      "(msc|sgsn) " CNLINK_NR_RANGE " ranap reset",
      "Manipulate an IuCS link to an MSC\n"
      "Manipulate an IuPS link to an SGSN\n"
      "MSC/SGSN nr\n"
      "Manipulate RANAP layer of Iu-interface\n"
      "Flip this CN link to disconnected state and re-send RANAP RESET\n")
{
	struct hnbgw_cnpool *cnpool;
	struct hnbgw_cnlink *cnlink;
	const char *msc_sgsn = argv[0];
	int nr = atoi(argv[1]);

	if (!strcmp("msc", msc_sgsn))
		cnpool = &g_hnbgw->sccp.cnpool_iucs;
	else
		cnpool = &g_hnbgw->sccp.cnpool_iups;

	cnlink = cnlink_get_nr(cnpool, nr, false);
	if (!cnlink) {
		vty_out(vty, "%% No such %s: nr %d\n", msc_sgsn, nr);
		return CMD_WARNING;
	}

	LOG_CNLINK(cnlink, DCN, LOGL_NOTICE, "VTY requests BSSMAP RESET\n");
	cnlink_resend_reset(cnlink);
	return CMD_SUCCESS;
}

#define APPLY_STR "Immediately use configuration modified via telnet VTY, and restart components as needed.\n"
#define SCCP_RESTART_STR \
      " If 'remote-addr' changed, related SCCP links will be restarted, possibly dropping active UE contexts."
#define IMPLICIT_ON_STARTUP_STR \
      " This is run implicitly on program startup, only needed to apply changes made later via telnet VTY."

DEFUN(cfg_cnlink_apply_sccp, cfg_cnlink_apply_sccp_cmd,
      "apply sccp",
      APPLY_STR
      "For telnet VTY: apply SCCP and NRI config changes made to this CN link in the running osmo-hnbgw process."
      SCCP_RESTART_STR IMPLICIT_ON_STARTUP_STR "\n")
{
	struct hnbgw_cnlink *cnlink = vty->index;
	hnbgw_cnlink_start_or_restart(cnlink);
	return CMD_SUCCESS;
}

DEFUN(cfg_cnpool_apply_nri, cfg_cnpool_apply_nri_cmd,
      "apply nri",
      APPLY_STR
      "For telnet VTY: apply NRI config changes made to this CN pool in the running osmo-hnbgw process."
      IMPLICIT_ON_STARTUP_STR "\n")
{
	struct hnbgw_cnpool *cnpool = vty->index;
	hnbgw_cnpool_apply_cfg(cnpool);
	return CMD_SUCCESS;
}

DEFUN(cfg_config_apply_sccp, cfg_config_apply_sccp_cmd,
      "apply sccp",
      APPLY_STR
      "For telnet VTY: apply all SCCP and NRI config changes made to any CN pools and CN links in the running"
      " osmo-hnbgw process."
      SCCP_RESTART_STR IMPLICIT_ON_STARTUP_STR "\n")
{
	struct hnbgw_cnpool *cnpool;

	cnpool = &g_hnbgw->sccp.cnpool_iucs;
	hnbgw_cnpool_apply_cfg(cnpool);
	hnbgw_cnpool_cnlinks_start_or_restart(cnpool);

	cnpool = &g_hnbgw->sccp.cnpool_iups;
	hnbgw_cnpool_apply_cfg(cnpool);
	hnbgw_cnpool_cnlinks_start_or_restart(cnpool);

	return CMD_SUCCESS;
}

#if ENABLE_PFCP

static struct cmd_node pfcp_node = {
	PFCP_NODE,
	"%s(config-hnbgw-pfcp)# ",
	1,
};

DEFUN(cfg_hnbgw_pfcp, cfg_hnbgw_pfcp_cmd,
      "pfcp", "Configure PFCP for GTP tunnel mapping")
{
	vty->node = PFCP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_pfcp_remote_addr, cfg_pfcp_remote_addr_cmd,
      "remote-addr IP_ADDR",
      "Remote UPF's listen IP address; where to send PFCP requests\n"
      "IP address\n")
{
	osmo_talloc_replace_string(g_hnbgw, &g_hnbgw->config.pfcp.remote_addr, argv[0]);
	LOGP(DLPFCP, LOGL_NOTICE, "%p cfg: pfcp remote-addr %s\n", g_hnbgw, g_hnbgw->config.pfcp.remote_addr);
	return CMD_SUCCESS;
}

DEFUN(cfg_pfcp_local_addr, cfg_pfcp_local_addr_cmd,
      "local-addr IP_ADDR",
      "Local address for PFCP\n"
      "IP address\n")
{
	osmo_talloc_replace_string(g_hnbgw, &g_hnbgw->config.pfcp.local_addr, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_pfcp_local_port, cfg_pfcp_local_port_cmd,
      "local-port <1-65535>",
      "Local port for PFCP\n"
      "IP port\n")
{
	g_hnbgw->config.pfcp.local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

#endif /* ENABLE_PFCP */

DEFUN_DEPRECATED(cfg_hnbgw_timer_ps, cfg_hnbgw_timer_ps_cmd,
		 "timer ps " OSMO_TDEF_VTY_ARG_SET,
		 "Configure or show timers\n"
		 "Deprecated: 'ps' timers are now in 'hnbgw'\n"
		 OSMO_TDEF_VTY_DOC_SET)
{
	return osmo_tdef_vty_set_cmd(vty, hnbgw_T_defs, argv);
}

/* hnbgw
 *  iucs  } this part
 *   foo  }
 */
static void _config_write_cnpool(struct vty *vty, struct hnbgw_cnpool *cnpool)
{
	if (cnpool->vty.nri_bitlen == OSMO_NRI_BITLEN_DEFAULT
	    && llist_empty(&cnpool->vty.null_nri_ranges->entries))
		return;

	vty_out(vty, " %s%s", cnpool->pool_name, VTY_NEWLINE);

	cnpool_write_nri(vty, cnpool, false);
}

static int config_write_hnbgw(struct vty *vty)
{
	vty_out(vty, "hnbgw%s", VTY_NEWLINE);
	vty_out(vty, " log-prefix %s%s", g_hnbgw->config.log_prefix_hnb_id ? "hnb-id" : "umts-cell-id",
		VTY_NEWLINE);
	osmo_tdef_vty_groups_write(vty, " ");

	_config_write_cnpool(vty, &g_hnbgw->sccp.cnpool_iucs);
	_config_write_cnpool(vty, &g_hnbgw->sccp.cnpool_iups);

	return CMD_SUCCESS;
}

static int config_write_hnbgw_iuh(struct vty *vty)
{
	const char *addr;
	uint16_t port;

	vty_out(vty, " iuh%s", VTY_NEWLINE);

	addr = g_hnbgw->config.iuh_local_ip;
	if (addr && (strcmp(addr, HNBGW_LOCAL_IP_DEFAULT) != 0))
		vty_out(vty, "  local-ip %s%s", addr, VTY_NEWLINE);

	port = g_hnbgw->config.iuh_local_port;
	if (port && port != IUH_DEFAULT_SCTP_PORT)
		vty_out(vty, "  local-port %u%s", port, VTY_NEWLINE);

	if (g_hnbgw->config.hnbap_allow_tmsi)
		vty_out(vty, "  hnbap-allow-tmsi 1%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* hnbgw
 * msc 0   } this part
 * sgsn 0  }
 */
static void _config_write_cnlink(struct vty *vty, struct hnbgw_cnpool *cnpool)
{
	struct hnbgw_cnlink *cnlink;

	llist_for_each_entry(cnlink, &cnpool->cnlinks, entry)
	{
		vty_out(vty, "%s %d%s", cnpool->peer_name, cnlink->nr, VTY_NEWLINE);
		if (cnlink->vty.remote_addr_name)
			vty_out(vty, " remote-addr %s%s", cnlink->vty.remote_addr_name, VTY_NEWLINE);
		cnlink_write_nri(vty, cnlink, false);
	}
}

static int config_write_msc(struct vty *vty)
{
	_config_write_cnlink(vty, &g_hnbgw->sccp.cnpool_iucs);
	return CMD_SUCCESS;
}

static int config_write_sgsn(struct vty *vty)
{
	_config_write_cnlink(vty, &g_hnbgw->sccp.cnpool_iups);
	return CMD_SUCCESS;
}

#if ENABLE_PFCP
static int config_write_hnbgw_pfcp(struct vty *vty)
{
	vty_out(vty, " pfcp%s", VTY_NEWLINE);
	if (g_hnbgw->config.pfcp.local_addr)
		vty_out(vty, "  local-addr %s%s", g_hnbgw->config.pfcp.local_addr, VTY_NEWLINE);
	if (g_hnbgw->config.pfcp.remote_addr)
		vty_out(vty, "  remote-addr %s%s", g_hnbgw->config.pfcp.remote_addr, VTY_NEWLINE);

	return CMD_SUCCESS;
}
#endif

static void install_cnlink_elements(int node)
{
	install_element(node, &cfg_cnlink_remote_addr_cmd);
	install_element(node, &cfg_cnlink_nri_add_cmd);
	install_element(node, &cfg_cnlink_nri_del_cmd);
	install_element(node, &cfg_cnlink_show_nri_cmd);
	install_element(node, &cfg_cnlink_apply_sccp_cmd);
	install_element(node, &cfg_cnlink_allow_attach_cmd);
	install_element(node, &cfg_cnlink_no_allow_attach_cmd);
	install_element(node, &cfg_cnlink_allow_emerg_cmd);
	install_element(node, &cfg_cnlink_no_allow_emerg_cmd);
}

void hnbgw_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_hnbgw_cmd);
	install_node(&hnbgw_node, config_write_hnbgw);

	install_element(HNBGW_NODE, &cfg_hnbgw_plmn_cmd);
	install_element(HNBGW_NODE, &cfg_hnbgw_rnc_id_cmd);
	install_element(HNBGW_NODE, &cfg_hnbgw_log_prefix_cmd);
	install_element(HNBGW_NODE, &cfg_hnbgw_max_sccp_cr_payload_len_cmd);

	install_element(HNBGW_NODE, &cfg_hnbgw_iuh_cmd);
	install_node(&iuh_node, config_write_hnbgw_iuh);

	install_element(IUH_NODE, &cfg_hnbgw_iuh_local_ip_cmd);
	install_element(IUH_NODE, &cfg_hnbgw_iuh_local_port_cmd);
	install_element(IUH_NODE, &cfg_hnbgw_iuh_hnbap_allow_tmsi_cmd);

	install_element(HNBGW_NODE, &cfg_hnbgw_iucs_cmd);
	install_node(&iucs_node, NULL);
	install_element(IUCS_NODE, &cfg_hnbgw_cnpool_nri_bitlen_cmd);
	install_element(IUCS_NODE, &cfg_hnbgw_cnpool_nri_null_add_cmd);
	install_element(IUCS_NODE, &cfg_hnbgw_cnpool_nri_null_del_cmd);

	install_element(HNBGW_NODE, &cfg_hnbgw_iups_cmd);
	install_node(&iups_node, NULL);
	install_element(IUPS_NODE, &cfg_hnbgw_cnpool_nri_bitlen_cmd);
	install_element(IUPS_NODE, &cfg_hnbgw_cnpool_nri_null_add_cmd);
	install_element(IUPS_NODE, &cfg_hnbgw_cnpool_nri_null_del_cmd);

	/* deprecated: 'remote-addr' outside of 'msc 123' redirects to 'msc 0' / same for 'sgsn' */
	install_element(IUCS_NODE, &cfg_hnbgw_cnpool_remote_addr_cmd);
	install_element(IUPS_NODE, &cfg_hnbgw_cnpool_remote_addr_cmd);

	install_element_ve(&show_cnlink_cmd);
	install_element_ve(&show_hnb_cmd);
	install_element_ve(&show_one_hnb_cmd);
	install_element_ve(&show_ue_cmd);
	install_element_ve(&show_talloc_cmd);

	install_element(HNBGW_NODE, &cfg_hnbgw_mgcp_cmd);
	/* Deprecated: Old MGCP config without pooling support in MSC node: */
	install_node(&mgcp_node, NULL);
	mgcp_client_vty_init(g_hnbgw, MGCP_NODE, g_hnbgw->config.mgcp_client);

	mgcp_client_pool_vty_init(HNBGW_NODE, MGW_NODE, " ", g_hnbgw->mgw_pool);

#if ENABLE_PFCP
	install_node(&pfcp_node, config_write_hnbgw_pfcp);
	install_element(HNBGW_NODE, &cfg_hnbgw_pfcp_cmd);
	install_element(PFCP_NODE, &cfg_pfcp_local_addr_cmd);
	install_element(PFCP_NODE, &cfg_pfcp_local_port_cmd);
	install_element(PFCP_NODE, &cfg_pfcp_remote_addr_cmd);
#endif

	osmo_tdef_vty_groups_init(HNBGW_NODE, hnbgw_tdef_group);
	install_element(HNBGW_NODE, &cfg_hnbgw_timer_ps_cmd);

	install_element(CONFIG_NODE, &cfg_msc_nr_cmd);
	install_node(&msc_node, config_write_msc);
	install_cnlink_elements(MSC_NODE);

	install_element(CONFIG_NODE, &cfg_sgsn_nr_cmd);
	install_node(&sgsn_node, config_write_sgsn);
	install_cnlink_elements(SGSN_NODE);

	/* global 'apply' commands. There are two more on MSC_NODE and SGSN_NODE from install_cnlink_elements(). */
	install_element(CONFIG_NODE, &cfg_config_apply_sccp_cmd);
	install_element(IUCS_NODE, &cfg_cnpool_apply_nri_cmd);
	install_element(IUPS_NODE, &cfg_cnpool_apply_nri_cmd);

	install_element_ve(&show_nri_cmd);
	install_element(ENABLE_NODE, &cnpool_roundrobin_next_cmd);
	install_element(ENABLE_NODE, &cnlink_ranap_reset_cmd);
}
