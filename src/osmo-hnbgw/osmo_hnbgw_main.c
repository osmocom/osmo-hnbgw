/* OsmoHNBGW main routine */

/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016-2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <getopt.h>

#include "config.h"

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>

#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/ports.h>

#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/protocol/m3ua.h>

#include <osmocom/ranap/ranap_common.h>

#include <osmocom/hnbgw/hnbgw.h>
#include <osmocom/hnbgw/hnbgw_cn.h>
#include <osmocom/hnbgw/hnbgw_pfcp.h>

static const char * const osmo_hnbgw_copyright =
	"OsmoHNBGW - Osmocom Home Node B Gateway implementation\r\n"
	"Copyright (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n"
	"Contributions by Daniel Willmann, Harald Welte, Neels Hofmeyr\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static const struct log_info_cat log_cat[] = {
	[DMAIN] = {
		.name = "DMAIN", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "Main program",
	},
	[DHNBAP] = {
		.name = "DHNBAP", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "Home Node B Application Part",
	},
	[DRUA] = {
		.name = "DRUA", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "RANAP User Adaptation",
	},
	[DRANAP] = {
		.name = "DRANAP", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "",
		.description = "RAN Application Part",
	},
	[DMGW] = {
		.name = "DMGW", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = "\033[1;33m",
		.description = "Media Gateway",
	},
	[DHNB] = {
		.name = "DHNB", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_CYAN,
		.description = "HNB side (via RUA)",
	},
	[DCN] = {
		.name = "DCN", .loglevel = LOGL_NOTICE, .enabled = 1,
		.color = OSMO_LOGCOLOR_DARKYELLOW,
		.description = "Core Network side (via SCCP)",
	},
};

static const struct log_info hnbgw_log_info = {
	.cat = log_cat,
	.num_cat = ARRAY_SIZE(log_cat),
};

static struct vty_app_info vty_info = {
	.name		= "OsmoHNBGW",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= hnbgw_vty_go_parent,
};

static struct {
	int daemonize;
	const char *config_file;
	bool log_disable_color;
	bool log_enable_timestamp;
	int log_level;
	const char *log_category_mask;
} hnbgw_cmdline_config = {
	0,
	"osmo-hnbgw.cfg",
	false,
	false,
	0,
	NULL,
};

static void print_usage()
{
	printf("Usage: osmo-hnbgw\n");
}

static void print_help()
{
	printf("  -h --help                  This text.\n");
	printf("  -d option --debug=DHNBAP:DRUA:DRANAP:DMAIN  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -V --version               Print the version of OsmoHNBGW.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");

	printf("\nVTY reference generation:\n");
	printf("     --vty-ref-mode MODE        VTY reference generation mode (e.g. 'expert').\n");
	printf("     --vty-ref-xml              Generate the VTY reference XML output and exit.\n");
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static int long_option = 0;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"version", 0, 0, 'V' },
			{"log-level", 1, 0, 'e'},
			{"vty-ref-mode", 1, &long_option, 1},
			{"vty-ref-xml", 0, &long_option, 2},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dc:sTVe:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			handle_long_options(argv[0], long_option);
			break;
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			hnbgw_cmdline_config.log_disable_color = true;
			break;
		case 'd':
			hnbgw_cmdline_config.log_category_mask = optarg;
			break;
		case 'D':
			hnbgw_cmdline_config.daemonize = 1;
			break;
		case 'c':
			hnbgw_cmdline_config.config_file = optarg;
			break;
		case 'T':
			hnbgw_cmdline_config.log_enable_timestamp = true;
			break;
		case 'e':
			hnbgw_cmdline_config.log_level = atoi(optarg);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

int main(int argc, char **argv)
{
	struct osmo_stream_srv_link *srv;
	int rc;

	talloc_enable_null_tracking();

	/* g_hnbgw serves as the root talloc ctx, so allocate with NULL parent */
	g_hnbgw_alloc(NULL);
	g_hnbgw->config.rnc_id = 23;

	talloc_asn1_ctx = talloc_named_const(g_hnbgw, 1, "asn1_context");
	msgb_talloc_ctx_init(g_hnbgw, 0);

	rc = osmo_init_logging2(g_hnbgw, &hnbgw_log_info);
	if (rc < 0)
		exit(1);

	osmo_fsm_log_timeouts(true);

	rc = osmo_ss7_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "osmo_ss7_init() failed with rc=%d\n", rc);
		exit(1);
	}

	vty_info.tall_ctx = g_hnbgw;
	vty_info.copyright = osmo_hnbgw_copyright;
	vty_init(&vty_info);

	osmo_ss7_vty_init_asp(g_hnbgw);
	osmo_sccp_vty_init();
	hnbgw_vty_init();
	ctrl_vty_init(g_hnbgw);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	/* Handle options after vty_init(), for --version */
	handle_options(argc, argv);

	rc = vty_read_config_file(hnbgw_cmdline_config.config_file, NULL);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Failed to parse the config file: '%s'\n",
		     hnbgw_cmdline_config.config_file);
		return 1;
	}

	/*
	 * cmdline options take precedence over config file, but if no options
	 * were passed we must not override the config file.
	 */
	if (hnbgw_cmdline_config.log_disable_color)
		log_set_use_color(osmo_stderr_target, 0);
	if (hnbgw_cmdline_config.log_category_mask)
		log_parse_category_mask(osmo_stderr_target,
					hnbgw_cmdline_config.log_category_mask);
	if (hnbgw_cmdline_config.log_enable_timestamp)
		log_set_print_timestamp(osmo_stderr_target, 1);
	if (hnbgw_cmdline_config.log_level)
		log_set_log_level(osmo_stderr_target,
				  hnbgw_cmdline_config.log_level);

	rc = telnet_init_default(g_hnbgw, g_hnbgw, OSMO_VTY_PORT_HNBGW);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}

	g_hnbgw->ctrl = ctrl_interface_setup2(g_hnbgw, OSMO_CTRL_PORT_HNBGW, hnb_ctrl_node_lookup,
					       _LAST_CTRL_NODE_HNB);
	if (!g_hnbgw->ctrl) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to create CTRL interface on %s:%u\n",
		     ctrl_vty_get_bind_addr(), OSMO_CTRL_PORT_HNBGW);
		exit(1);
	} else {
		rc = hnb_ctrl_cmds_install();
		if (rc) {
			LOGP(DMAIN, LOGL_ERROR, "Failed to install CTRL interface commands\n");
			return 2;
		}
	}

	ranap_set_log_area(DRANAP);

	rc = hnbgw_cnlink_init("localhost", M3UA_PORT, "localhost");
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to initialize SCCP link to CN\n");
		exit(1);
	}

	LOGP(DHNBAP, LOGL_NOTICE, "Using RNC-Id %u\n", g_hnbgw->config.rnc_id);

	OSMO_ASSERT(g_hnbgw->config.iuh_local_ip);
	LOGP(DMAIN, LOGL_NOTICE, "Listening for Iuh at %s %d\n",
	     g_hnbgw->config.iuh_local_ip,
	     g_hnbgw->config.iuh_local_port);
	srv = osmo_stream_srv_link_create(g_hnbgw);
	if (!srv) {
		perror("cannot create server");
		exit(1);
	}
	osmo_stream_srv_link_set_data(srv, g_hnbgw);
	osmo_stream_srv_link_set_proto(srv, IPPROTO_SCTP);
	osmo_stream_srv_link_set_nodelay(srv, true);
	osmo_stream_srv_link_set_addr(srv, g_hnbgw->config.iuh_local_ip);
	osmo_stream_srv_link_set_port(srv, g_hnbgw->config.iuh_local_port);
	osmo_stream_srv_link_set_accept_cb(srv, hnbgw_rua_accept_cb);

	if (osmo_stream_srv_link_open(srv) < 0) {
		perror("Cannot open server");
		exit(1);
	}
	g_hnbgw->iuh = srv;

	/* Initialize and connect MGCP client. */
	if (hnbgw_mgw_setup() != 0)
		return -EINVAL;

#if ENABLE_PFCP
	/* If UPF is configured, set up PFCP socket and send Association Setup Request to UPF */
	hnbgw_pfcp_init();
#endif

	if (hnbgw_cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		rc = osmo_select_main_ctx(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
