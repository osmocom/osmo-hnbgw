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
 */

#include "config.h"

#include <osmocom/hnbgw/tdefs.h>

#if ENABLE_PFCP
#include <osmocom/pfcp/pfcp_endpoint.h>
#endif

struct osmo_tdef mgw_fsm_T_defs[] = {
	{.T = -1001, .default_val = 5, .desc = "Timeout for HNB side call-leg (to-HNB) creation" },
	{.T = -1002, .default_val = 10, .desc = "Timeout for the HNB to respond to RAB Assignment Request" },
	{.T = -1003, .default_val = 5, .desc = "Timeout for HNB side call-leg (to-HNB) completion" },
	{.T = -1004, .default_val = 5, .desc = "Timeout for MSC side call-leg (to-MSC) completion" },
	{.T = -2427, .default_val = 5, .desc = "timeout for MGCP response from MGW" },
	{ }
};

struct osmo_tdef ps_T_defs[] = {
	{.T = -1002, .default_val = 10, .desc = "Timeout for the HNB to respond to PS RAB Assignment Request" },
	{ }
};

struct osmo_tdef_group hnbgw_tdef_group[] = {
	{.name = "mgw", .tdefs = mgw_fsm_T_defs, .desc = "MGW (Media Gateway) interface" },
	{.name = "ps", .tdefs = ps_T_defs, .desc = "timers for Packet Switched domain" },
#if ENABLE_PFCP
	{.name = "pfcp", .tdefs = osmo_pfcp_tdefs, .desc = "PFCP timers" },
#endif
	{ }
};
