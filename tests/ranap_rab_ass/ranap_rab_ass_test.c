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

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/hnbgw/hnbgw.h>

#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/iu_helpers.h>
#include <osmocom/hnbgw/ranap_rab_ass.h>
#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_common_ran.h>

static void *tall_hnb_ctx;
static void *msgb_ctx;
extern void *talloc_asn1_ctx;

void test_ranap_rab_ass_req_decode_encode(void)
{
	int rc;
	ranap_message message;
	uint8_t testvec[] = {
		0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x01, 0x00,
		0x36, 0x40, 0x52, 0x00, 0x00, 0x01, 0x00, 0x35,
		0x00, 0x48, 0x78, 0x22, 0xcd, 0x80, 0x10, 0x2f,
		0xa7, 0x20, 0x1a, 0x2c, 0x00, 0x00, 0xf4, 0x4c,
		0x08, 0x0a, 0x02, 0x80, 0x00, 0x51, 0x40, 0x00,
		0x27, 0x20, 0x28, 0x14, 0x00, 0x67, 0x40, 0x00,
		0x00, 0x22, 0x28, 0x14, 0x00, 0x3c, 0x40, 0x00,
		0x00, 0x00, 0x50, 0x3d, 0x02, 0x00, 0x02, 0x27,
		0xc0, 0x35, 0x00, 0x01, 0x0a, 0x09, 0x01, 0xa2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x1f, 0x76,
		0x00, 0x00, 0x40, 0x01, 0x00, 0x00
	};
	uint8_t encoded[sizeof(testvec)];

	rc = ranap_ran_rx_co_decode(talloc_asn1_ctx, &message, testvec, sizeof(testvec));
	OSMO_ASSERT(rc == 0);

	rc = ranap_rab_ass_req_encode(encoded, sizeof(encoded), &message.msg.raB_AssignmentRequestIEs);
	printf("ranap_rab_ass_req_encode rc=%d\n", rc);

	printf("INPUT:  %s\n", osmo_hexdump_nospc(testvec, sizeof(testvec)));
	printf("RESULT: %s\n", osmo_hexdump_nospc(encoded, sizeof(encoded)));
	OSMO_ASSERT(memcmp(testvec, encoded, sizeof(testvec)) == 0);

	ranap_ran_rx_co_free(&message);
}

void test_ranap_rab_ass_resp_decode_encode(void)
{
	int rc;
	ranap_message message;
	uint8_t testvec[] = {
		0x60, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x01, 0x00,
		0x34, 0x40, 0x23, 0x00, 0x00, 0x01, 0x00, 0x33,
		0x40, 0x1c, 0x60, 0x3a, 0x7c, 0x35, 0x00, 0x01,
		0x0a, 0x09, 0x01, 0xa4, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x40, 0x04, 0x0a, 0x00, 0x00
	};
	uint8_t encoded[sizeof(testvec)];

	rc = ranap_cn_rx_co_decode(talloc_asn1_ctx, &message, testvec, sizeof(testvec));
	OSMO_ASSERT(rc == 0);

	rc = ranap_rab_ass_resp_encode(encoded, sizeof(encoded), &message.msg.raB_AssignmentResponseIEs);
	printf("ranap_rab_ass_resp_encode rc=%d\n", rc);

	printf("INPUT:  %s\n", osmo_hexdump_nospc(testvec, sizeof(testvec)));
	printf("RESULT: %s\n", osmo_hexdump_nospc(encoded, sizeof(encoded)));
	OSMO_ASSERT(memcmp(testvec, encoded, sizeof(testvec)) == 0);

	ranap_cn_rx_co_free(&message);
}

void test_ranap_rab_ass_req_extract_inet_addr(void)
{
	int rc;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	uint8_t rab_id;
	ranap_message message;
	uint8_t testvec[] = {
		0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x01, 0x00,
		0x36, 0x40, 0x52, 0x00, 0x00, 0x01, 0x00, 0x35,
		0x00, 0x48, 0x78, 0x22, 0xcd, 0x80, 0x10, 0x2f,
		0xa7, 0x20, 0x1a, 0x2c, 0x00, 0x00, 0xf4, 0x4c,
		0x08, 0x0a, 0x02, 0x80, 0x00, 0x51, 0x40, 0x00,
		0x27, 0x20, 0x28, 0x14, 0x00, 0x67, 0x40, 0x00,
		0x00, 0x22, 0x28, 0x14, 0x00, 0x3c, 0x40, 0x00,
		0x00, 0x00, 0x50, 0x3d, 0x02, 0x00, 0x02, 0x27,
		0xc0, 0x35, 0x00, 0x01, 0x0a, 0x09, 0x01, 0xa2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x1f, 0x76,
		0x00, 0x00, 0x40, 0x01, 0x00, 0x00
	};

	rc = ranap_ran_rx_co_decode(talloc_asn1_ctx, &message, testvec, sizeof(testvec));
	OSMO_ASSERT(rc == 0);
	rc = ranap_rab_ass_req_ies_extract_inet_addr(&addr, &rab_id, &message.msg.raB_AssignmentRequestIEs, 0);
	osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	printf("ranap_rab_ass_req_extract_inet_addr rc=%d\n", rc);
	printf("RESULT: addr=%s, port=%u, rab-id=%02x\n", addr_str.ip, addr_str.port, rab_id);
	ranap_ran_rx_co_free(&message);
}

void test_ranap_rab_ass_resp_extract_inet_addr(void)
{
	int rc;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	ranap_message message;
	uint8_t testvec[] = {
		0x60, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x01, 0x00,
		0x34, 0x40, 0x23, 0x00, 0x00, 0x01, 0x00, 0x33,
		0x40, 0x1c, 0x60, 0x3a, 0x7c, 0x35, 0x00, 0x01,
		0x0a, 0x09, 0x01, 0xa4, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x40, 0x04, 0x0a, 0x00, 0x00
	};

	rc = ranap_cn_rx_co_decode(talloc_asn1_ctx, &message, testvec, sizeof(testvec));
	OSMO_ASSERT(rc == 0);
	rc = ranap_rab_ass_resp_ies_extract_inet_addr(&addr, &message.msg.raB_AssignmentResponseIEs, 7);
	osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	printf("ranap_rab_ass_resp_extract_inet_addr rc=%d\n", rc);
	printf("RESULT: addr=%s, port=%u\n", addr_str.ip, addr_str.port);
	ranap_cn_rx_co_free(&message);
}

void test_ranap_rab_ass_req_replace_inet_addr(void)
{
	int rc;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	ranap_message message;
	uint8_t rab_id;
	uint8_t testvec_in[] = {
		0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x01, 0x00,
		0x36, 0x40, 0x52, 0x00, 0x00, 0x01, 0x00, 0x35,
		0x00, 0x48, 0x78, 0x4e, 0xcd, 0x80, 0x10, 0x2f,
		0xa7, 0x20, 0x1a, 0x2c, 0x00, 0x00, 0xf4, 0x4c,
		0x08, 0x0a, 0x02, 0x80, 0x00, 0x51, 0x40, 0x00,
		0x27, 0x20, 0x28, 0x14, 0x00, 0x67, 0x40, 0x00,
		0x00, 0x22, 0x28, 0x14, 0x00, 0x3c, 0x40, 0x00,
		0x00, 0x00, 0x50, 0x3d, 0x02, 0x00, 0x02, 0x27,
		0xc0, 0x35, 0x00, 0x01, 0x0a, 0x09, 0x01, 0xa2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x1f, 0xba,
		0x00, 0x00, 0x40, 0x01, 0x00
	};
	uint8_t testvec_expected_out[] = {
		0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x01, 0x00,
		0x36, 0x40, 0x52, 0x00, 0x00, 0x01, 0x00, 0x35,
		0x00, 0x48, 0x78, 0x4e, 0xcd, 0x80, 0x10, 0x2f,
		0xa7, 0x20, 0x1a, 0x2c, 0x00, 0x00, 0xf4, 0x4c,
		0x08, 0x0a, 0x02, 0x80, 0x00, 0x51, 0x40, 0x00,
		0x27, 0x20, 0x28, 0x14, 0x00, 0x67, 0x40, 0x00,
		0x00, 0x22, 0x28, 0x14, 0x00, 0x3c, 0x40, 0x00,
		0x00, 0x00, 0x50, 0x3d, 0x02, 0x00, 0x02, 0x27,
		0xc0, 0x35, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x04, 0xd2,
		0x00, 0x00, 0x40, 0x01, 0x00
	};

	rc = ranap_ran_rx_co_decode(talloc_asn1_ctx, &message, testvec_in, sizeof(testvec_in));
	OSMO_ASSERT(rc == 0);

	rc = ranap_rab_ass_req_ies_extract_inet_addr(&addr, &rab_id, &message.msg.raB_AssignmentRequestIEs, 0);
	OSMO_ASSERT(rc == 0);
	osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	printf("before: addr=%s, port=%u, rab_id=%u\n", addr_str.ip, addr_str.port, rab_id);

	memset(&addr_str, 0, sizeof(addr_str));
	addr_str.af = AF_INET;
	addr_str.port = 1234;
	osmo_strlcpy(addr_str.ip, "1.2.3.4", sizeof(addr_str.ip));
	osmo_sockaddr_str_to_sockaddr(&addr_str, &addr.u.sas);

	rc = ranap_rab_ass_req_ies_replace_inet_addr(&message.msg.raB_AssignmentRequestIEs, &addr, rab_id);
	printf("ranap_rab_ass_req_replace_inet_addr rc=%d\n", rc);

	rc = ranap_rab_ass_req_ies_extract_inet_addr(&addr, &rab_id, &message.msg.raB_AssignmentRequestIEs, 0);
	OSMO_ASSERT(rc == 0);
	osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	printf("after: addr=%s, port=%u, rab_id=%u\n", addr_str.ip, addr_str.port, rab_id);

	rc = ranap_rab_ass_req_encode(testvec_in, sizeof(testvec_in), &message.msg.raB_AssignmentRequestIEs);
	OSMO_ASSERT(rc == sizeof(testvec_in));
	OSMO_ASSERT(memcmp(testvec_in, testvec_expected_out, sizeof(testvec_in)) == 0);

	ranap_ran_rx_co_free(&message);
}

void test_ranap_rab_ass_resp_replace_inet_addr(void)
{
	int rc;
	struct osmo_sockaddr addr;
	struct osmo_sockaddr_str addr_str;
	ranap_message message;
	uint8_t testvec_in[] = {
		0x60, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x01, 0x00,
		0x34, 0x40, 0x23, 0x00, 0x00, 0x01, 0x00, 0x33,
		0x40, 0x1c, 0x60, 0x32, 0x7c, 0x35, 0x00, 0x01,
		0x0a, 0x09, 0x01, 0xa4, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x40, 0x04, 0x0a, 0x00, 0x00
	};
	uint8_t testvec_expected_out[] = {
		0x60, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x01, 0x00,
		0x34, 0x40, 0x23, 0x00, 0x00, 0x01, 0x00, 0x33,
		0x40, 0x1c, 0x60, 0x32, 0x7c, 0x35, 0x00, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x40, 0x04, 0xd2, 0x00, 0x00
	};

	rc = ranap_cn_rx_co_decode(talloc_asn1_ctx, &message, testvec_in, sizeof(testvec_in));
	OSMO_ASSERT(rc == 0);

	rc = ranap_rab_ass_resp_ies_extract_inet_addr(&addr, &message.msg.raB_AssignmentResponseIEs, 6);
	OSMO_ASSERT(rc == 0);
	osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	printf("before: addr=%s, port=%u\n", addr_str.ip, addr_str.port);

	memset(&addr_str, 0, sizeof(addr_str));
	addr_str.af = AF_INET;
	addr_str.port = 1234;
	osmo_strlcpy(addr_str.ip, "1.2.3.4", sizeof(addr_str.ip));
	osmo_sockaddr_str_to_sockaddr(&addr_str, &addr.u.sas);

	rc = ranap_rab_ass_resp_ies_replace_inet_addr(&message.msg.raB_AssignmentResponseIEs, &addr, 6);
	printf("ranap_rab_ass_resp_replace_inet_addr rc=%d\n", rc);

	rc = ranap_rab_ass_resp_ies_extract_inet_addr(&addr, &message.msg.raB_AssignmentResponseIEs, 6);
	OSMO_ASSERT(rc == 0);
	osmo_sockaddr_str_from_sockaddr(&addr_str, &addr.u.sas);
	printf("after: addr=%s, port=%u\n", addr_str.ip, addr_str.port);

	rc = ranap_rab_ass_resp_encode(testvec_in, sizeof(testvec_in), &message.msg.raB_AssignmentResponseIEs);
	OSMO_ASSERT(rc == sizeof(testvec_in));
	OSMO_ASSERT(memcmp(testvec_in, testvec_expected_out, sizeof(testvec_in)) == 0);

	ranap_cn_rx_co_free(&message);
}

void test_ranap_rab_ass_resp_ies_check_failure(void)
{
	int rc;
	ranap_message message;
	bool rab_failed_at_hnb;
	uint8_t testvec[] = {
		0x60, 0x00, 0x00, 0x11, 0x00, 0x00, 0x01, 0x00,
		0x23, 0x40, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x22,
		0x40, 0x03, 0x05, 0xd0, 0x00
	};

	rc = ranap_cn_rx_co_decode(talloc_asn1_ctx, &message, testvec, sizeof(testvec));
	OSMO_ASSERT(rc == 0);

	rab_failed_at_hnb =
		ranap_rab_ass_resp_ies_check_failure(&message.msg.raB_AssignmentResponseIEs, 23);
	printf("ranap_rab_ass_resp_ies_check_failure rab_failed_at_hnb=%u (RAB ID 23)\n", rab_failed_at_hnb);

	rab_failed_at_hnb =
		ranap_rab_ass_resp_ies_check_failure(&message.msg.raB_AssignmentResponseIEs, 44);
	printf("ranap_rab_ass_resp_ies_check_failure rab_failed_at_hnb=%u (RAB ID 44, which is not in the message)\n",
	       rab_failed_at_hnb);

	ranap_cn_rx_co_free(&message);
}

static const struct log_info_cat log_cat[] = {
	[DRANAP] = {
		    .name = "RANAP", .loglevel = LOGL_DEBUG, .enabled = 1,
		    .color = "",
		    .description = "RAN Application Part",
		     },
};

static const struct log_info test_log_info = {
	.cat = log_cat,
	.num_cat = ARRAY_SIZE(log_cat),
};

int test_init(void)
{
	int rc;

	tall_hnb_ctx = talloc_named_const(NULL, 0, "hnb_context");
	msgb_ctx = msgb_talloc_ctx_init(NULL, 0);
	talloc_asn1_ctx = talloc_named_const(NULL, 0, "asn1_context");

	rc = osmo_init_logging2(tall_hnb_ctx, &test_log_info);
	if (rc < 0)
		exit(1);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	return rc;
}

void test_cleanup(void)
{
	if (talloc_total_blocks(msgb_ctx) != 1 || talloc_total_size(msgb_ctx) != 0)
		talloc_report_full(msgb_ctx, stderr);

	OSMO_ASSERT(talloc_total_blocks(msgb_ctx) == 1);
	OSMO_ASSERT(talloc_total_size(msgb_ctx) == 0);
	talloc_free(msgb_ctx);

	if (talloc_total_blocks(talloc_asn1_ctx) != 1 || talloc_total_size(talloc_asn1_ctx) != 0)
		talloc_report_full(talloc_asn1_ctx, stderr);

	OSMO_ASSERT(talloc_total_blocks(talloc_asn1_ctx) == 1);
	OSMO_ASSERT(talloc_total_size(talloc_asn1_ctx) == 0);
	talloc_free(talloc_asn1_ctx);
}

int main(int argc, char **argv)
{
	test_init();

	test_ranap_rab_ass_req_decode_encode();
	test_ranap_rab_ass_resp_decode_encode();

	test_ranap_rab_ass_req_extract_inet_addr();
	test_ranap_rab_ass_resp_extract_inet_addr();
	test_ranap_rab_ass_req_replace_inet_addr();
	test_ranap_rab_ass_resp_replace_inet_addr();
	test_ranap_rab_ass_resp_ies_check_failure();

	test_cleanup();
	return 0;
}

/* Stub */
const char *hnb_context_name(struct hnb_context *ctx)
{
	return "TEST";
}
