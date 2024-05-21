#include <stdio.h>

#include <osmocom/hnbgw/hnbgw.h>

struct test {
	const char *id_str;
	int expect_rc;
	struct umts_cell_id id;
};

struct test tests[] = {
	{
		.id_str = "001-01-L1-R1-S1-C1",
		.id = {
			.mcc = 1,
			.mnc = 1,
			.lac = 1,
			.rac = 1,
			.sac = 1,
			.cid = 1,
		},
	},

	/* ensure that a 3-digit MNC with leading zeroes is kept separate from two-digit MNC */
	{
		.id_str = "001-001-L1-R1-S1-C1",
		.id = {
			.mcc = 1,
			.mnc = 1,
			.lac = 1,
			.rac = 1,
			.sac = 1,
			.cid = 1,
		},
	},
	{
		.id_str = "001-099-L1-R1-S1-C1",
		.id = {
			.mcc = 1,
			.mnc = 99,
			.lac = 1,
			.rac = 1,
			.sac = 1,
			.cid = 1,
		},
	},
	{
		.id_str = "001-99-L1-R1-S1-C1",
		.id = {
			.mcc = 1,
			.mnc = 99,
			.lac = 1,
			.rac = 1,
			.sac = 1,
			.cid = 1,
		},
	},

	{
		.id_str = "999-999-L65534-R65535-S65535-C268435455",
		.id = {
			.mcc = 999,
			.mnc = 999,
			.lac = 65534,
			.rac = 65535,
			.sac = 65535,
			.cid = (1 << 28) - 1,
		},
	},

	{
		.id_str = "1000-001-L1-R1-S1-C1",
		.expect_rc = -EINVAL,
	},
	{
		.id_str = "001-001-L65535-R1-S1-C1",
		.expect_rc = -EINVAL,
	},
	/* TODO? There is no bounds checking on RAC and SAC.
	{
		.id_str = "001-001-L1-R65536-S1-C1",
		.expect_rc = -EINVAL,
	},
	{
		.id_str = "001-001-L1-R1-S65536-C1",
		.expect_rc = -EINVAL,
	},
	*/
	{
		.id_str = "001-001-L1-R1-S1-C268435456",
		.expect_rc = -EINVAL,
	},
};

int main(void)
{
	struct hnbgw hnbgw_dummy = {};
	struct test *t;

	/* umts_cell_id_to_str() accesses g_hnbgw->config.plmn.mnc_3_digits, so make sure it is valid mem: */
	g_hnbgw = &hnbgw_dummy;

	for (t = tests; (t - tests) < ARRAY_SIZE(tests); t++) {
		int rc;
		struct umts_cell_id parsed;
		char to_str[128] = {};

		printf("\"%s\"\n", t->id_str);

		memset(&parsed, 0x2b, sizeof(parsed));
		rc = umts_cell_id_from_str(&parsed, t->id_str);
		if (rc != t->expect_rc) {
			printf("  ERROR: umts_cell_id_from_str(): expected rc == %d, got %d\n",
			       t->expect_rc, rc);
			continue;
		}

		if (rc) {
			if (rc == t->expect_rc)
				printf("  expected rc != 0: ok\n");
			continue;
		}
		printf("  -> umts_cell_id_from_str(): ok\n");

		rc = umts_cell_id_to_str_buf(to_str, sizeof(to_str), &parsed);
		if (rc <= 0) {
			printf("  ERROR: umts_cell_id_to_str_buf(): expected rc == 0, got %d\n", rc);
			continue;
		} else {
			printf("  -> umts_cell_id_to_str_buf(): ok\n");

			if (strcmp(t->id_str, to_str))
				printf("  ERROR: conversion to umts_cell_id and back to string doesn't return the original string\n");
			printf("  -> \"%s\"\n", to_str);
		}

		if (umts_cell_id_equal(&t->id, &parsed)) {
			printf("  umts_cell_id_equal(expected, parsed): ok\n");
		} else {
			char to_str_expect[128] = {};
			umts_cell_id_to_str_buf(to_str_expect, sizeof(to_str_expect), &t->id);
			printf("  ERROR: umts_cell_id_equal(expected, parsed) == false\n");
			printf("         expected %s\n", to_str_expect);
			printf("         got      %s\n", to_str);
			printf("         expected %s\n", osmo_hexdump((void *)&t->id, sizeof(t->id)));
			printf("         got      %s\n", osmo_hexdump((void *)&parsed, sizeof(t->id)));
		}
	}

	return 0;
}
