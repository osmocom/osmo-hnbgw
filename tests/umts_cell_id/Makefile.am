AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = -no-install

EXTRA_DIST = \
	umts_cell_id_test.ok \
	$(NULL)

check_PROGRAMS = \
	umts_cell_id_test \
	$(NULL)

umts_cell_id_test_SOURCES = \
	umts_cell_id_test.c \
	$(NULL)

umts_cell_id_test_LDADD = \
	$(top_builddir)/src/osmo-hnbgw/libhnbgw.la \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/umts_cell_id_test >$(srcdir)/umts_cell_id_test.ok
