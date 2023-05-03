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
	ranap_rab_ass_test.ok \
	$(NULL)

check_PROGRAMS = \
	ranap_rab_ass_test \
	$(NULL)

ranap_rab_ass_test_SOURCES = \
	ranap_rab_ass_test.c \
	$(NULL)

ranap_rab_ass_test_LDADD = \
	$(top_builddir)/src/osmo-hnbgw/libhnbgw.la \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/ranap_rab_ass_test >$(srcdir)/ranap_rab_ass_test.ok
