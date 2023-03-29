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
	$(LIBASN1C_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(top_builddir)/src/osmo-hnbgw/ranap_rab_ass.o \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/ranap_rab_ass_test >$(srcdir)/ranap_rab_ass_test.ok
