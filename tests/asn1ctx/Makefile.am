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
	asn1ctx_test.ok \
	$(NULL)

check_PROGRAMS = \
	asn1ctx_test \
	$(NULL)

asn1ctx_test_SOURCES = \
	asn1ctx_test.c \
	$(NULL)

asn1ctx_test_LDADD = \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/asn1ctx_test >$(srcdir)/asn1ctx_test.ok
