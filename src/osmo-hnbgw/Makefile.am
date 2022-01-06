AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOTRAU_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORUA_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBOSMOHNBAP_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-hnbgw \
	$(NULL)

osmo_hnbgw_SOURCES = \
	hnbgw.c \
	hnbgw_hnbap.c \
	hnbgw_rua.c \
	hnbgw_ranap.c \
	hnbgw_vty.c \
	context_map.c \
	hnbgw_cn.c \
	ranap_rab_ass.c \
	mgw_fsm.c \
	tdefs.c \
	$(NULL)

osmo_hnbgw_LDADD = \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORUA_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOHNBAP_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBSCTP_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(NULL)
