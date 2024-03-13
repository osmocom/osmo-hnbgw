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

noinst_LTLIBRARIES = \
	libhnbgw.la \
	$(NULL)

libhnbgw_la_SOURCES = \
	hnbgw.c \
	hnbgw_hnbap.c \
	hnbgw_l3.c \
	hnbgw_rua.c \
	hnbgw_ranap.c \
	hnbgw_vty.c \
	context_map.c \
	context_map_rua.c \
	context_map_sccp.c \
	hnbgw_cn.c \
	cnlink.c \
	ranap_rab_ass.c \
	mgw_fsm.c \
	kpi_ranap.c \
	tdefs.c \
	$(NULL)

libhnbgw_la_LIBADD = \
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
	$(LIBSCTP_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(NULL)

if ENABLE_PFCP
AM_CFLAGS += \
	$(LIBOSMOPFCP_CFLAGS) \
	$(NULL)
libhnbgw_la_LIBADD += \
	$(LIBOSMOPFCP_LIBS) \
	$(NULL)
libhnbgw_la_SOURCES += \
	hnbgw_pfcp.c \
	ps_rab_ass_fsm.c \
	ps_rab_fsm.c \
	$(NULL)
endif

bin_PROGRAMS = \
	osmo-hnbgw \
	$(NULL)

osmo_hnbgw_SOURCES = \
	osmo_hnbgw_main.c \
	$(NULL)

osmo_hnbgw_LDADD = \
	libhnbgw.la \
	$(NULL)
