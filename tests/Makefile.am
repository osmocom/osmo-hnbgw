SUBDIRS = \
	ranap_rab_ass \
	$(NULL)

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	osmo-hnbgw-vty-test.cfg \
	$(srcdir)/*.vty \
	$(srcdir)/*.ctrl \
	$(srcdir)/config/*.cfg \
	$(srcdir)/config/*.vty \
	$(srcdir)/config/run_tests.sh \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
python-tests:
	$(MAKE) vty-test
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
else
python-tests:
	echo "Not running python-based tests (determined at configure-time)"
endif

# Run a specific test with: 'make vty-test VTY_TEST=osmo-hnbgw.vty'
VTY_TEST ?= *.vty

# To update the VTY script from current application behavior,
# pass -u to vty_script_runner.py by doing:
#   make vty-test U=-u
vty-test: $(top_builddir)/src/osmo-hnbgw/osmo-hnbgw
	osmo_verify_transcript_vty.py -v \
		-n OsmoHNBGW -p 4261 \
		-r "$(top_builddir)/src/osmo-hnbgw/osmo-hnbgw \
		-c $(srcdir)/osmo-hnbgw-vty-test.cfg" \
		$(U) $(srcdir)/$(VTY_TEST)

# Test each config/*.cfg file with the corresponding config/*.vty transcript test.
#
# To be invoked manually only: This is not part of 'make check' because the
# output may change when libosmo-sccp changes its VTY appearance, which can
# cause annoying test fallout.
#
# Each config test runs an osmo-hnbgw process to talk to, so they must not run concurrently.
# To prevent 'make -j N' from running these tests in parallel, call a script with a linear for-loop.
.PHONY: config-tests
config-tests:
	$(srcdir)/config/run_tests.sh "$(top_builddir)/src/osmo-hnbgw/osmo-hnbgw" "$(srcdir)/config/" $U

# Run a specific test with: 'make ctrl-test CTRL_TEST=osmo-hnbgw.ctrl'
CTRL_TEST ?= *.ctrl

# To update the CTRL script from current application behavior,
# pass -u to ctrl_script_runner.py by doing:
#   make ctrl-test U=-u
ctrl-test: $(top_builddir)/src/osmo-hnbgw/osmo-hnbgw
	osmo_verify_transcript_ctrl.py -v \
		-p 4262 \
		-r "$(top_builddir)/src/osmo-hnbgw/osmo-hnbgw -c $(top_srcdir)/doc/examples/osmo-hnbgw/osmo-hnbgw-cnpool.cfg" \
		$(U) $(srcdir)/$(CTRL_TEST)

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
