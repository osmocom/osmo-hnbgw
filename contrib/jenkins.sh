#!/usr/bin/env bash
# jenkins build helper script for osmo-hnbgw.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * PFCP: configure PFCP support if set to "1" (default)
# * WITH_MANUALS: build manual PDFs if set to "1"
# * NFTABLES: configure nftables support if set to "1" (default)
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
#
PFCP=${PFCP:-1}
NFTABLES=${NFTABLES:-1}

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

osmo-build-dep.sh libosmocore "" --disable-doxygen
osmo-build-dep.sh libosmo-abis
osmo-build-dep.sh libosmo-netif
osmo-build-dep.sh libosmo-sigtran
osmo-build-dep.sh libasn1c
osmo-build-dep.sh osmo-iuh
osmo-build-dep.sh osmo-mgw

# Additional configure options and depends
CONFIG=""
if [ "$PFCP" = "1" ]; then
	osmo-build-dep.sh libosmo-pfcp
	CONFIG="$CONFIG --enable-pfcp"
fi
if [ "$NFTABLES" = "1" ]; then
	CONFIG="$CONFIG --enable-nftables"
fi
if [ "$WITH_MANUALS" = "1" ]; then
	CONFIG="$CONFIG --enable-manuals"
fi

set +x
echo
echo
echo
echo " =============================== osmo-hnbgw ==============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-external-tests --enable-werror $CONFIG
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
  || cat-testlogs.sh
LD_LIBRARY_PATH="$inst/lib" \
  DISTCHECK_CONFIGURE_FLAGS="--enable-vty-tests --enable-external-tests $CONFIG" \
  $MAKE $PARALLEL_MAKE distcheck \
  || cat-testlogs.sh

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/doc/manuals" publish
fi

$MAKE $PARALLEL_MAKE maintainer-clean
osmo-clean-workspace.sh
