#!/bin/sh
osmo_hnbgw="$1"
tests_src="$2"
shift
shift

if [ ! -x "$osmo_hnbgw" ]; then
	echo "there seems to be no osmo-hnbgw executable at '$osmo_hnbgw'"
	exit 1
fi

if [ ! -d "$tests_src" ]; then
	echo "there seems to be no tests source dir at '$tests_src'"
	exit 1
fi

set -e
for dot_vty in "$tests_src"/*.vty; do
	dot_cfg="$(echo $dot_vty | sed 's/\.vty$/.cfg/')"
	osmo_verify_transcript_vty.py -v -n OsmoHNBGW -p 4261 -r "$osmo_hnbgw -c $dot_cfg" "$dot_vty" $@
done
