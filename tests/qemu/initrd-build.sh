#!/bin/sh -e
DIR="$(cd "$(dirname "$0")" && pwd)"
DIR_INITRD="$DIR/_initrd"
DIR_MODULES="$(find /lib/modules/* -type d -prune | sort -r | head -n 1)"

# Add one or more files to the initramfs, with parent directories.
# usr-merge: resolve symlinks for /lib -> /usr/lib etc. so "cp --parents" does
# not fail with "cp: cannot make directory '/tmp/initrd/lib': File exists"
# $@: path to files
initrd_add_file() {
	local i

	for i in "$@"; do
		case "$i" in
		/bin/*|/sbin/*|/lib/*|/lib64/*)
			cp -a --parents "$i" "$DIR_INITRD"/usr
			;;
		*)
			cp -a --parents "$i" "$DIR_INITRD"
			;;
		esac
	done
}

# Add kernel module files with dependencies
# $@: kernel module names
initrd_add_mod() {
	local i
	local kernel="$(basename "$DIR_MODULES")"
	local files="$(modprobe \
		-a \
		--dry-run \
		--show-depends \
		--set-version="$kernel" \
		"$@" \
		| grep -v "^builtin" \
		| sort -u \
		| cut -d ' ' -f 2)"

	initrd_add_file $files

	# Save the list of modules
	for i in $@; do
		echo "$i" >> "$DIR_INITRD"/modules
	done
}

# Add binaries with depending libraries
# $@: paths to binaries
initrd_add_bin() {
	local bin
	local bin_path
	local file

	for bin in "$@"; do
		local bin_path="$(which "$bin")"
		if [ -z "$bin_path" ]; then
			echo "ERROR: file not found: $bin"
			exit 1
		fi

		lddtree_out="$(lddtree -l "$bin_path")"
		if [ -z "$lddtree_out" ]; then
			echo "ERROR: lddtree failed on '$bin_path'"
			exit 1
		fi

		for file in $lddtree_out; do
			initrd_add_file "$file"

			# Copy resolved symlink
			if [ -L "$file" ]; then
				initrd_add_file "$(realpath "$file")"
			fi
		done
	done
}

rm -rf "$DIR_INITRD"
mkdir -p "$DIR_INITRD"
cd "$DIR_INITRD"

for dir in bin sbin lib lib64; do
	ln -s usr/"$dir" "$dir"
done

mkdir -p \
	dev/net \
	proc \
	run \
	sys \
	tmp \
	usr/bin \
	usr/sbin

initrd_add_bin \
	busybox

initrd_add_mod \
	9p \
	9pnet \
	9pnet_virtio \
	nf_tables \
	nfnetlink \
	sctp

initrd_add_file \
	"$DIR_MODULES"/modules.dep

cp "$DIR"/_init.sh init

find . -print0 \
	| cpio --quiet -o -0 -H newc \
	| gzip -1 > "$DIR"/_initrd.gz
