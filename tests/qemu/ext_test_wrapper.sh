#!/bin/sh -ex
DIR="$(cd "$(dirname "$0")" && pwd)"

cat << EOF > "$DIR"/_testcmd.sh
#!/bin/sh -ex
cd "$PWD"

EOF
chmod +x "$DIR"/_testcmd.sh

for i in "$@"; do
	echo -n "\"$i\" " >> "$DIR"/_testcmd.sh
done
echo >> "$DIR"/_testcmd.sh

cat << EOF > "$DIR"/_init.sh
#!/usr/bin/busybox sh
echo "Running _init.sh"
set -x

/usr/bin/busybox --install -s
hostname qemu

for i in \$(cat /modules); do
	modprobe "\$i"
done

ip link set lo up
ip a

mkdir /mnt/
mount \
	-t 9p \
	-o trans=virtio \
	fs0 \
	/mnt/

# osmotestconfig.py tries to write to builddir
cp -r /mnt/$BUILDDIR /tmp/builddir
mount --bind /tmp/builddir /mnt/$BUILDDIR

if chroot /mnt "$DIR"/_testcmd.sh; then
	echo "QEMU_TEST_SUCCESSFUL"
fi

poweroff -f
EOF
chmod +x "$DIR"/_init.sh

if ! [ -e "$DIR"/_linux ]; then
	cp /boot/vmlinuz "$DIR"/_linux
fi

$DIR/initrd-build.sh

KERNEL_CMDLINE="root=/dev/ram0 console=ttyS0 panic=-1 init=/init"

qemu-system-x86_64 \
	$MACHINE_ARG \
	-smp 1 \
	-m 512M \
	-no-user-config -nodefaults -display none \
	-gdb unix:"$DIR"/_gdb.pipe,server=on,wait=off \
	-no-reboot \
	-kernel "$DIR"/_linux \
	-initrd "$DIR"/_initrd.gz \
	-append "${KERNEL_CMDLINE}" \
	-serial stdio \
	-chardev socket,id=charserial1,path="$DIR"/_gdb-serial.pipe,server=on,wait=off \
	-device isa-serial,chardev=charserial1,id=serial1 \
	-fsdev local,security_model=passthrough,id=fsdev-fs0,multidevs=remap,path=/ \
	-device virtio-9p-pci,id=fs0,fsdev=fsdev-fs0,mount_tag=fs0 \
	2>&1 | tee "$DIR/_output"

grep -q QEMU_TEST_SUCCESSFUL "$DIR/_output"
