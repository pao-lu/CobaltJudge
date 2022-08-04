#!/bin/bash

TEMP_DIR="/dev/shm"
MIRROR_SITE="dl-cdn.alpinelinux.org"
USER_MIRROR="http://$MIRROR_SITE/alpine"
ARCH=$(arch)
SANDBOX_FS="/sandbox/fs"
SANDBOX_DEV="/sandbox/dev"

if [ $(id -u) -ne "0" ]; then
	echo "Must be root"
	exit 1
fi

wget "$USER_MIRROR/latest-stable/releases/$ARCH/latest-releases.yaml" \
	-O $TEMP_DIR"/latest-releases.yaml" || exit 1

LATEST_STABLE_NAME=$(
	grep -o -m1 "alpine-minirootfs-[0-9\\.]\\+-$ARCH.tar.gz" \
		$TEMP_DIR"/latest-releases.yaml"
)

echo latest stable name = $LATEST_STABLE_NAME

if [ $LATEST_STABLE_NAME -eq "" ]; then
	echo "Error getting latest stable alpine-linux release."
	exit 1
fi

rm "$TEMP_DIR/latest-releases.yaml"

mkdir -p /sandbox/fs

wget "$USER_MIRROR/latest-stable/releases/$ARCH/$LATEST_STABLE_NAME" \
	-O "$TEMP_DIR/$LATEST_STABLE_NAME" || exit 1

tar xzvf "$TEMP_DIR/$LATEST_STABLE_NAME" --one-top-level=$SANDBOX_FS

rm "$TEMP_DIR/$LATEST_STABLE_NAME"

sed -i \
	-e "s/dl-cdn.alpinelinux.org/$MIRROR_SITE/g" \
	-e 's/https/http/g' \
	$SANDBOX_FS/etc/apk/repositories

cp /etc/resolv.conf $SANDBOX_FS/etc/

export PATH=$PATH:/sbin

mkdir -p $SANDBOX_FS/etc/apk
#echo "$USER_MIRROR/$LATEST_STABLE_NAME/main" > /sandbox/etc/apk/repositories

mkdir -p $SANDBOX_DEV

mknod -m 666 $SANDBOX_DEV/full c 1 7
mknod -m 666 $SANDBOX_DEV/ptmx c 5 2
mknod -m 644 $SANDBOX_DEV/random c 1 8
mknod -m 644 $SANDBOX_DEV/urandom c 1 9
mknod -m 666 $SANDBOX_DEV/zero c 1 5
mknod -m 666 $SANDBOX_DEV/tty c 5 0
mknod -m 666 $SANDBOX_DEV/null c 1 3

chown root:tty $SANDBOX_DEV/tty
chown root:root $SANDBOX_DEV/full $SANDBOX_DEV/ptmx $SANDBOX_DEV/random \
	$SANDBOX_DEV/urandom


mount -t proc none $SANDBOX_FS/proc
mount -o bind /sys $SANDBOX_FS/sys
mount -o bind $SANDBOX_DEV $SANDBOX_FS/dev

cp /etc/resolv.conf $SANDBOX_FS/etc/

chroot $SANDBOX_FS apk add gcc
chroot $SANDBOX_FS apk add g++
chroot $SANDBOX_FS apk add musl-dev
chroot $SANDBOX_FS apk add openjdk11-jdk
chroot $SANDBOX_FS apk add python3

umount $SANDBOX_FS/proc
umount $SANDBOX_FS/sys
umount $SANDBOX_FS/dev
