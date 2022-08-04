#!/bin/bash
export PATH=$PATH:/sbin
SANDBOX_FS="/sandbox/fs"
SANDBOX_DEV="/sandbox/dev"

mount -t proc none $SANDBOX_FS/proc
mount -o bind /sys $SANDBOX_FS/sys
mount -o bind /dev $SANDBOX_FS/dev

chroot $SANDBOX_FS /bin/sh

umount $SANDBOX_FS/proc
umount $SANDBOX_FS/sys
umount $SANDBOX_FS/dev
