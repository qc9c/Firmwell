#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox

[ -d /dev ] || ${BUSYBOX} mkdir -p /dev
[ -d /root ] || ${BUSYBOX} mkdir -p /root
[ -d /sys ] || ${BUSYBOX} mkdir -p /sys
[ -d /proc ] || ${BUSYBOX} mkdir -p /proc
[ -d /tmp ] || ${BUSYBOX} mkdir -p /tmp
${BUSYBOX} mkdir -p /var/lock

${BUSYBOX} mount -t sysfs sysfs /sys
${BUSYBOX} mount -t proc proc /proc
${BUSYBOX} ln -sf /proc/mounts /etc/mtab

${BUSYBOX} mkdir -p /dev/pts
${BUSYBOX} mount -t devpts devpts /dev/pts
${BUSYBOX} mount -t tmpfs tmpfs /run
