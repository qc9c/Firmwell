#!/bin/bash
set -e
set -u
set -x

# Check if the tarball file path is provided and exists
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path_to_tarball.tar.gz> [<architecture>]"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "Error: Tarball file '$1' not found!"
    exit 1
fi

USER=$(whoami)

check_arch () {
    ARCHS=("armel" "mipseb" "mipsel")

    if [ -z "${1}" ]; then
        return 0
    fi

    match=0
    for i in "${ARCHS[@]}"; do
        if [ "${1}" == "$i" ]; then
            match=1
        fi
    done

    if [ "${match}" -eq 0 ]; then
        return 0
    fi

    return 1
}

get_binary () {
    if check_arch "${2}"; then
        echo "Error: Invalid architecture!"
        exit 1
    fi

    echo "/qemu_system_files/${1}.${2}"
}

# The following functions are for partition management.
get_device () {
    echo '/dev/mapper/'`ls -t /dev/mapper | head -1`
}

get_dev_of_image () {
    IMAGE=${1}
    local IFS=$'\n'
    for LINE in `losetup`
    do
            # echo ${LINE} | awk '{print $1}'
            DEV_PATH=`echo ${LINE} | awk '{print $6}'`
            # echo ${LINE} | awk '{print $1}'
            # echo $DEV_PATH
            # echo $IMAGE
            if [[ "$DEV_PATH" == "$IMAGE" ]]; then
                echo ${LINE} | awk '{print $1}'
            fi
    done
}

add_partition () {
    local IFS=$'\n'
    local IMAGE_PATH
    local DEV_PATH=""
    local FOUND=false
    local LDEVRESULT="failed"

    echo "Setting up loop dev" 1>&2
    while [[ $LDEVRESULT == *"failed"* || $LDEVRESULT == *"in use"* ]]; do
        TARGETLOOPDEV=`losetup -f`
        # HOSTPATH="/dev/"$(basename ${LDEV})
        echo "    TARGET " $TARGETLOOPDEV 1>&2
        # COUNTER=1
        if [ ! -e ${TARGETLOOPDEV} ]; then
            ID=`echo $TARGETLOOPDEV | cut -c 10-`
            mknod -m660 "/dev/loop"$ID b 7 $ID
            echo "    made " "/dev/loop"$ID 1>&2
            chown root.disk $TARGETLOOPDEV
        fi
        # losetup -Pf ${1}
        LDEVRESULT="$(losetup -Pf ${1} 2>&1)"
        echo "    --> "$LDEVRESULT 1>&2
        sleep 1
    done
    echo "done setting up" 1>&2

    while (! ${FOUND})
    do
        sleep 1
        for LINE in `losetup`
        do
            IMAGE_PATH=`echo ${LINE} | awk '{print $6}'`
            if [ "${IMAGE_PATH}" = "${1}" ]; then
                DEV_PATH=/host/`echo ${LINE} | awk '{print $1}'`p1
                if [ -e ${DEV_PATH} ]; then
                    FOUND=true
                fi
            fi
        done
    done
    echo "FOUND " $DEV_PATH 1>&2

    while (! ls -al ${DEV_PATH} | grep -q "disk")
    do
        sleep 1
    done
    echo "SUCCESS" 1>&2
    echo ${DEV_PATH}
}

del_partition () {
    losetup -d ${1} &> /dev/null || true
    dmsetup remove $(basename ${1}) &>/dev/null || true
    sleep 1
}


TARBALL_PATH="$1"
WORK_DIR="$2"
ARCH=${3:-""}  # Optional architecture argument

# Derive working directory, image file path, and mount directory from the tarball path.
# The image file is created with the same basename but with .img extension.
# The mount point is a directory with suffix _mount.
#WORK_DIR=$(dirname "$TARBALL_PATH")
#BASENAME=$(basename "$TARBALL_PATH" .tar.gz)
IMAGE="${WORK_DIR}/image.raw"
IMAGE_DIR="${WORK_DIR}/image"
mkdir -p $IMAGE_DIR



echo "----Running----"
# Removed database-related path derivations:
# WORK_DIR=`get_scratch ${IID}`
# IMAGE=`get_fs ${IID}`
# IMAGE_DIR=`get_fs_mount ${IID}`

# Removed copying tarball part.
# We assume the input tarball is already at TARBALL_PATH.

echo "----Creating QEMU Image----"
qemu-img create -f raw "${IMAGE}" 1G
chmod a+rw "${IMAGE}"

echo "----Creating Partition Table----"
echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "${IMAGE}"

echo "----Mounting QEMU Image----"
DEVICE=$(add_partition "${IMAGE}")

echo "----Creating Filesystem----"
sync
mkfs.ext2 "${DEVICE}"

echo "----Making QEMU Image Mountpoint----"
if [ ! -e "${IMAGE_DIR}" ]; then
    mkdir "${IMAGE_DIR}"
    chown "${USER}" "${IMAGE_DIR}"
fi

echo "----Mounting QEMU Image Partition----"
sync
mount "${DEVICE}" "${IMAGE_DIR}"

echo "----Extracting Filesystem Tarball----"
tar -xf "${TARBALL_PATH}" -C "${IMAGE_DIR}"
# Optionally remove the tarball after extraction if desired:
# rm "${TARBALL_PATH}"

echo "----Creating FIRMADYNE Directories----"
mkdir "${IMAGE_DIR}/firmadyne/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram.override/"

cp "$(which busybox)" "${IMAGE_DIR}"
#cp "$(which bash-static)" "${IMAGE_DIR}"
#echo "----Finding Init (chroot)----"
#if [ -e "${WORK_DIR}/kernelInit" ]; then
#  cp "${WORK_DIR}/kernelInit" "${IMAGE_DIR}"
#fi
#cp "${SCRIPT_DIR}/inferFile.sh" "${IMAGE_DIR}"
#FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} chroot "${IMAGE_DIR}" /bash-static /inferFile.sh
#rm "${IMAGE_DIR}/bash-static"
#rm "${IMAGE_DIR}/inferFile.sh"
#if [ -e "${IMAGE_DIR}/kernelInit" ]; then
#  rm "${IMAGE_DIR}/kernelInit"
#fi
#
#mv "${IMAGE_DIR}/firmadyne/init" "${WORK_DIR}"
#if [ -e "${IMAGE_DIR}/firmadyne/service" ]; then
#  cp "${IMAGE_DIR}/firmadyne/service" "${WORK_DIR}"
#fi
#
echo "----Patching Filesystem (chroot)----"
#cp "${SCRIPT_DIR}/fixImage.sh" "${IMAGE_DIR}"
cp "/fw/firmwell/tools/scripts/fixImage.sh" "${IMAGE_DIR}"
chroot "${IMAGE_DIR}" /busybox ash /fixImage.sh
rm "${IMAGE_DIR}/fixImage.sh"
rm "${IMAGE_DIR}/busybox"

echo "----Setting up FIRMADYNE----"
BINARIES=( "busybox" "console" "strace")
for BINARY_NAME in "${BINARIES[@]}"
do
    BINARY_PATH=$(get_binary "${BINARY_NAME}" "${ARCH}")
    cp "${BINARY_PATH}" "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
    chmod a+x "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
done

if [ "$ARCH" = "mipseb" ]; then
    ARCH="mips"
fi
if [ "$ARCH" = "armel" ]; then
    ARCH="arm"
fi
mkdir -p "${IMAGE_DIR}/gh_nvram"
cp /fw/firmwell/greenhouse_files/libnvram_faker/lib/${ARCH}/uclibc/libnvram-faker.so "${IMAGE_DIR}/firmadyne/libnvram.so"


mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65

#cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
#chmod a+x "${IMAGE_DIR}/firmadyne/preInit.sh"
#
#cp "${SCRIPT_DIR}/network.sh" "${IMAGE_DIR}/firmadyne/network.sh"
#chmod a+x "${IMAGE_DIR}/firmadyne/network.sh"
#
#cp "${SCRIPT_DIR}/run_service.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
#chmod a+x "${IMAGE_DIR}/firmadyne/run_service.sh"
#
#cp "${SCRIPT_DIR}/injectionChecker.sh" "${IMAGE_DIR}/bin/a"
#chmod a+x "${IMAGE_DIR}/bin/a"
#
#touch "${IMAGE_DIR}/firmadyne/debug.sh"
#chmod a+x "${IMAGE_DIR}/firmadyne/debug.sh"
#
#if (! ${FIRMAE_ETC}); then
#  sed -i 's/sleep 60/sleep 15/g' "${IMAGE_DIR}/firmadyne/network.sh"
#  sed -i 's/sleep 120/sleep 30/g' "${IMAGE_DIR}/firmadyne/run_service.sh"
#  sed -i 's@/firmadyne/sh@/bin/sh@g' "${IMAGE_DIR}/firmadyne/preInit.sh" "${IMAGE_DIR}/firmadyne/network.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
#  sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' "${IMAGE_DIR}/firmadyne/preInit.sh" "${IMAGE_DIR}/firmadyne/network.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
#fi

echo "----Unmounting QEMU Image----"
sync
umount "${IMAGE_DIR}"
del_partition "${DEVICE:0:$((${#DEVICE}-2))}"

DEVICE=$(add_partition "${IMAGE}")
e2fsck -y "${DEVICE}"
sync
sleep 1
del_partition "${DEVICE:0:$((${#DEVICE}-2))}"

