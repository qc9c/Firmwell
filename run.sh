#!/bin/bash

# ==============================================================================
# FIRMWELL Standalone Runner
#
# Usage: run.sh <brand> <firmware_image> [extra_args...]
#
# Phases:
#   1. Parse arguments and prepare working directories
#   2. Run FIRMWELL rehosting
#   3. Export results
#   4. Cleanup (Docker containers, networks, loop devices, tap interfaces)
# ==============================================================================

set -x

# ---- 1. Parse arguments -----------------------------------------------------

BRAND=${1}
IMG_PATH=${2}
shift 2
ARGS="$*"

echo "Running FIRMWELL"
echo "BRAND: ${BRAND}"
echo "IMG_PATH: ${IMG_PATH}"
echo "ARGS: ${ARGS}"

SHA256=$(sha256sum "${IMG_PATH}" | awk '{print $1}')
echo "SHA256: ${SHA256}"

LOCAL_IMG_PATH="/tmp/img_${SHA256}"
cp "${IMG_PATH}" "${LOCAL_IMG_PATH}"

LOCAL_OUT=/tmp/logs/${SHA256}

# ---- 2. Initialize working environment --------------------------------------

source /root/venv/bin/activate

mkdir -p "/${BRAND}"
mkdir -p /tmp/firm
mkdir -p /tmp/${SHA256}
mkdir -p /tmp/results/
mkdir -p /tmp/fixlog
mkdir -p /tmp/rsflog
mkdir -p /tmp/logs

# ---- 3. Rehost ---------------------------------------------------------------

cd /fw

# NOTE: Do NOT enable --privileged on a host machine.
# Only enable it when running inside a VMware virtual machine,
# otherwise it may modify the host's procfs and cause damage.
CMD="timeout 7200 python3 /fw/firmwell.py \
    --img_path=\"${LOCAL_IMG_PATH}\" \
    --outpath=/tmp/results/${SHA256} \
    --brand=${BRAND} \
    --rehost_type=HTTP \
    --firmhash ${SHA256} \
    --export \
    --max_cycles=10"

if [[ -n "$ARGS" ]]; then
    CMD="${CMD} ${ARGS}"
fi

echo "current cmdline: $CMD"

eval "$CMD"
RET_CODE=$?

echo "Return code: $RET_CODE"

if [[ $RET_CODE == 124 ]]; then
    echo "! REHOST TIMEDOUT !"
    echo "! REHOST TIMEDOUT !" >> ${LOCAL_OUT}
fi

# ---- 4. Export results -------------------------------------------------------

echo "exporting results"
if [ -d "/tmp/results/${SHA256}" ]; then
    cd /tmp/results/
    ls /tmp/results/${SHA256}
    tar -czf ${SHA256}.tar.gz ${SHA256}
    cd /
fi

# ---- 5. Cleanup --------------------------------------------------------------

# Disconnect stale loop devices
LOOPDEVS=$(losetup 2>/dev/null | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}')
for LDEV in $LOOPDEVS; do
    echo "Disconnecting $LDEV"
    losetup -d /dev/$LDEV 2>/dev/null
    dmsetup remove "${LDEV}p1" 2>/dev/null
done

# Tear down any remaining tap interfaces
timeout 60 ifconfig -a 2>/dev/null | sed 's/[ :\t].*//;/^$/d' | grep tap | xargs -L 1 -I{} ifconfig {} down

# Prune unused Docker resources
docker system prune --force 2>/dev/null

echo "REHOSTING COMPLETE: " $RET_CODE
