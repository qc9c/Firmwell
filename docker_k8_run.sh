#!/bin/bash
set -x

# ==============================================================================
# FIRMWELL Kubernetes Job Runner
#
# Usage: docker_k8_run.sh <dir_path> <list_path> <job_index> <skip_flag>
#                          <retry_flag> [extra_param]
#
# Phases:
#   1. Parse arguments and CSV target list
#   2. Prepare working directories and copy firmware image
#   3. Restore cache / pre-extracted filesystem if available
#   4. Ensure extracted filesystem exists (delegates to docker_k8_extract.sh)
#   5. Rehost with extracted fs
#   6. Export results, callchain, and cache
#   7. Cleanup (FirmAE images, loop devices, tap interfaces)
#   8. Retry logic
# ==============================================================================

# ---- 1. Parse arguments -----------------------------------------------------

DIR_PATH=${1}
LIST_PATH=${2}
JOB_INDEX=${3}
SKIP_FLAG=${4}
RETRY_FLAG=${5}
EXTRA_PARAM=${6}

echo "${DIR_PATH}"
echo "${LIST_PATH}"
echo "${JOB_INDEX}"
echo "${SKIP_FLAG}"
echo "${RETRY_FLAG}"
echo "${EXTRA_PARAM}"

# Read target entry from CSV
CONF=$(sed -n "${JOB_INDEX}p" "${LIST_PATH}")
BRAND=$(echo "$CONF" | csvtool col 1 -)
NAME=$(echo "$CONF" | csvtool col 2 -)
IMG_PATH="/shared/$(echo "$CONF" | csvtool col 3 - | tr -d '"')"
SHA256=$(echo "$CONF" | csvtool col 4 -)

# ---- 2. Derived paths -------------------------------------------------------

OUT_PATH=${DIR_PATH}/logs/${JOB_INDEX}
RETRY_PATH=${DIR_PATH}/retries/${JOB_INDEX}
FIX_PATH=${DIR_PATH}/fix/${JOB_INDEX}
RSF_PATH=${DIR_PATH}/rsf/${JOB_INDEX}
LOCAL_OUT=/tmp/logs/${JOB_INDEX}
LOCAL_PATCH=/patches/${JOB_INDEX}
LOCAL_IMG_PATH="/tmp/img_${NAME}"
LABEL="${NAME//./_}"
MAX_RETRIES=2

# ---- 3. Initialize working environment --------------------------------------

mkdir -p "/${BRAND}"
mkdir -p /tmp/firm
mkdir -p /tmp/results/
mkdir -p /tmp/"${SHA256}"
mkdir -p "/work/${JOB_INDEX}"
mkdir -p /output/images

mv /work/FirmAE "/work/${JOB_INDEX}/FirmAE"
mkdir -p "/work/${JOB_INDEX}/FirmAE/images/"

source /root/venv/bin/activate

# ---- 4. Log initial state ----------------------------------------------------

{
    echo "CONF: $CONF"
    echo "BRAND: $BRAND"
    echo "NAME: $NAME"
    echo "IMG_PATH: $IMG_PATH"
    echo "RUNNING K8POD: ${POD_NAME} on > ${NODE_NAME}"
    echo "$DIR_PATH $LIST_PATH $JOB_INDEX"
    echo "FIRMWARE_PATH $IMG_PATH $BRAND $NAME"
    echo "Network Devices:"
    echo "--------------------------------------------------------------------"
    ifconfig
    echo "--------------------------------------------------------------------"
} > "${LOCAL_OUT}" 2>&1

# ---- 5. Copy firmware image --------------------------------------------------

echo "copying ${IMG_PATH} to ${LOCAL_IMG_PATH}" >> "${LOCAL_OUT}" 2>&1
cp "${IMG_PATH}" "${LOCAL_IMG_PATH}"
echo "${SHA256}" >> "${LOCAL_OUT}" 2>&1

# ---- 6. Restore cache if available ------------------------------------------

if [ -f "${DIR_PATH}/cache/${SHA256}.tar.gz" ]; then
    echo "Copying cache ${SHA256}.tar.gz" >> "${LOCAL_OUT}" 2>&1
    cp "${DIR_PATH}/cache/${SHA256}.tar.gz" /cache/
    tar -xzf "/cache/${SHA256}.tar.gz" -C /cache/
    rm "/cache/${SHA256}.tar.gz"
    ls /cache >> "${LOCAL_OUT}" 2>&1
fi



# ---- 8. Ensure extracted filesystem exists -----------------------------------

bash /fw/docker_k8_extract.sh "${DIR_PATH}" "${LIST_PATH}" "${JOB_INDEX}" "${LOCAL_IMG_PATH}" "${LOCAL_OUT}"
if [ $? -ne 0 ]; then
    echo "Extraction failed, aborting" >> "${LOCAL_OUT}"
    cp "${LOCAL_OUT}" "${OUT_PATH}"
    touch "${DIR_PATH}/done/${JOB_INDEX}"
    exit 1
fi

# ---- 10. Prepare extracted filesystem for Phase 2 ----------------------------

cd /

mkdir -p /tmp/ori_fs
tar -xzf "/output/images/${JOB_INDEX}.tar.gz" -C /tmp/ori_fs
echo "extracted /output/images/${JOB_INDEX}.tar.gz to /tmp/ori_fs" >> "${LOCAL_OUT}" 2>&1
ls /tmp/ori_fs >> "${LOCAL_OUT}" 2>&1

# Copy callchain from shared storage if not already present
if [ ! -f "/tmp/${SHA256}/${SHA256}_callchain.json" ]; then
    if [ -f "${DIR_PATH}/callchain/${SHA256}_callchain.json" ]; then
        echo "cp ${DIR_PATH}/callchain/${SHA256}_callchain.json /tmp/${SHA256}/${SHA256}_callchain.json" >> "${LOCAL_OUT}" 2>&1
        cp "${DIR_PATH}/callchain/${SHA256}_callchain.json" "/tmp/${SHA256}/${SHA256}_callchain.json" >> "${LOCAL_OUT}" 2>&1
    elif [ -f "/shared/callchain/${SHA256}_callchain.json" ]; then
        echo "cp /shared/callchain/${SHA256}_callchain.json /tmp/${SHA256}/${SHA256}_callchain.json" >> "${LOCAL_OUT}" 2>&1
        cp "/shared/callchain/${SHA256}_callchain.json" "/tmp/${SHA256}/${SHA256}_callchain.json" >> "${LOCAL_OUT}" 2>&1
    else
        echo "No available source callchain file for ${SHA256}" >> "${LOCAL_OUT}" 2>&1
    fi
fi

# ---- 11. Phase 2: Rehost with extracted filesystem ---------------------------

cd /fw

CMD="timeout 7200 python3 /fw/firmwell.py \
    --fixpath ${FIX_PATH} \
    --rsfpath ${RSF_PATH} \
    --outpath=/tmp/results/${JOB_INDEX} \
    --logpath=${LOCAL_PATCH} \
    --brand=${BRAND} \
    --img_path=\"${LOCAL_IMG_PATH}\" \
    --max_cycles=10 \
    --fs_path /tmp/ori_fs \
    --jobindex ${JOB_INDEX} \
    --firmhash ${SHA256} \
    --privileged \
    --export \
    --firmae /work/${JOB_INDEX}/FirmAE \
    --rehost_type=HTTP"

if [[ -n "$EXTRA_PARAM" ]]; then
    CMD="$CMD $EXTRA_PARAM"
fi

echo "current cmdline: $CMD"
eval "$CMD >> ${LOCAL_OUT} 2>&1"
RET_CODE=$?

echo "Return code: $RET_CODE"
tail "${LOCAL_OUT}"

echo "REHOSTING COMPLETE: $RET_CODE" >> "${LOCAL_OUT}"
cat /tmp/qemu.final.serial.log >> "${LOCAL_OUT}" 2>&1

# ---- 12. Tear down tap interfaces (pre-cleanup) -----------------------------

timeout 600 ifconfig -a | sed 's/[ :\t].*//;/^$/d' | grep tap | xargs -L 1 -I{} ifconfig {} down

if [[ $RET_CODE == 124 ]]; then
    echo "! REHOST TIMEDOUT !"
    echo "! REHOST TIMEDOUT !" >> "${LOCAL_OUT}"
fi

# ---- 13. Export results ------------------------------------------------------

cp "${LOCAL_PATCH}" "${DIR_PATH}/patches/${JOB_INDEX}"
ls "/tmp/results/${JOB_INDEX}"

echo "exporting results" >> "${LOCAL_OUT}" 2>&1
if [ -d "/tmp/results/${JOB_INDEX}" ]; then
    cd /tmp/results/
    ls "/tmp/results/${JOB_INDEX}" >> "${LOCAL_OUT}" 2>&1
    tar -czf "${JOB_INDEX}_${SHA256}.tar.gz" "${JOB_INDEX}"
    cp "/tmp/results/${JOB_INDEX}_${SHA256}.tar.gz" "${DIR_PATH}/results/${JOB_INDEX}_${SHA256}.tar.gz" >> "${LOCAL_OUT}" 2>&1
    cd /
fi

# Export callchain (if not already on shared storage)
echo "copy callchain" >> "${LOCAL_OUT}" 2>&1
if [ ! -f "${DIR_PATH}/callchain/${SHA256}_callchain.json" ]; then
    echo "cp /tmp/${SHA256}/${SHA256}_callchain.json ${DIR_PATH}/callchain/${SHA256}_callchain.json" >> "${LOCAL_OUT}" 2>&1
    cp "/tmp/${SHA256}/${SHA256}_callchain.json" "${DIR_PATH}/callchain/${SHA256}_callchain.json" >> "${LOCAL_OUT}" 2>&1
fi

# ---- 14. Cleanup FirmAE images and loop devices ------------------------------

cd "/work/${JOB_INDEX}/FirmAE/"
sudo timeout 600 /work/FirmAE/scripts/delete.sh 1

for i in "/work/${JOB_INDEX}/FirmAE/scratch/"*; do
    echo "...deleting $(basename "$i")"
    sudo "/work/${JOB_INDEX}/FirmAE/scripts/delete.sh" "$(basename "$i")"
done

# Disconnect stale loop devices left by FirmAE
LOOPDEVS=$(losetup | grep "FirmAE" | grep "image.raw" | grep "deleted" | tr "/" " " | awk '{print $2}')
for LDEV in $LOOPDEVS; do
    echo "Disconnecting $LDEV"
    echo "    - Disconnecting /dev/$LDEV" >> "${LOCAL_OUT}" 2>&1
    losetup -d "/dev/$LDEV"
    dmsetup remove "${LDEV}p1"
done

# Tear down any remaining tap interfaces
timeout 600 ifconfig -a | sed 's/[ :\t].*//;/^$/d' | grep tap | xargs -L 1 -I{} ifconfig {} down

# ---- 15. Save cache ----------------------------------------------------------

CACHEPATH=$(ls /cache)
echo "$CACHEPATH"
HASCACHE=$(ls "/cache/$CACHEPATH/GH_SUCCESSFUL_CACHE" 2>/dev/null)
if [[ -n "$HASCACHE" ]]; then
    echo "Good rehost, creating cache: ${SHA256}.tar.gz" >> "${LOCAL_OUT}"
    if [[ ! -f "${DIR_PATH}/cache/${SHA256}.tar.gz" ]]; then
        cd /cache
        tar -czf "${SHA256}.tar.gz" "$CACHEPATH"
        cp "${SHA256}.tar.gz" "${DIR_PATH}/cache/"
    else
        echo "    - cache already present, skip!" >> "${LOCAL_OUT}"
    fi
else
    echo "No cache created" >> "${LOCAL_OUT}"
fi

# ---- 16. Finalize log --------------------------------------------------------

echo "GHREHOST COMPLETE: $RET_CODE" >> "${LOCAL_OUT}"

# Append or overwrite log depending on retry round
LOG_OP=">"
if [[ -f "$RETRY_PATH" ]]; then
    COUNT=$(cat "$RETRY_PATH")
    if [[ $COUNT -ge 1 ]]; then
        LOG_OP=">>"
    fi
fi

if [[ "$LOG_OP" == ">" ]]; then
    cat "$LOCAL_OUT" > "$OUT_PATH"
else
    echo -e "\n\n===== Retry round $COUNT =====" >> "$OUT_PATH"
    cat "$LOCAL_OUT" >> "$OUT_PATH"
fi

# ---- 17. Retry logic ---------------------------------------------------------

echo "GHREHOST COMPLETE: $RET_CODE"
echo "RETRY_FLAG: $RETRY_FLAG"

if [[ "$RETRY_FLAG" == "1" ]]; then
    if [[ $RET_CODE -ne 0 ]]; then
        if [[ ! -f "$RETRY_PATH" ]]; then
            echo 1 > "$RETRY_PATH"
        fi
        COUNT=$(cat "$RETRY_PATH")
        if [[ $COUNT -lt $MAX_RETRIES ]]; then
            echo "Attempting a retry!"
            echo $(($COUNT + 1)) > "$RETRY_PATH"
            exit 42
        fi
        echo "No retries left"
    fi
fi

cat "${LOCAL_OUT}" >> "${OUT_PATH}"
echo "FIRMWELL CONTAINER exit"
touch "${DIR_PATH}/done/${JOB_INDEX}"
exit 0
