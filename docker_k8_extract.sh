#!/bin/bash
set -x

# ==============================================================================
# FIRMWELL Kubernetes Extraction Script
#
# Usage: docker_k8_extract.sh <dir_path> <list_path> <job_index>
#                              <local_img_path> <local_out>
#
# Ensures an extracted firmware filesystem exists at
#   /output/images/${JOB_INDEX}.tar.gz
#
# Paths:
#   1. If a pre-extracted fs is found in /shared/extracted_fs/, copy it.
#   2. Otherwise run firmwell.py --unpack2zip to extract.
#
# Exit codes:
#   0 — extraction artifact exists
#   1 — extraction failed or artifact missing
# ==============================================================================

DIR_PATH=${1}
LIST_PATH=${2}
JOB_INDEX=${3}
LOCAL_IMG_PATH=${4}
LOCAL_OUT=${5}

# ---- Parse CSV to get target info --------------------------------------------

CONF=$(sed -n "${JOB_INDEX}p" "${LIST_PATH}")
BRAND=$(echo "$CONF" | csvtool col 1 -)
NAME=$(echo "$CONF" | csvtool col 2 -)
SHA256=$(echo "$CONF" | csvtool col 4 -)

FIX_PATH=${DIR_PATH}/fix/${JOB_INDEX}
RSF_PATH=${DIR_PATH}/rsf/${JOB_INDEX}
LOCAL_PATCH=/patches/${JOB_INDEX}


# ---- Lookup pre-extracted filesystem from full target list -------------------

csv_file="/shared/all_targets.list"
full_set_id=""

if [ -f "$csv_file" ]; then
    full_set_id=$(csvtool col 4 "$csv_file" | grep -n "^${SHA256}$" | awk -F: '{print $1}')
    echo "csv_file exists, full_set_id: ${full_set_id}" >> "${LOCAL_OUT}" 2>&1
else
    echo "csv_file does not exist: $csv_file" >> "${LOCAL_OUT}" 2>&1
fi

if [ -f "$csv_file" ] && [ -n "$full_set_id" ]; then
    LINE=$(sed -n "${full_set_id}p" "${csv_file}")
    full_set_name=$(echo "${LINE}" | csvtool col 2 -)
    full_set_path="/shared/$(echo "${LINE}" | csvtool col 3 - | tr -d '"')"

    echo "full_set_id: ${full_set_id}" >> "${LOCAL_OUT}" 2>&1
    echo "full_set_name: ${full_set_name}" >> "${LOCAL_OUT}" 2>&1
    echo "NAME: ${NAME}" >> "${LOCAL_OUT}" 2>&1
    echo "IMG_PATH: ${LOCAL_IMG_PATH}" >> "${LOCAL_OUT}" 2>&1
    echo "full_set_path: ${full_set_path}" >> "${LOCAL_OUT}" 2>&1
else
    echo "csv_file or full_set_id not found, skipping extraction check" >> "${LOCAL_OUT}" 2>&1
fi

# ---- Copy pre-extracted filesystem and kernel if available -------------------

if [ -f "$csv_file" ] && [ -n "$full_set_id" ] && [ -e "/shared/extracted_fs/${full_set_id}.tar.gz" ]; then
    echo "Copying extracted_fs/${full_set_id}.tar.gz to /output/images/${JOB_INDEX}.tar.gz" >> "${LOCAL_OUT}" 2>&1
    echo "Copying extracted_fs/${full_set_id}.tar.gz to /work/${JOB_INDEX}/FirmAE/images/" >> "${LOCAL_OUT}" 2>&1

    cp "/shared/extracted_fs/${full_set_id}.tar.gz" "/output/images/${JOB_INDEX}.tar.gz" >> "${LOCAL_OUT}" 2>&1
    cp "/shared/extracted_fs/${full_set_id}.tar.gz" "/work/${JOB_INDEX}/FirmAE/images/" >> "${LOCAL_OUT}" 2>&1
    cp "/shared/extracted_fs/${full_set_id}.kernel" "/output/images/${JOB_INDEX}.kernel" >> "${LOCAL_OUT}" 2>&1
    cp "/shared/extracted_fs/${full_set_id}.kernel" "/work/${JOB_INDEX}/FirmAE/images/" >> "${LOCAL_OUT}" 2>&1
else
    # ---- Run extraction via firmwell.py --------------------------------------

    echo "Extracted files not found or csv_file/full_set_id missing, proceeding with extraction" >> "${LOCAL_OUT}" 2>&1

    docker load -i /docker_img/fact_extractor.tar

    cd /fw

    CMD="timeout 7200 python3 /fw/firmwell.py \
        --fixpath ${FIX_PATH} \
        --rsfpath ${RSF_PATH} \
        --outpath=/tmp/results/${JOB_INDEX} \
        --logpath=${LOCAL_PATCH} \
        --brand=${BRAND} \
        --img_path=\"${LOCAL_IMG_PATH}\" \
        --max_cycles=10 \
        --jobindex ${JOB_INDEX} \
        --firmhash ${SHA256} \
        --privileged \
        --export \
        --rehost_type=HTTP \
        --unpack2zip"

    echo "current cmdline: $CMD"
    eval "$CMD >> ${LOCAL_OUT} 2>&1"
    RET_CODE=$?
    echo "Return code: $RET_CODE"

    docker rmi -f fkiecad/fact_extractor:latest
fi

# ---- Verify extraction artifact exists ---------------------------------------

if [ -f "/output/images/${JOB_INDEX}.tar.gz" ]; then
    echo "Extraction complete: /output/images/${JOB_INDEX}.tar.gz exists" >> "${LOCAL_OUT}" 2>&1
    exit 0
else
    echo "Extraction FAILED: /output/images/${JOB_INDEX}.tar.gz not found" >> "${LOCAL_OUT}" 2>&1
    exit 1
fi
