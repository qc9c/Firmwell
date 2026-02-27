#!/bin/bash

DIR_PATH=${1} # /shared
LIST_PATH=${2} # targets.list
JOB_INDEX=${3}
EXTRA_PARAM=${4} # optional extra parameter
SKIP_FLAG=1
RETRY_FLAG=0
MAX_RETRIES=1
RETRY_PATH=${DIR_PATH}/retries/${JOB_INDEX}

echo "entrypoint.sh"
echo "SKIP_FLAG is currently set to: $SKIP_FLAG"
echo "OUT_PATH" $OUT_PATH


if [ $JOB_INDEX == "0" ]; then # edge-case
    echo "skip 0";
    touch ${DIR_PATH}/done/${JOB_INDEX} # for dockerd exit
    exit 0
fi

DONE_PATH="${DIR_PATH}/done/${JOB_INDEX}"
OUT_PATH="${DIR_PATH}/logs/${JOB_INDEX}"


# =============== SKIP LOGIC ==============
if [[ -f "$OUT_PATH" && $SKIP_FLAG == "1" ]]; then
    if [[ $RETRY_FLAG == "1" && -f "$RETRY_PATH" ]]; then
        COUNT=$(cat "$RETRY_PATH")
        if [[ $COUNT -lt $MAX_RETRIES ]]; then
            echo "In the middle of retry process, not skipping."
        else
            echo "log already present, skip!"
            touch "$DONE_PATH"
            exit 0
        fi
    else
        echo "log already present, skip!"
        touch "$DONE_PATH"
        exit 0
    fi
else
    rm -f "$DONE_PATH"
fi

/fw/docker_init.sh ${JOB_INDEX}

if [[ -n "$EXTRA_PARAM" ]]; then
    /fw/docker_k8_run.sh ${DIR_PATH} ${LIST_PATH} ${JOB_INDEX} ${SKIP_FLAG} ${RETRY_FLAG} ${EXTRA_PARAM}
else
    /fw/docker_k8_run.sh ${DIR_PATH} ${LIST_PATH} ${JOB_INDEX} ${SKIP_FLAG} ${RETRY_FLAG}
fi
