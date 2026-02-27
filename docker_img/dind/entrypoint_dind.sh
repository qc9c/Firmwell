#!/bin/sh
set -e

DIR_PATH=${1}         # /shared
LIST_PATH=${2}        # target/list
JOB_INDEX=${3}

echo "== dind entrypoint: index=${JOB_INDEX} =="

if [ "${JOB_INDEX}" = "0" ]; then
  echo "Skip index 0"
  touch "${DIR_PATH}/done/${JOB_INDEX}"
  exit 0
fi

# Wait for a done flag file before exiting
DONE_PATH="${DIR_PATH}/done/${JOB_INDEX}"

if [[ -f ${DONE_PATH} && $SKIP_FLAG == "1" ]]; then
       echo "done already present, skip!"
       exit 0
fi

if [[ -f ${OUT_PATH} && $SKIP_FLAG == "1" ]]; then
       echo "log already present, skip!"
       touch ${DIR_PATH}/done/${JOB_INDEX} # for dockerd exit
       exit 0
fi


mkdir -p /tmp/docker-root
#mount -t tmpfs -o rw,size=2G tmpfs /tmp/docker-root
mkdir -p /etc/docker
echo '{"data-root": "/tmp/docker-root"}' > /etc/docker/daemon.json
dockerd-entrypoint.sh &
while [ ! -f "${DONE_PATH}" ]; do
  sleep 10
done
exit 0
