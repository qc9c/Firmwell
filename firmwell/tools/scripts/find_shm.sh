#!/bin/sh

SHM_ID="shmid=0x1"
for pid in $(ps -e -o pid=); do
    if pmap $pid 2>/dev/null | grep -q $SHM_ID; then
        echo "Process $pid is using shared memory ID $SHM_ID"
    fi
done