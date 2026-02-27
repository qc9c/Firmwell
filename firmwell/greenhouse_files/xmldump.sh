#!/bin/sh
set -x

while true; do
    timestamp=$(/greenhouse/busybox date +%Y%m%d_%H%M%S)
    file="xmldump_${timestamp}.xml"

    xmldbc -D "$file"

    sleep 8
done