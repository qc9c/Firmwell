#!/bin/sh
set -x

BUSYBOX=/greenhouse/busybox

while true; do
    timestamp=$($BUSYBOX date +%Y%m%d_%H%M%S)
    file="xmldump_${timestamp}.xml"

    {xmldbc} -D "$file"

    $BUSYBOX sleep 8
done