#!/bin/bash

path=$1
parent_dir=$(dirname "$path")

if [ ! -d "$parent_dir" ]; then
    mkdir -p "$parent_dir"
fi

# 16777216, 16M
data=$(head -c 1048576 < /dev/zero | tr '\0' '\xFF')
printf "%s" "$data" > "$path"
