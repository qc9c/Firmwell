#!/bin/bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

directory="$script_dir/ghdev"

if [ ! -d "$directory" ]; then
    mkdir -p "$directory"
fi

if [ ! -d "$directory/mtd" ]; then
    mkdir -p "$directory/mtd"
fi

if [ ! -d "$directory/mtdblock" ]; then
    mkdir -p "$directory/mtdblock"
fi

file_list=("mtd0" "mtd1" "mtd2" "mtd3" "mtd4" "mtd5" "mtd6" "mtd7" "mtd8" "mtd9" "mtd10" "mtd11")
#mtd_dir_list=("mtd/0" "mtd/1" "mtd/2" "mtd/3" "mtd/4" "mtd/5" "mtd/6" "mtd/7" "mtd/8" "mtd/9" "mtd/10" "mtd/11")
mtdr_list=("mtdr0" "mtdr1" "mtdr2" "mtdr3" "mtdr4" "mtdr5" "mtdr6" "mtdr7" "mtdr8" "mtdr9" "mtdr10" "mtdr11")
mtd_block_list=("mtdblock0" "mtdblock1" "mtdblock2" "mtdblock3" "mtdblock3" "mtdblock4" "mtdblock5" "mtdblock6" "mtdblock7" "mtdblock8" "mtdblock9" "mtdblock10" "mtdblock11")
mtd_block_dir_list=("mtdblock/0" "mtdblock/1" "mtdblock/2" "mtdblock/3" "mtdblock/3" "mtdblock/4" "mtdblock/5" "mtdblock/6" "mtdblock/7" "mtdblock/8" "mtdblock/9" "mtdblock/10" "mtdblock/11")

file_list+=("${mtd_list[@]}")
#file_list+=("${mtd_dir_list[@]}")
file_list+=("${mtdr_list[@]}")
file_list+=("${mtd_block_list[@]}")
file_list+=("${mtd_block_dir_list[@]}")

data=$(head -c 1048576 < /dev/zero | tr '\0' '\377')

for file in "${file_list[@]}"; do
    printf "%s" "$data" > "$directory/$file"
#    /greenhouse/bash -c "printf "%01048576d" 1 | tr '0' '\377'" > "$directory/$file"
done
