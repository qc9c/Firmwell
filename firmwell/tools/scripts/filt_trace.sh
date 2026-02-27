#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <input_file> <output_file>"
  exit 1
fi
input="$1"
output="$2"

mawk '
  BEGIN { FS="[][]"; OFS="\n" }
  /^Trace 0/ {
    # $2  00000480/ADDR/00000000/… 
    split($2, a, "/")
    print a[2]      #  addr
    next
  }
  { print }
' "$input" > "$output"


