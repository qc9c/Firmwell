#!/bin/sh

while true; do
  process_count=$(ps -e | wc -l)
  if [ "$process_count" -gt 500 ]; then
      touch /fs/fork_bomb
      kill -9 -1
  fi
#  ps -eo pid,pcpu --sort=-pcpu | awk 'NR>1 {if ($1 != 1 && $2 > 50.0) print $1}' | xargs -r kill # kill process if cpu > 50%
  sleep 10

  # Kill processes containing "/bin/sh -c . /lib/functions.sh"， docker OOM
#  pids=$(ps -eo pid,args | awk '{
#    if ($0 ~ "/bin/sh -c . /lib/functions.sh") {
#      print $1
#    }
#  }')
#  if [ -n "$pids" ]; then
#    kill -9 $pids
#  fi

    # Kill processes containing "/bin/sh -c . /lib/functions.sh"， docker OOM, R6700v3_V1.0.3.66_10.0.50
  pids=$(ps -eo pid,args | awk '{
    if ($0 ~ "check_db") {
      print $1
    }
  }')
  if [ -n "$pids" ]; then
    kill -9 $pids
  fi

  # if multi process with same name, kill
  ps -eo args | tail -n +2 | sort | uniq -c | while read -r count cmdline; do
      if [ "$count" -gt 5 ]; then
          pids=$(ps -eo pid,args | awk -v target="$cmdline" '{
              full = substr($0, index($0,$2))
              if (full == target)
                  print $1
          }')
          if [ -n "$pids" ]; then
              kill -9 $pids
          fi
      fi
  done

done