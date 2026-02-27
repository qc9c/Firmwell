#!/bin/sh
ipcs -m | awk 'NR>3 {print $2}' | xargs -n1 ipcrm -m
ipcs -s | awk 'NR>3 {print $2}' | xargs -n1 ipcrm -s
ipcs -q | awk 'NR>3 {print $2}' | xargs -n1 ipcrm -q