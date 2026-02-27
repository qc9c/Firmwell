#!/bin/sh

# remove special virtual device, and create it later
rm -f /fs/dev/null /fs/dev/random /fs/dev/urandom

# remove /tmp/shm_id, and httpd will create a new shm, EX6200_V1.0.0.46_1.1.70
rm /fs/tmp/shm_id

# get filesystem
find /fs \( -o -type s -o -type p \) -exec rm -f {} \;

# rm core dump
find /fs -type f -name '*.core' -exec rm -f {} +