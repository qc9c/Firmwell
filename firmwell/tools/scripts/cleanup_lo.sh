#!/bin/bash

IFS=$'\n'

ORPHANS=`losetup | grep FirmAE | awk '{print $1}'`

for ORPH in $ORPHANS
do
	losetup -d $ORPH
done