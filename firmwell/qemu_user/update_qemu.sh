#!/bin/sh

chmod +x ./*
rm /qemu_user/*
cp ./* /qemu_user/
cp -r /qemu_user/* /usr/bin/
chmod +x /usr/bin/qemu*