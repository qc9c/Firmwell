#!/bin/bash


ip link add br0 type bridge
ip link set br0 up
ip link set eth2 master br0


ip addr add 192.168.0.1/24 dev br0
ip addr add fe80::2de:faff:fe1a:100/64 dev br0


ip link set eth2 up


ip link add link eth2 name eth2.1 type vlan id 1
ip link set eth2.1 up
ip link set eth2.1 master br0


ip link add link eth2 name eth2.2 type vlan id 2
ip link set eth2.2 up
ip addr add fe80::2de:faff:fe3a:100/64 dev eth2.2


echo "--- Network Configuration ---"
ip addr show
ip link show
bridge link

