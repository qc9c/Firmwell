#!/bin/bash

# delete all net dev with br-xxx
network_cards=$(ip link show | grep -o "^.*br-[^:]*")

for card in $network_cards; do
    ip link delete $card
    echo "Deleted network card: $card"
done

network_cards=$(ip link show | grep -o "^.*veth[^:]*")

for card in $network_cards; do
    ip link delete $card
    echo "Deleted network card: $card"
done

echo "All br- and veth network cards have been deleted."