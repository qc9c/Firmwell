#!/bin/bash

while true; do
#    kill -9 $(ps aux | grep 'hotplug' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'net-scan' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'mount_root' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'acld' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'acsd' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'signalc' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'uclited' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'uci_apply_defaults' | grep -v 'grep' | awk '{print $2}') 2>/dev/null


#    kill -9 $(ps aux | grep 'sleep 240' | grep -v 'grep' | awk '{print $2}') 2>/dev/null
#    kill -9 $(ps aux | grep 'xagent' | grep -v 'grep' | awk '{print $2}') 2>/dev/null

  ps aux | awk '/hotplug/ || /net-scan/ || /mount_root/ || /acld/ || /acsd/ || /signalc/ || /uclited/ || /uci_apply_defaults/ || /S50optic.sh/ || /set_hw_nvram/ || /S10boot/ || /S02boot/ || /mktemp/ && !/awk/ {system("kill -9 " $2)}' 2>/dev/null

  sleep 20
done

#|| /<defunct>/
# /S50optic.sh tenda/US_G103V1.0la_V1.0.0.2_EN_TDE01.rar

# set_hw_nvram.sh JWNR2000_Firmware_Version_1.0.0.5_for_users_outside_North_America_only_.zip
