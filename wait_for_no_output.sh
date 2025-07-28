#!/usr/bin/env bash

while read -t 1 line; do echo -n ""; done < <(sudo tcpdump -i enp132s0f1 "port 179 and len > 85" 2>/dev/null)

echo "Convergence done."
exit 0
