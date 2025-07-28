#!/usr/bin/bash

sudo killall -9 exabgp 2>/dev/null
ps aux | grep "python3 \/local\/home\/roschmi\/.router-lab_run_exabgp\.py" | awk '{print $2}' | sudo xargs kill -9 2>/dev/null
