#!/usr/bin/bash


sudo firewall-cmd --add-port=5201/tcp
sudo firewall-cmd --add-port=5201/udp
iperf3 --server --bind 192.33.88.221 --daemon
