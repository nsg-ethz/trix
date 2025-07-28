#!/bin/bash
sudo ip netns add iperf_client
sudo ip link set dev enp5s0f2 netns iperf_client
sudo ip netns exec iperf_client ip link set dev enp5s0f2 up
sudo ip netns exec iperf_client ip addr add dev enp5s0f2 192.33.88.222/24
sudo ip netns exec iperf_client ping -c 5 192.33.88.221
sudo ip netns exec iperf_client iperf3 --udp --length 550 --bitrate 1G --time 0 --client 192.33.88.221
