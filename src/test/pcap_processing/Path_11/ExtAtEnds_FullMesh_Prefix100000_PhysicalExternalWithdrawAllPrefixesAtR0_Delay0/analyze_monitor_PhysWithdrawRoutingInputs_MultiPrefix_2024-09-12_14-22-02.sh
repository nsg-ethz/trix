#!/usr/bin/bash

# Traffic trace analyzer for Experiment monitor_PhysWithdrawRoutingInputs_MultiPrefix_2024-09-12_14-22-02

# uncompress pcap file if required
if [ ! -f "${1}" ] ; then
    gunzip "${1}.gz"
fi


# Pre-process the traffic capture to start with the first BGP Upate message and adjust timestamps accordingly
# Requires wireshark v3.6 to work! Try `sudo add-apt-repository wireshark-dev/stable && sudo apt-get update && sudo apt-get install wireshark` to install
# NOTE: this filter filters out "TCP Retransmission" packets on purpose to ensure that we don't end up finding a keepalive packet that had to be retransmitted!
TIME_OFFSET=$(tcpdump -r "${{1}}" -w - 2>/dev/null "(port 179)" | tshark -r - -Y "bgp.type != 4" -w - 2>/dev/null | tshark -r - -c1 -T fields -e frame.time_epoch 2>/dev/null)
editcap -A "${TIME_OFFSET}" -t "-${TIME_OFFSET}" "${1}" "/tmp/tmp_${TIME_OFFSET}.pcap" 

# Find the first local prober packet to each possible next-hop:
function get_fw_updates_from {
editcap -A "${1}" "/tmp/tmp_${TIME_OFFSET}.pcap" "/tmp/tmp_${TIME_OFFSET}.pcap.${1}"
# Router r5
# local iface 1: MAC(de:ad:00:cf:01:32) IP(1.128.0.21)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cf:01:32 and src 1.0.5.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r5,r6,PROBE/"
# local iface 0: MAC(de:ad:00:cf:01:31) IP(1.128.0.18)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cf:01:31 and src 1.0.5.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r5,r4,PROBE/"
# Router r7
# local iface 0: MAC(de:ad:00:d1:01:31) IP(1.128.0.26)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d1:01:31 and src 1.0.7.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r7,r6,PROBE/"
# local iface 1: MAC(de:ad:00:d1:01:32) IP(1.128.0.29)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d1:01:32 and src 1.0.7.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r7,r8,PROBE/"
# Router r10
# local iface 1: MAC(de:ad:00:d4:01:32) IP(1.128.0.38)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d4:01:32 and src 1.0.10.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r10,r9,PROBE/"
# local iface 0: MAC(de:ad:00:d4:01:31) IP(1.192.0.1)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d4:01:31 and src 1.0.10.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r10,r10_ext,PROBE/"
# Router r0
# local iface 1: MAC(de:ad:00:96:01:32) IP(1.192.0.5)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:96:01:32 and src 1.0.0.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r0,r0_ext,PROBE/"
# local iface 0: MAC(de:ad:00:96:01:31) IP(1.128.0.1)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:96:01:31 and src 1.0.0.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r0,r1,PROBE/"
# Router r8
# local iface 0: MAC(de:ad:00:d2:01:31) IP(1.128.0.30)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d2:01:31 and src 1.0.8.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r8,r7,PROBE/"
# local iface 1: MAC(de:ad:00:d2:01:32) IP(1.128.0.33)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d2:01:32 and src 1.0.8.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r8,r9,PROBE/"
# Router r4
# local iface 0: MAC(de:ad:00:ce:01:31) IP(1.128.0.14)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:ce:01:31 and src 1.0.4.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r4,r3,PROBE/"
# local iface 1: MAC(de:ad:00:ce:01:32) IP(1.128.0.17)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:ce:01:32 and src 1.0.4.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r4,r5,PROBE/"
# Router r1
# local iface 0: MAC(de:ad:00:cb:01:31) IP(1.128.0.2)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cb:01:31 and src 1.0.1.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r1,r0,PROBE/"
# local iface 1: MAC(de:ad:00:cb:01:32) IP(1.128.0.5)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cb:01:32 and src 1.0.1.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r1,r2,PROBE/"
# Router r9
# local iface 1: MAC(de:ad:00:d3:01:32) IP(1.128.0.37)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d3:01:32 and src 1.0.9.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r9,r10,PROBE/"
# local iface 0: MAC(de:ad:00:d3:01:31) IP(1.128.0.34)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d3:01:31 and src 1.0.9.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r9,r8,PROBE/"
# Router r2
# local iface 0: MAC(de:ad:00:cc:01:31) IP(1.128.0.6)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cc:01:31 and src 1.0.2.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r2,r1,PROBE/"
# local iface 1: MAC(de:ad:00:cc:01:32) IP(1.128.0.9)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cc:01:32 and src 1.0.2.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r2,r3,PROBE/"
# Router r6
# local iface 1: MAC(de:ad:00:d0:01:32) IP(1.128.0.25)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d0:01:32 and src 1.0.6.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r6,r7,PROBE/"
# local iface 0: MAC(de:ad:00:d0:01:31) IP(1.128.0.22)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:d0:01:31 and src 1.0.6.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r6,r5,PROBE/"
# Router r3
# local iface 0: MAC(de:ad:00:cd:01:31) IP(1.128.0.10)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cd:01:31 and src 1.0.3.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r3,r2,PROBE/"
# local iface 1: MAC(de:ad:00:cd:01:32) IP(1.128.0.13)
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap.${1}" "(ether src de:ad:00:cd:01:32 and src 1.0.3.6 and dst 100.0.0.1)" | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null -c1 | sed -e "s/$/,r3,r4,PROBE/"
# cleanup tmp dir
rm -f "/tmp/tmp_${TIME_OFFSET}.pcap.${1}"
} # end function get_fw_updates_from

# make sure to collect all relevant data-plane updates
for time in $(tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap" "(port 179)" | tshark -r - -Y "not bgp || bgp.type != 4" -w - 2>/dev/null | tshark -r - -T fields -e frame.time_epoch 2>/dev/null); do
    get_fw_updates_from "${time}"
done

# BGP trace:
tcpdump -w - 2>/dev/null -r "/tmp/tmp_${TIME_OFFSET}.pcap" "(port 179)" | tshark -r - -Y "not bgp || bgp.type != 4" -w - 2>/dev/null | tshark -r - -E separator=, -T fields -e frame.time_epoch -e eth.src -e eth.dst -e ip.src -e ip.dst 2>/dev/null | sed -e "s/$/,,/"  | sed -e "s/\(1\.0\.5\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r5,\3/" | sed -e "s/\(1\.0\.7\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r7,\3/" | sed -e "s/\(1\.192\.0\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r10,\3/" | sed -e "s/\(1\.192\.0\.2\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r10_ext,\3/" | sed -e "s/\(1\.0\.10\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r10,\3/" | sed -e "s/\(1\.192\.0\.5\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r0,\3/" | sed -e "s/\(1\.192\.0\.6\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r0_ext,\3/" | sed -e "s/\(1\.0\.0\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r0,\3/" | sed -e "s/\(1\.0\.8\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r8,\3/" | sed -e "s/\(1\.0\.4\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r4,\3/" | sed -e "s/\(1\.0\.1\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r1,\3/" | sed -e "s/\(1\.0\.9\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r9,\3/" | sed -e "s/\(1\.0\.2\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r2,\3/" | sed -e "s/\(1\.0\.6\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r6,\3/" | sed -e "s/\(1\.0\.3\.1\),\([^,.]\+\.[^,.]\+\.[^,.]\+\.[^,.]\+\),,\([^,]*\)$/\1,\2,r3,\3/"  | sed -e "s/\(1\.0\.5\.1\),\([^,]*\),$/\1,\2,r5/" | sed -e "s/\(1\.0\.7\.1\),\([^,]*\),$/\1,\2,r7/" | sed -e "s/\(1\.192\.0\.1\),\([^,]*\),$/\1,\2,r10/" | sed -e "s/\(1\.192\.0\.2\),\([^,]*\),$/\1,\2,r10_ext/" | sed -e "s/\(1\.0\.10\.1\),\([^,]*\),$/\1,\2,r10/" | sed -e "s/\(1\.192\.0\.5\),\([^,]*\),$/\1,\2,r0/" | sed -e "s/\(1\.192\.0\.6\),\([^,]*\),$/\1,\2,r0_ext/" | sed -e "s/\(1\.0\.0\.1\),\([^,]*\),$/\1,\2,r0/" | sed -e "s/\(1\.0\.8\.1\),\([^,]*\),$/\1,\2,r8/" | sed -e "s/\(1\.0\.4\.1\),\([^,]*\),$/\1,\2,r4/" | sed -e "s/\(1\.0\.1\.1\),\([^,]*\),$/\1,\2,r1/" | sed -e "s/\(1\.0\.9\.1\),\([^,]*\),$/\1,\2,r9/" | sed -e "s/\(1\.0\.2\.1\),\([^,]*\),$/\1,\2,r2/" | sed -e "s/\(1\.0\.6\.1\),\([^,]*\),$/\1,\2,r6/" | sed -e "s/\(1\.0\.3\.1\),\([^,]*\),$/\1,\2,r3/" | sed -e "s/$/,BGP/"

# cleanup tmp dir
rm "/tmp/tmp_${TIME_OFFSET}.pcap"

# compress pcap file to save disk space
gzip "${1}"
