# Transient Network Analyzer

### Quick start: how to run the analyzer experiments
```
# Rust dependencies
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# login new
rustup toolchain update stable
# install the gcc compiler
sudo apt-get update
sudo apt-get install build-essential python3-pip
python3 -m pip install pandas plotly

# now log in to each device (server, tofino, router) at least once to ensure
# there are no "unknown host" issues preventing automated ssh connections

# also, make sure that:
# - the delayers are running on the server
# - the pfring kernel module is installed on the server
# - tcpdump_pfring can be called on the server for collecting data
# - the Tofino has the kdrv kernel module loaded
# - the Tofino is running the simple_router.p4 program

# collect data
cargo run --release --bin collect_hw_data -- -d ./data/ -s FullMesh_Prefix1 -v Prefix1_ -v 00000 -v Delay -n10

# old processing pipeline
#RAYON_NUM_THREADS=30 cargo run --bin process_pcaps --release --features incremental all-fw-properties -- -d ./data/
#RAYON_NUM_THREADS=30 cargo run --bin process_pcaps --release --no-default-features -- -d ./data/ -x plots_randomized10/

# ground truth extraction
RAYON_NUM_THREADS=30 cargo run --bin new_prober_analysis --release -- -d ./data/
# bgp parsing + queuing model + visualize single sample
RAYON_NUM_THREADS=30 cargo run --bin extract_bgp_updates --release -- -d ./data/

# evaluate with the baseline and interval algorithm
RAYON_NUM_THREADS=30 cargo run --bin evaluate --release -- -d ./data/
# create plots
python3 visualize_accuracy.py data/Abilene --template eval-accuracy
```
The absolute error of the data is then plotted to `./data/Abilene/eval_abs.html`.

# Miscellaneous

### Packet capture performance

If you encounter large packet losses from using the traffic_monitor of the router-lab, consider changing the capture command.
For example, a suitable choice could be tcpdump with the `pf_ring` kernel module.
To install, we followed the instructions from [here](https://satishdotpatel.github.io/maximizing-packet-capture-performance-with-tcpdump/https://satishdotpatel.github.io/maximizing-packet-capture-performance-with-tcpdump/):

```
git clone https://github.com/ntop/PF_RING.git
cd PF_RING
```

Prerequisite ( make sure you download same kernel-source tree which you are running)

```
sudo apt-get install bison flex elfutils gcc
```

Compile PF_Ring

```
cd PF_RING
make
sudo make -C kernel install
sudo make -C userland/lib install
```

Compile Tcpdump

```
cd userland
make all
make tcpdump/Makefile
make build_tcpdump
```

copy new tcpdump binary to system PATH with differnet name.

```
sudo cp tcpdump/tcpdump /usr/local/sbin/tcpdump_pfring
```

Compare older tcpdump and newer tcpdump

```
# /usr/sbin/tcpdump --version
tcpdump version 4.9.2
libpcap version 1.5.3
OpenSSL 1.0.2k-fips  26 Jan 2017
```
 
```
# /usr/local/sbin/tcpdump_pfring --version
tcpdump_pfring version 4.9.3
libpcap version 1.9.1 (with TPACKET_V3)
```

Load pf_ring kernel module

```
sudo insmod PF_RING/kernel/pf_ring.ko
```

Verify module is loaded

```
# lsmod | grep pf_ring
pf_ring               196608  0
```

```
# cat /proc/net/pf_ring/info
PF_RING Version          : 8.5.0 (dev:f5fa74892c178bb75a9abc52765e87a6837ffea8)
Total rings              : 0
 
Standard (non ZC) Options
Ring slots               : 4096
Slot version             : 17
Capture TX               : Yes [RX+TX]
IP Defragment            : No
Socket Mode              : Standard
Cluster Fragment Queue   : 0
Cluster Fragment Discard : 0
```

Finally, you can observe that captures did not yield any losses by logging the output of stderr using `2>/path/to/log/file.log`. To check if there was ever packet loss, use:
```
cat /path/to/log/file.log | grep "packets dropped" | grep -v "^0"
```

### Transferring files to the routers (if SCP doesn't work for some reason)

When trying to push the `cpu-monitor.py` file to the cisco routers, we ran into a problem that the scp client simply reported "connection has been closed".
As a workaround, one can execute the following:
```
cat cpu-monitor.py | ssh -T user@cisco-router "run bash cat > cpu-monitor.py"
```
