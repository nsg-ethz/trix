#!/usr/bin/env python3

# TRIX: Inference of Transient Violation Times from Logged Routing Events or Collected BGP Messages
# Copyright (C) 2024-2025 Roland Schmid <roschmi@ethz.ch> and Tibor Schneider <sctibor@ethz.ch>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import psutil
import argparse
import time
import os
from datetime import datetime
import csv


def read_control(control_file):
    """Read the control file and return its integer content (1 or 0)."""
    try:
        with open(control_file, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def monitor_all_processes(
    interval, control_file, router_id, router_name="", output_file=None
):
    """Monitor all processes. Data collection continues until control_file contains something else than a 1."""
    data_log = []

    # wait before starting the measurements
    while read_control(control_file) != 1:
        time.sleep(interval)

    attrs = [
        "pid",
        "name",
        "exe",
        "cpu_percent",
        "memory_percent",
        "num_threads",
        "nice",
        "num_fds",
        "open_files",
    ]
    headers = ["rid", "router_name", "timestamp"] + attrs

    cont = True
    while cont:
        for proc in psutil.process_iter(attrs):
            timestamp = datetime.utcnow().timestamp()
            row = (router_id, router_name, timestamp) + tuple(
                proc.info[attr] for attr in attrs
            )
            data_log.append(row)

            time.sleep(interval)
            cont = read_control(control_file) == 1
            if not cont:
                break

    if output_file:
        # Write the collected data to a CSV file
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            for entry in data_log:
                writer.writerow(entry)
    else:
        print(",".join(headers))
        for entry in data_log:
            print(",".join([str(x) for x in entry]))


def monitor_bgp_cpu(
    interval, control_file, router_id, router_name="", output_file=None
):
    """Monitor system and the processes relevant for BGP workloads for CPU usage and log results to a file. Data collection continues until control_file contains something else than a 1."""
    data_log = []

    # find the BGP process
    for bgp_process in psutil.process_iter():
        if bgp_process.name() == "bgp":
            break
    if not bgp_process:
        print("BGP process not found.")
        return

    # find the ipfib process
    for ipfib_process in psutil.process_iter():
        if ipfib_process.name() == "ipfib":
            break
    if not ipfib_process:
        print("'ipfib' process not found.")
        return

    # find the urib process
    for urib_process in psutil.process_iter():
        if urib_process.name() == "urib":
            break
    if not urib_process:
        print("'urib' process not found.")
        return

    # wait before starting the measurements
    while read_control(control_file) != 1:
        time.sleep(interval)

    # reset counters
    last_cpu = psutil.cpu_percent(percpu=True)
    last_bgp_cpu = bgp_process.cpu_percent()
    last_ipfib_cpu = ipfib_process.cpu_percent()
    last_urib_cpu = urib_process.cpu_percent()

    # get number of CPUs to define columns dynamically
    num_cpus = len(last_cpu)
    cpu_columns = [f"cpu{i+1}" for i in range(num_cpus)]  # e.g., cpu1, cpu2, ..., cpuX
    headers = ["rid", "router_name", "timestamp", "cpu"] + cpu_columns + ["bgp_cpu", "ipfib_cpu", "urib_cpu"]

    while read_control(control_file) == 1:
        # collect data
        timestamp = datetime.utcnow().timestamp()
        system_cpu_percent = psutil.cpu_percent(percpu=True)
        bgp_process_cpu_percent = bgp_process.cpu_percent()
        ipfib_process_cpu_percent = ipfib_process.cpu_percent()
        urib_process_cpu_percent = urib_process.cpu_percent()

        total_cpu_percent = sum(system_cpu_percent)

        # store data
        data_log.append(
            (
                router_id,
                router_name,
                timestamp,
                total_cpu_percent,
                *system_cpu_percent,
                bgp_process_cpu_percent,
                ipfib_process_cpu_percent,
                urib_process_cpu_percent,
            )
        )

        # sleep for the specified interval
        time.sleep(interval)

    if output_file:
        # Write the collected data to a CSV file
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            for entry in data_log:
                writer.writerow(entry)
    else:
        print(",".join(headers))
        for entry in data_log:
            print(",".join([str(x) for x in entry]))


def main():
    parser = argparse.ArgumentParser(
        description="Monitor CPU usage of the BGP process."
    )
    parser.add_argument(
        "-r",
        "--router-id",
        type=int,
        required=True,
        help="RouterId of the monitored router.",
    )
    parser.add_argument(
        "-n",
        "--router-name",
        type=str,
        default="",
        help="Router name of the monitored router.",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=0.01,
        help="Time interval between measurements in seconds (default: 0.01)",
    )
    parser.add_argument(
        "-c",
        "--control-file",
        type=str,
        default=".router_lab_cpu_monitor_control",
        help="Path to the control file (default: .router_lab_cpu_monitor_control)",
    )
    parser.add_argument(
        "--std-out",
        action="store_true",
        help="Print results to stdout instead of writing to a file.",
    )
    parser.add_argument(
        "--all-processes", action="store_true", help="Get CPU usage of all processes."
    )
    args = parser.parse_args()

    if args.std_out:
        output_file = None
    else:
        # prepare output file path based on current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file = f"cpu_log/cpu_log_{timestamp}.csv"

    if args.all_processes:
        monitor_all_processes(
            args.interval,
            args.control_file,
            args.router_id,
            args.router_name,
            output_file,
        )
    else:
        # start basic CPU monitoring
        monitor_bgp_cpu(
            args.interval,
            args.control_file,
            args.router_id,
            args.router_name,
            output_file,
        )


if __name__ == "__main__":
    main()
