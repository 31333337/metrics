# Metrics for network throughput measurements

## Overview
This script captures and logs network packet metrics using Scapy.

The main goal of this quick n dirty script is to get a basic idea how muchthroughput is needed for validator A to validator B to communicate over Trellis based mixnet and to test if they would lose blocks or not.

Running the script without any flags will default to port 26656.

## Features
- Capture packets on a specified port and IP address.
- Log metrics: Packets/s, Bits/s, Bytes/min for inbound and outbound traffic.
- Optional raw packet output.
- Save metrics to `.csv` file.
- Set a time limit for script execution.

## Requirements
- Python 3.x
- Scapy
- argparse
- elevated priveleges (we are dealing with some raw sockets, there is a way to do this without elevating privs to root but that might come later)
## Usage

### Basic Usage
```bash
sudo python3 measure_throughput.py
```

### Optional Arguments
```bash
--port: Port to monitor (default: 26656)
--ip: IP address to monitor (default: local IP)
--log_file: File to save logs (default: metrics.txt)
--csv: CSV file to save logs
-r, --raw: Output raw packet data
-t, --time: Time in seconds to run the script (default: 60)
```
### Examples

```bash
sudo python3 measure_throughput.py --port 8080 --ip 192.168.1.2 --log_file custom_metrics.txt
sudo python3 measure_throughput.py --csv metrics.csv --time 120
sudo python3 measure_throughput.py --raw
```
#### This script is to be used as is, see MIT License. I do not have any responsibility if you break your system. ;]
