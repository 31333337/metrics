import time
import logging
import threading
import socket
from scapy.all import sniff
import argparse
import csv
# Initialize logging
logging.basicConfig(filename='metrics.txt', level=logging.INFO)

# Initialize global variables
in_packets_per_second = 0
out_packets_per_second = 0
in_bits_per_second = 0
out_bits_per_second = 0
in_bytes_per_minute = 0
out_bytes_per_minute = 0

# get ip
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
local_ip = s.getsockname()[0]
s.close()

# Allow output as .csv 
csv_file = None
csv_writer = None

# Argument parsing
parser = argparse.ArgumentParser(description='Packet metrics capture.')
parser.add_argument('--port', type=int, default=26656, help='Port to monitor')
parser.add_argument('--ip', type=str, default=local_ip, help='IP address to monitor (localhost or public)')
parser.add_argument('--log_file', type=str, default='metrics.txt', help='File to save logs')
parser.add_argument('-r', '--raw', action='store_true', help='Output raw packet data')
parser.add_argument('--csv', type=str, help='CSV file to save logs')
parser.add_argument('-t', '--time', type=int, default=60, help='Time in seconds to run the script')

args = parser.parse_args()

# Initialize logging with user-specified or default file
logging.basicConfig(filename=args.log_file, level=logging.INFO)

# ...

if args.csv:
    csv_file = open(args.csv, 'w', newline='')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['Time', 'Inbound Packets/s', 'Inbound Bits/s', 'Inbound Bytes/min', 'Outbound Packets/s', 'Outbound Bits/s', 'Outbound Bytes/min'])

def report_metrics():
    global in_packets_per_second, out_packets_per_second
    global in_bits_per_second, out_bits_per_second
    global in_bytes_per_minute, out_bytes_per_minute
    global csv_writer
    global csv_writer
    start_time = time.time()

    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > args.time:
            break

        log_data = [elapsed_time, in_packets_per_second, in_bits_per_second, in_bytes_per_minute, out_packets_per_second, out_bits_per_second, out_bytes_per_minute]
        
        # CSV Writing
        if csv_writer:
            csv_writer.writerow(log_data)
            csv_file.flush()

        # Logging and Printing
        log_str = f"Inbound - Packets/s: {in_packets_per_second}, Bits/s: {in_bits_per_second}, Bytes/min: {in_bytes_per_minute} | " \
                  f"Outbound - Packets/s: {out_packets_per_second}, Bits/s: {out_bits_per_second}, Bytes/min: {out_bytes_per_minute}"

        print(log_str)
        logging.info(log_str)

        # Reset counters
        in_packets_per_second = 0
        out_packets_per_second = 0
        in_bits_per_second = 0
        out_bits_per_second = 0
        in_bytes_per_minute = 0
        out_bytes_per_minute = 0

        threading.Event().wait(2)

    if csv_file:
        csv_file.close()

def packet_callback(pkt):
    global in_packets_per_second, out_packets_per_second
    global in_bits_per_second, out_bits_per_second
    global in_bytes_per_minute, out_bytes_per_minute

    if args.raw:
        print(pkt)  # or another representation of the raw packet
        print(f"Captured packet: {pkt.summary()}")
 
    global in_packets_per_second, out_packets_per_second
    global in_bits_per_second, out_bits_per_second
    global in_bytes_per_minute, out_bytes_per_minute

    if 'IP' in pkt:
        if pkt['IP'].src == local_ip:
            out_packets_per_second += 1
            out_bits_per_second += len(pkt) * 8
            out_bytes_per_minute += len(pkt)
        elif pkt['IP'].dst == local_ip:
            in_packets_per_second += 1
            in_bits_per_second += len(pkt) * 8
            in_bytes_per_minute += len(pkt)

if __name__ == "__main__":
    try:
        report_thread = threading.Thread(target=report_metrics)
        report_thread.daemon = True
        report_thread.start()

        sniff(filter=f"tcp port {args.port} and host {args.ip}", prn=packet_callback, timeout=args.time)

    except KeyboardInterrupt:
        print("Stopping packet capture.")
    except Exception as e:
        print(f"An error occurred: {e}")

