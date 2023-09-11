import logging
import threading
import socket
from scapy.all import sniff

# Initialize logging
logging.basicConfig(filename='metrics.txt', level=logging.INFO)

# Initialize global variables
in_packets_per_second = 0
out_packets_per_second = 0
in_bits_per_second = 0
out_bits_per_second = 0
in_bytes_per_minute = 0
out_bytes_per_minute = 0

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
local_ip = s.getsockname()[0]
s.close()

def packet_callback(pkt):
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

def report_metrics():
    global in_packets_per_second, out_packets_per_second
    global in_bits_per_second, out_bits_per_second
    global in_bytes_per_minute, out_bytes_per_minute

    while True:
        log_data = f"Inbound - Packets/s: {in_packets_per_second}, Bits/s: {in_bits_per_second}, Bytes/min: {in_bytes_per_minute} | " \
                   f"Outbound - Packets/s: {out_packets_per_second}, Bits/s: {out_bits_per_second}, Bytes/min: {out_bytes_per_minute}"
        
        print(log_data)
        logging.info(log_data)
        
        # Reset counters
        in_packets_per_second = 0
        out_packets_per_second = 0
        in_bits_per_second = 0
        out_bits_per_second = 0
        in_bytes_per_minute = 0
        out_bytes_per_minute = 0

        threading.Event().wait(2)

if __name__ == "__main__":
    try:
        # Start the reporting thread
        report_thread = threading.Thread(target=report_metrics)
        report_thread.daemon = True
        report_thread.start()

        # Start packet sniffing
        sniff(filter="tcp port 26656", prn=packet_callback)
    except KeyboardInterrupt:
        logging.info("Stopping packet capture.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")


















































































