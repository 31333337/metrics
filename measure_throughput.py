import logging
import threading
from scapy.all import sniff

# Initialize logging
logging.basicConfig(filename='metrics.txt', level=logging.INFO)

# Initialize global variables
packets_per_second = 0
bits_per_second = 0
bytes_per_minute = 0

def packet_callback(pkt):
    global packets_per_second, bits_per_second, bytes_per_minute
    packets_per_second += 1
    bits_per_second += len(pkt) * 8
    bytes_per_minute += len(pkt)

def report_metrics():
    global packets_per_second, bits_per_second, bytes_per_minute
    while True:
        log_data = f"Packets/s: {packets_per_second}, Bits/s: {bits_per_second}, Bytes/min: {bytes_per_minute}"
        print(log_data)
        logging.info(log_data)
        packets_per_second = 0
        bits_per_second = 0
        bytes_per_minute = 0
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








































