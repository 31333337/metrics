from scapy.all import sniff
import time

packets_per_second = 0
bits_per_second = 0
bytes_per_minute = 0

def packet_callback(pkt):
    global packets_per_second, bits_per_second, bytes_per_minute
    packets_per_second += 1
    bits_per_second += len(pkt) * 8
    bytes_per_minute += len(pkt)

if __name__ == "__main__":
    sniff(filter="tcp port 26656", prn=packet_callback)

