import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP 
from typing import DefaultDict, Set


THRESHOLD = 100  # Number of packets


def packet_call(packet):
    if IP in packet:
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1
        current_time = time.time()
        time_interval = current_time - start_time[src_ip]
    
        if packet_counts[src_ip] >= 1:
            for ip, count in packet_counts.items():
                packet_rate = count / time_interval

                if packet_rate > THRESHOLD and ip not in blocked_ips:
                    blocked_ips.add(ip)
                    print(f"[ALERT] Blocking IP: {ip} | Packet Rate: {packet_rate:.2f} packets/sec")
                    os.system(f"iptables -A INPUT -s {ip} -j DROP")
        
        packet_counts.clear()
        start_time[src_ip] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run as root.")
        sys.exit(1)
    packet_counts: DefaultDict[str, int] = defaultdict(int)
    start_time: DefaultDict[str, float] = defaultdict(time.time)
    blocked_ips: Set[str] = set()
    print("Starting DoS Blocker... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=packet_call, store=0)
    print("DoS Blocker stopped.")
    