from collections import defaultdict
from scapy import *
import pyshark
import os
from event_logger import logger_setup, log_event

logger_setup()

def portscan_detector(packets, file_path, max_value = 10):
    scan_counter = defaultdict(set)

    for pkt in packets:
        if hasattr(pkt, 'ip') and hasattr(pkt, 'tcp'):
            src_ip = pkt.ip.src
            dst_port = pkt.tcp.dstport
            scan_counter[src_ip].add(dst_port)
            log_event("info", f"{len(packets)} Packets in {file_path} scanned.")
        else:
            print(f"Error analyzing packet: {pkt}")
            log_event("error", f"{pkt} cannot be scanned.")
            continue
    
    for ip, ports in scan_counter.items():
        if len(ports) > max_value:
            print(f"PORT SCAN DETECTED! Possible port scan detected from {ip}, alert emailed.")
            #add to logs
            log_event("warning", f"Port Scan detected from {ip}.")
            #send email
            #ask for pretty table
        else:
            print(f"No Port Scan detected.")
            log_event("info", f"No Port Scan Detected")

def dos_detector(packets, file_path, time_window=5, max_value=100):
    request_counter = defaultdict(int)

    for pkt in packets:
        if hasattr(pkt, 'ip'):
            src_ip = pkt.ip.src
            request_counter[src_ip] +=1
            log_event("info", f"{len(packets)} Packets in {file_path} scanned.")
        else:
            print(f"Error analyzing packet: {pkt}.")
            log_event("error", f"{pkt} cannot be scanned.")
            continue
    
    for ip, count in request_counter.items():
        if count > max_value:
            print(f"DOS ATTACK DETECTED! Possible DoS Attack detected from {ip}, alert emailed.")
            #add to logs
            log_event("warning", f"Possible DoS Attack detected from {ip}.")
            #send email
            #ask for pretty table
        else:
            print(f"No DoS Attack detected.")
            log_event("info", f"No DoS Attack Detected")

def filter_ip(pkt, blocklist=None, allowlist=None):
    if hasattr(pkt, 'ip'):
        src_ip = pkt.ip.src
        if blocklist and src_ip in blocklist:
            print(f"{src_ip} is in the Blocklist.")
            log_event("warning", f"Blocked IP : {src_ip} detected.")
            return None
        if allowlist and src_ip not in allowlist:
            print(f"{src_ip} is not in the Allowlist.")
            log_event("warning", f"IP : {src_ip} not found in the Allowlist.")
            return None
        
        return pkt


def analyze_file(file_path):
    packets = rdpcap(file_path)
    portscan_detector(packets, file_path)
    dos_detector(packets, file_path)

