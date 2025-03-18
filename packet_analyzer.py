from collections import defaultdict
import scapy
import os 

logger_setup()

def portscan_detector(packets, max_value = 10):
    scan_counter = defaultdict(set)

    for pkt in packets:
        if hasattr(pkt, 'ip') and hasattr(pkt, 'tcp'):
            src_ip = pkt.ip.src
            dst_port = pkt.tcp.dstport
            scan_counter[src_ip].add(dst_port)
            log_event(info, f"{len(packets)} Packets in {file_path} scanned.")
        else:
            print(f"Error analyzing packet: {pkt}")
            log_event(error, f"{pkt} cannot be scanned.")
            continue
    
    for ip, ports in scan_counter.items():
        if len(ports) > max_value:
            print(f"PORT SCAN DETECTED! Possible port scan detected from {ip}, alert emailed.")
            #add to logs
            log_event(warning, f"Port Scan detected from {ip}.")
            #send email
            #ask for pretty table

def dos_detector(packets, time_window=5, max_value=100):
    request_counter = defaultdict(int)

    for pkt in packets:
        if hasattr(pkt, 'ip'):
            src_ip = pkt.ip.src
            request_counter[src_ip] +=1
            log_event(info, f"{len(packets)} Packets in {file_path} scanned.")
        else:
            print(f"Error analyzing packet: {pkt}.")
            log_event(error, f"{pkt} cannot be scanned.")
            continue
    
    for ip, count in request_counter.items():
        if count > max_value:
            print(f"DOS ATTACK DETECTED! Possible DoS Attack detected from {ip}, alert emailed.")
            #add to logs
            log_event(warning, f"Possible DoS Attack detected from {ip}.")
            #send email
            #ask for pretty table







def analyze_file(file_path):
    packets = rdpcap(file_path)
    portscan_detector(packets)
    dos_detector(packets)

