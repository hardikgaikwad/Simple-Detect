import pyshark
import os
from event_logger import logger_setup, log_event

logger_setup()

def cap_pkt(interface='eth0', output_path="/", packet_limit=100):
    
    print("Capturing live packets...")

    cap = pyshark.LiveCapture(interface=interface, output_file=output_path)
    cap.sniff_continuously(packet_count=packet_limit)
    print("Capture Complete")
    
    log_event("info", f"Captured Packets stored in {output_path}")
    