import pyshark
import os
import event_logger

#ef cap_pkt(interface=None, file_path=None): 
#   if file_path:
#       capture = pyshark.FileCapture(file_path)                                        # Capture packets from a PCAP file
#       print("Sniffing Packets from File...")
#   else:
#       capture = pyshark.LiveCapture(interface=interface)                              # Capture Live Packets from the network interface
#       print("Sniffing Live Packets...")

#   for pkt in capture.sniff_continuously(packet_count=5):                              # Capture 5 packets continuously
#       print(pkt)

def cap_pkt(interface='eth0', output_path, packet_limit=100):
    
    print("Capturing live packets...")

    cap = pyshark.LiveCapture(interface=interface, output_file=output_path)
    cap.sniff_continuously(packet_count=packet_limit)
    print("Capture Complete")
    logger_setup()
    log_event(info, f"Captured Packets stored in {output_path}")
    