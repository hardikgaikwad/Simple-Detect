import pyshark

def cap_pkt(interface=None, file_path=None):
    if file_path:
        capture = pyshark.FileCapture(file_path)
        print("Sniffing Packets from File...")
    else:
        capture = pyshark.LiveCapture(interface=interface)
        print("Sniffing Live Packets...")

    for pkt in capture.sniff_continuously(packet_count=5):
        print(pkt)
    