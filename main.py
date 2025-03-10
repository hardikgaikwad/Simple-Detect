import pyshark
import argparse
from packet_sniffer import cap_pkt

parser = argparse.Argumentparser()
group_pk_snfr = parser.add_mutually_exclusive_group(required=True)
group_pk_snfr.add_argument('-l', '--live', type=str, help="It is used to initiate Live Capture of the packets")
group_pk_snfr.add_argument('-p', '--pcap', type=str, help="It is used to read from the PCAP files")
args = parser.parse_args()

cap_pkt(args.live, args.pcap)