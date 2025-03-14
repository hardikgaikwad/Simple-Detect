import pyshark
import argparse
import os
from packet_sniffer import cap_pkt


def main():
    parser = argparse.Argumentparser()                                                                                          # Create an argument parser
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-l', '--live', type=str, help=""": used to capture live packets if you do not have an existing PCAP file.
                                                            interface, output path and count flags are to be used while capturing live packets.""")
    group1.add_argument('-f', '--file', type=str, help=": used to store path to an existing PCAP file.")

    parser.add_argument('-i', '--interface', type=str, help="It is used to specify the interface type")
    parser.add_argument('-o', '--output', type=str, default='capture.pcap', help="It is the output of the file capture stored")
    parser.add_argument('-c', '--count', type=int, default=10, help="It is the number of packets to be stored in the PCAP file")
    args = parser.parse_args()


    if args.file:
        if os.path.exists(args.file):
            print(f"File Found. Using PCAP file: {args.file}")
            pcap_file = args.file
        else:
            print("File not found")
    elif args.live:
        cap_pkt(interface=args.interface, output_path=args.output, packet_limit=args.count))

if __name__ == "__main__":
    main()