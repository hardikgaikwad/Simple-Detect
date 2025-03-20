    import pyshark
    import argparse
    import os
    from manage_list import *
    from packet_sniffer import *
    from packet_analyzer import *


    def main():
        parser = argparse.ArgumentParser()

        group1 = parser.add_mutually_exclusive_group(required=True)
        group1.add_argument('-l', '--live', type=str, help="Capture live packets. Requires -i (interface).")
        group1.add_argument('-f', '--file', type=str, help="Use an existing PCAP file for analysis.")

        parser.add_argument('-i', '--interface', type=str, help="Specify the network interface.")
        parser.add_argument('-o', '--output', type=str, default='capture.pcap', help="Output file for captured packets.")
        parser.add_argument('-c', '--count', type=int, default=100, help="Number of packets to capture (min 100).")
        
        parser.add_argument('action', choices=['add', 'remove', 'load'], help="Manage blocklist/allowlist.")
        parser.add_argument('--ip', type=str, help="IP address to add/remove." )
        parser.add_argument('-t', '--type' , choices=['blocklist', 'allowlist'], default='blocklist', help='List type.')

        parser.add_argument('-b', '--block', type=str, help="Path to blocklist.")
        parser.add_argument('-a', '--allow', type=str, help="Path to allowlist.")


        args = parser.parse_args()

        if args.action in ["add", "remove"] and not args.ip:
            print("IP address required for adding/removing.")
            log_event("error", "IP address required for blocklist/allowlist modification.")
            return
        
        manage_filter(args.action, args.ip, args.type)

        if args.file:
            if not os.path.exists(args.file):
                print(f"File {args.file} not found.")
                log_event("error", "File {args.file} not found.")
                return

            print(f"Using PCAP file: {args.file}")
            analyze_file(args.file, args.block, args.allow)

        elif args.live:
            if not args.interface:
                print("Network interface required for live capture.")
                log_event("error", "Interface required for live capture")
                return
            
            cap_pkt(interface=args.interface, output_path=args.output, packet_limit=args.count)
            analyze_file(args.output, args.block, args.allow)

    if __name__ == "__main__":
        main()