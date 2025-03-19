    import pyshark
    import argparse
    import os
    from manage_list import *
    from packet_sniffer import *
    from packet_analyzer import *


    def main():
        parser = argparse.ArgumentParser()                                                                                          # Create an argument parser
        group1 = parser.add_mutually_exclusive_group(required=True)
        group1.add_argument('-l', '--live', type=str, help=""": used to capture live packets if you do not have an existing PCAP file.
                                                                interface, output path and count flags are to be used while capturing live packets.""")
        group1.add_argument('-f', '--file', type=str, help=": used to store path to an existing PCAP file.")

        parser.add_argument('-i', '--interface', type=str, help=": used to specify the interface type.")
        parser.add_argument('-o', '--output', type=str, default='capture.pcap', help=": used to specify the output of the file capture stored.")
        parser.add_argument('-c', '--count', type=int, default=100, help=": used to specify the number of packets to be stored in the PCAP file. ; Minimum value 100")
        
        parser.add_argument('action', choices=['add', 'remove', 'load'], help=": used to specify the action to perform on either the blocklist or the allowlist.")
        parser.add_argument('--ip', type=str, help=": used to specify the IP address to be added or removed to or from the list." )
        parser.add_argument('-t', '--type' , choices=['blocklist', 'allowlist'], default='blocklist', help=': used to define whether to manage the blocklist or allowlist.')

        parser.add_argument('-b', '--block', type=str, help=": used to specify the blocklist path")
        parser.add_argument('-a', '--allow', type=str, help=": used to specify the allowlist path")
        args = parser.parse_args()

        if args.action in ["add", "remove"] and not args.ip:
            print("IP not listed to be added to the list.")
            log_event("error", "IP not listed to be added to blocklist or allowlist")
            return
        
        manage_filter(args.action, args.ip, args.type)


        if args.file:
            if os.path.exists(args.file):
                print(f"File Found. Using PCAP file: {args.file}")
                pcap_file = args.file
            else:
                print("File not found")
            analyze_file(args.file)
        elif args.file and (args.block or args.allow):
            if os.path.exists(args.file):
                print(f"File Found. Using PCAP file: {args.file}")
                pcap_file = args.file
            else:
                print("File not found")
            analyze_file(args.file, args.block, args.allow)
        elif args.live:
            cap_pkt(interface=args.interface, output_path=args.output, packet_limit=args.count)
            analyze_file(args.output)
        elif args.live and (args.block or args.allow):
            cap_pkt(interface=args.interface, output_path=args.output, packet_limit=args.count)
            analyze_file(args.output, args.block, args.allow)

    if __name__ == "__main__":
        main()