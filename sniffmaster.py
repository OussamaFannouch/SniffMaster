#!/usr/bin/env python3
import socket
from threading import *
import struct
import sys
import argparse
from ethernet_tools import EthernetFrame, IPV4, UDP, TCP, hexdump
from colors import *
from collections import defaultdict
import time


scan_threshold = 20
syn_pair_count = defaultdict(int)

def menu():
    print(
        "           _        _                                                                                        \n"
        "          /\\     ,'/|                                                                                       \n"
        "        _|  |\\-'-'_/_/                                                                                      \n"
        "   __--'/`           \\       ███████╗███╗   ██╗██╗███████╗███████╗███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ \n"
        "       /              \\      ██╔════╝████╗  ██║██║██╔════╝██╔════╝████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
        "      /        \"o.  |o\"|     ███████╗██╔██╗ ██║██║█████╗  █████╗  ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝\n"
        "      |              \\/                                   made by FANNOUCH OUSSAMA(D1B)                                                \n"
        "       \\_          ___\\      ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗\n"
        "         `--._`.   \\;//      ███████║██║ ╚████║██║██║     ██║     ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║\n"
        "              ;-.___,`       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
        "             /                                                                                                   \n"
        "           ,'                                                                                                     \n"
        "        _                                                                                                         \n"
        "Welcome to SNIFFMASTER tool, how can we help you today?:\n"
        "1- start sniffing\n"
        "2- filter\n"
        "3- exit\n"
        )
    choice = input("Choice:")
    return int(choice)


def get_args():
    parser = argparse.ArgumentParser(description="A simple network sniffer")
    parser.add_argument('interface', help="Network interface to sniff on")
    parser.add_argument('-f', '--filter', help="Filter by IP, port, or HTTP request, exemple of usage: ./mysnifer.py <interface > -f port:80", nargs='?')
    return parser.parse_args()

def detect_nmap(src_ip,dst_ip):
    pair = (src_ip, dst_ip)
    syn_pair_count[pair] += 1
    if syn_pair_count[pair] > scan_threshold:
        readable_src_ip = socket.inet_ntoa(src_ip)
        readable_dst_ip = socket.inet_ntoa(dst_ip)
        print(red(f"Possible Nmap scan detected from {readable_src_ip}"))



def reset_counts():
    """Reset SYN counts periodically."""
    while True:
        time.sleep(scan_time_window)
        syn_pair_count.clear()






def packet_handler(raw_data, filter_type, filter_value):
        # Ethernet
        frame = EthernetFrame(raw_data)
        print(beige(str(frame)))

# with filter option        
        if frame.ETHER_TYPE == IPV4.ID:
            ipv4 = IPV4(frame.PAYLOAD)
            if ipv4.PROTOCOL == TCP.ID and ipv4.PAYLOAD[13] == 0x02:  # Check if it's a SYN packet
                detect_nmap(ipv4.SOURCE,ipv4.DESTINATION)  # Call the Nmap detection logic
            if filter_type == 'ip':
                if filter_value == ipv4.SOURCE or filter_value == ipv4.DESTINATION:
                    print(violet("└─ " + str(ipv4)))
            elif filter_type == 'port':
                if ipv4.PROTOCOL == UDP.ID:
                    udp = UDP(ipv4.PAYLOAD)
                    if int(filter_value) == udp.SOURCE_PORT or int(filter_value) == udp.DEST_PORT:
                        print(yellow("   └─ " + str(udp)))
                        print(yellow(hexdump(udp.PAYLOAD, 5)))
                elif ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    if int(filter_value)== tcp.SOURCE_PORT or int(filter_value) == tcp.DEST_PORT:
                        print(green_light("   └─ " + str(tcp)))
                        print(green_light(hexdump(tcp.PAYLOAD, 5)))
            elif filter_type == 'http':
                if ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    if tcp.SOURCE_PORT == 80 or tcp.DEST_PORT == 80:
                        if b'GET' in tcp.PAYLOAD or b'POST' in tcp.PAYLOAD:
                            print(green_light("   └─ " + str(tcp)))
                            print(green_light(hexdump(tcp.PAYLOAD, 5)))
            elif filter_type == 'flag':
                if ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    if filter_value in tcp.FLAGS:
                        print(green_light("   └─ " + str(tcp)))
                        print(green_light(hexdump(tcp.PAYLOAD, 5)))
#            without filter option
            else:
            # UDP
                ipv4 = IPV4(frame.PAYLOAD)
                if ipv4.PROTOCOL == UDP.ID:
                    udp = UDP(ipv4.PAYLOAD)
                    print(yellow("   └─ " + str(udp)))
                    print(yellow(hexdump(udp.PAYLOAD, 5)))
            # TCP
                if ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    print(green_light("   └─ " + str(tcp)))
                    print(green_light(hexdump(tcp.PAYLOAD, 5)))
    

def main(interface,filters_type,filters_value):
    ETH_P_ALL = 0x03 # Listen for everything
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((interface,0))
    while True:
        raw_data, addr = s.recvfrom(65565)
        packet_handler(raw_data, filter_type, filter_value)


if __name__ == "__main__":
    args = get_args()

    if args.filter:
        try:
            if ':' in args.filter:
                filter_type, filter_value = args.filter.split(':')
            elif args.filter.lower() == 'http':
                filter_type, filter_value = 'http', None
            else:
                raise ValueError("Invalid filter format. Use 'ip:<value>', 'port:<value>', flag:<value> , or 'http'.")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        filter_type, filter_value = None, None

    if filter_type == 'port' and filter_value is None:
        print("Error: Port filter requires a port number.")
        sys.exit(1)
    elif filter_type == 'ip' and filter_value is None:
        print("Error: IP filter requires an ip.")
        sys.exit(1)
    elif filter_type == 'flag' and filter_value is None:
        print("Error: FLAG filter requires a flag.")
        sys.exit(1)

    try:
        choice = int(menu())
        if (filter_type == None) and (filter_value == None):
            if choice == 1:
                main(args.interface, filter_type, filter_value)
            elif choice == 2:
                fltr_type, fltr_value = input("Filter type(Format: 'ip:<value>', 'port:<value>', flag:<value> , or 'http'.): ").split(':')
                main(args.interface, fltr_type, fltr_value)
            elif choice == 3:
                print("Exiting...")
                sys.exit(1)
            else:
                print("Invalide choice.")
        else:
            main(args.interface, filter_type, filter_value)

    except KeyboardInterrupt:
        print("\n" + "Adios!")


