#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse
import datetime
import signal
import sys
from pygments import highlight
from pygments.lexers import HttpLexer
from pygments.formatters import TerminalFormatter

# Global variables for stats
packet_count = 0
start_time = datetime.datetime.now()

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Banner with colors
def show_banner():
    print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════╗
    ║   {Colors.BOLD}ADVANCED NETWORK SNIFFER{Colors.RESET}{Colors.CYAN}      ║
    ║   Version: 2.0                       ║
    ║   Author: Network Security Expert    ║
    ╚══════════════════════════════════════╝
    {Colors.RESET}""")

# Signal handler for graceful exit
def signal_handler(sig, frame):
    print(f"\n{Colors.RED}[!] Keyboard interrupt detected. Stopping sniffer...{Colors.RESET}")
    print_stats()
    sys.exit(0)

# Print summary statistics
def print_stats():
    global packet_count, start_time
    duration = datetime.datetime.now() - start_time
    print(f"\n{Colors.YELLOW}╔══════════════════════════════════════╗")
    print(f"║          {Colors.BOLD}SNIFFER STATISTICS{Colors.RESET}{Colors.YELLOW}         ║")
    print(f"╠══════════════════════════════════════╣")
    print(f"║ Packets Captured: {packet_count:20} ║")
    print(f"║ Duration: {str(duration):28} ║")
    print(f"╚══════════════════════════════════════╝{Colors.RESET}")

# Enhanced packet processing
def process_packet(packet):
    global packet_count
    packet_count += 1
    
    # Clear screen for new packet (optional)
    if packet_count % 20 == 0:
        os.system('clear' if os.name == 'posix' else 'cls')
        show_banner()
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"\n{Colors.MAGENTA}═════ Packet #{packet_count} [{timestamp}] ═════{Colors.RESET}")

    # Ethernet layer
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        eth_type = packet[Ether].type
        print(f"{Colors.BLUE}[ Ethernet ]{Colors.RESET}")
        print(f"  Source: {Colors.GREEN}{src_mac}{Colors.RESET} → Dest: {Colors.GREEN}{dst_mac}{Colors.RESET}")
        print(f"  Type: 0x{eth_type:04x}")

    # IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        ttl = packet[IP].ttl
        print(f"{Colors.BLUE}[ IP ]{Colors.RESET}")
        print(f"  Source: {Colors.GREEN}{src_ip}{Colors.RESET} → Dest: {Colors.GREEN}{dst_ip}{Colors.RESET}")
        print(f"  Protocol: {proto} (TTL: {ttl})")

    # TCP layer
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        print(f"{Colors.BLUE}[ TCP ]{Colors.RESET}")
        print(f"  Ports: {src_port} → {dst_port}")
        print(f"  Flags: {flags} (Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack})")

    # HTTP Request
    if packet.haslayer(HTTPRequest):
        print(f"{Colors.BLUE}[ HTTP Request ]{Colors.RESET}")
        method = packet[HTTPRequest].Method.decode()
        url = f"{packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}"
        print(f"  Method: {Colors.YELLOW}{method}{Colors.RESET}")
        print(f"  URL: {Colors.CYAN}{url}{Colors.RESET}")
        
        # Pretty print headers
        if packet.haslayer(Raw):
            headers = packet[Raw].load.decode('utf-8', errors='ignore').split('\r\n')
            print("  Headers:")
            for header in headers[:10]:  # Show first 10 headers max
                if header.strip():
                    print(f"    {header}")

    # HTTP Response
    elif packet.haslayer(HTTPResponse):
        print(f"{Colors.BLUE}[ HTTP Response ]{Colors.RESET}")
        status_code = packet[HTTPResponse].Status_Code.decode()
        reason = packet[HTTPResponse].Reason_Phrase.decode()
        print(f"  Status: {Colors.RED}{status_code} {reason}{Colors.RESET}")
        
        if packet.haslayer(Raw):
            # Highlight HTTP response
            http_data = packet[Raw].load.decode('utf-8', errors='ignore')
            highlighted = highlight(http_data[:500], HttpLexer(), TerminalFormatter())
            print("  Content (first 500 chars):")
            print(highlighted)

    # DNS packets
    elif packet.haslayer(DNS):
        print(f"{Colors.BLUE}[ DNS ]{Colors.RESET}")
        if packet[DNS].qr == 0:
            print("  Type: Query")
        else:
            print("  Type: Response")
        print(f"  Question: {packet[DNS].qd.qname.decode()}")

    # Raw payload (non-HTTP)
    elif packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"{Colors.BLUE}[ Raw Data ]{Colors.RESET}")
        print(f"  Hex Dump (first 64 bytes):")
        hexdump(payload[:64])

# Main function
def main():
    show_banner()
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description="Advanced Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network Interface (e.g., eth0)", required=True)
    parser.add_argument("-f", "--filter", help="BPF Filter (e.g., 'tcp port 80')", default="")
    parser.add_argument("-o", "--output", help="Save packets to file (PCAP format)")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    args = parser.parse_args()

    print(f"{Colors.YELLOW}[*] Starting sniffer on {args.interface}{Colors.RESET}")
    if args.filter:
        print(f"{Colors.YELLOW}[*] Applying filter: '{args.filter}'{Colors.RESET}")
    
    try:
        if args.output:
            print(f"{Colors.YELLOW}[*] Saving packets to {args.output}{Colors.RESET}")
            sniff(iface=args.interface, filter=args.filter, prn=process_packet, 
                  store=False, stop_filter=lambda x: packet_count >= 1000 if not args.verbose else False)
        else:
            sniff(iface=args.interface, filter=args.filter, prn=process_packet, store=False)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
    finally:
        print_stats()

if __name__ == "__main__":
    main()
