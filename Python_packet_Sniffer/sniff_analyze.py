from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, ARP
import argparse
import time

def handle_packet(pkt):
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    
    if IP in pkt:  # IPv4
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        proto  = pkt[IP].proto
        length = len(pkt)

        # TCP
        if TCP in pkt:
            print(f"[{timestamp}] {ip_src} → {ip_dst}  TCP  {pkt[TCP].sport}:{pkt[TCP].dport}  len={length}")

        # UDP
        elif UDP in pkt:
            print(f"[{timestamp}] {ip_src} → {ip_dst}  UDP  {pkt[UDP].sport}:{pkt[UDP].dport}  len={length}")

        # ICMP
        elif ICMP in pkt:
            print(f"[{timestamp}] {ip_src} → {ip_dst}  ICMP  type={pkt[ICMP].type} code={pkt[ICMP].code}")

        else:
            print(f"[{timestamp}] {ip_src} → {ip_dst}  Other IPv4 Protocol {proto}")

    elif ARP in pkt:  # ARP
        if pkt[ARP].op == 1:
            print(f"[{timestamp}] ARP Request: Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}")
        elif pkt[ARP].op == 2:
            print(f"[{timestamp}] ARP Reply: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")

    else:
        print(f"[{timestamp}] Non-IP packet captured")

# ----------------------------

def main():
    parser = argparse.ArgumentParser(description=" Python Packet Sniffer")
    parser.add_argument("-i", "--interface", default=None, help="Network interface (default: auto)")
    parser.add_argument("-f", "--filter", default=None, help="BPF filter (e.g. 'tcp or udp')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-o", "--outfile", default=None, help="Save captured packets to PCAP file")

    args = parser.parse_args()

    print("\n=== Packet Sniffer ===")
    print(f"Interface: {args.interface or 'default'}")
    print(f"Filter   : {args.filter or 'None'}")
    print(f"Count    : {args.count or 'Unlimited'}")
    print(f"Saving   : {args.outfile or 'No'}")
    print("=============================\n")

    packets = sniff(iface=args.interface,
                    filter=args.filter,
                    count=args.count,
                    prn=handle_packet)

    if args.outfile:
        wrpcap(args.outfile, packets)
        print(f"\n[+] Packets saved to {args.outfile}")

# ----------------------------

if __name__ == "__main__":
    main()
