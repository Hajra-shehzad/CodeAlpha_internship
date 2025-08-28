# 🕵️ Python Packet Sniffer

A simple yet powerful **network packet sniffer** built using [Scapy](https://scapy.net/).  
This tool captures network traffic in real-time and displays useful details like **source & destination IPs, protocols, ports, ARP requests/replies, and ICMP messages**.  
It also supports saving captured traffic into a `.pcap` file for later analysis in Wireshark.

---

## 🚀 Features
- Capture **IPv4 traffic** (TCP, UDP, ICMP, and others).
- Capture **ARP requests/replies**.
- Display **source & destination IP addresses** with protocol info.
- Apply **filters** (BPF syntax) to capture specific traffic (e.g., `tcp`, `udp`, `icmp`).
- Choose **specific network interface** for sniffing.
- Save packets to a **PCAP file** for offline analysis.
- Show **timestamps** for each packet.

---

## 🛠️ Requirements
- Python **3.7+**
- [Scapy](https://scapy.readthedocs.io/) library  

Install Scapy with:
```bash
pip install scapy
```

---

## Usage
Run the sniffer with default options:
```
python packet_sniffer.py
```
Capture only 10 packets:
```
python packet_sniffer.py -c 10
```

Capture only TCP traffic:
```
python packet_sniffer.py -f "tcp"
```

Capture packets on a specific interface:
```
python packet_sniffer.py -i eth0
```

Save captured packets to a PCAP file:
```
python packet_sniffer.py -o output.pcap
```

---

## 🙌 Author

Developed by TheHajra

-Contributions, issues, and feature requests are welcome!




