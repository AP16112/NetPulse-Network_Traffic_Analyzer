"""Decode headers without retaining packet payloads."""
from datetime import datetime, timezone
from scapy.all import ARP, DHCP, DNS, Dot1Q, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.layers.inet6 import _ICMPv6


def parse_packet(packet):
    network = packet.getlayer(IP) or packet.getlayer(IPv6)
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    protocol = "OTHER"
    layers = []
    if Ether in packet:
        layers.append("L2 · Ethernet")
    if Dot1Q in packet:
        layers.append(f"L2 · 802.1Q VLAN {packet[Dot1Q].vlan}")
    if ARP in packet:
        protocol = "ARP"
        layers.append("L2/L3 · ARP address resolution")
    if network is not None:
        layers.append("L3 · IPv4" if IP in packet else "L3 · IPv6")
        protocol = "IPv4" if IP in packet else "IPv6"
    if TCP in packet:
        protocol = "TCP"
        layers.append("L4 · TCP")
    elif UDP in packet:
        protocol = "UDP"
        layers.append("L4 · UDP")
    elif ICMP in packet or any(issubclass(layer, _ICMPv6) for layer in packet.layers()):
        protocol = "ICMP" if ICMP in packet else "ICMPv6"
        layers.append(f"L3 · {protocol}")
    query = ""
    if DNS in packet:
        protocol = "DNS"
        layers.append("L7 · DNS")
        if packet[DNS].qd:
            query = packet[DNS].qd[0].qname.decode("utf-8", errors="replace").rstrip(".")
    dhcp_message = ""
    if DHCP in packet:
        protocol = "DHCP"
        layers.append("L7 · DHCP")
        names = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
        for option in packet[DHCP].options:
            if isinstance(option, tuple) and option[0] == "message-type":
                value = option[1]
                if isinstance(value, bytes):
                    value = int.from_bytes(value, "big")
                dhcp_message = names.get(value, str(value))
    arp = packet.getlayer(ARP)
    stamp = float(packet.time)
    return {
        "timestamp": stamp,
        "time_utc": datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="milliseconds"),
        "source": str(network.src) if network is not None else str(arp.psrc) if arp else str(packet[Ether].src) if Ether in packet else "—",
        "destination": str(network.dst) if network is not None else str(arp.pdst) if arp else str(packet[Ether].dst) if Ether in packet else "—",
        "source_port": int(transport.sport) if transport is not None else None,
        "destination_port": int(transport.dport) if transport is not None else None,
        "protocol": protocol,
        "length": len(packet),
        "ttl": int(network.ttl) if IP in packet else int(network.hlim) if IPv6 in packet else None,
        "tcp_flags": str(packet[TCP].flags) if TCP in packet else "",
        "icmp_type": int(packet[ICMP].type) if ICMP in packet else None,
        "dns_query": query,
        "dhcp_message": dhcp_message,
        "vlan_id": int(packet[Dot1Q].vlan) if Dot1Q in packet else None,
        "dns_direction": ("Response" if packet[DNS].qr else "Query") if DNS in packet else "",
        "layers": " → ".join(layers) or "Unrecognized link layer",
    }
