"""Session-local, bounded capture storage. No packets are transmitted."""
from collections import deque
from io import BytesIO
import random
import threading
import time

from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, Dot1Q, Ether, ICMP, IP, IPv6, PcapReader, Raw, TCP, UDP, conf, sniff
from .packets import parse_packet

CAPACITY = 15000


def demo_packets(stamp, count, rng):
    for _ in range(count):
        host = f"192.168.1.{rng.choice([12, 18, 24, 42, 55])}"
        kind = rng.choices(["TCP", "UDP", "DNS", "ICMP", "ARP", "IPv6", "DHCP", "VLAN"], [44, 15, 20, 8, 4, 3, 3, 3])[0]
        base = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=host, dst="203.0.113.10")
        if kind == "DNS":
            packet = base / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=rng.choice(["example.com", "docs.python.org", "example.net"])))
        elif kind == "TCP":
            packet = base / TCP(sport=rng.randint(49152, 65535), dport=443, flags="PA") / Raw(b"x" * rng.randint(60, 1200))
        elif kind == "UDP":
            packet = base / UDP(sport=55000, dport=443) / Raw(b"x" * 180)
        elif kind == "ICMP":
            packet = base / ICMP()
        elif kind == "ARP":
            packet = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=host, pdst="192.168.1.1", hwsrc="02:00:00:00:00:01")
        elif kind == "DHCP":
            packet = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", 1), "end"])
        elif kind == "VLAN":
            packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Dot1Q(vlan=10) / IP(src=host, dst="203.0.113.10") / TCP(sport=53000, dport=443)
        else:
            packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IPv6(src="2001:db8::12", dst="2001:db8::1") / TCP(sport=54000, dport=443)
        packet.time = stamp + rng.random() * 0.95
        yield packet


class CaptureSession:
    def __init__(self, capacity=CAPACITY):
        self.records = deque(maxlen=capacity)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None
        self.error = ""
        self.total = 0
        self.parse_errors = 0
        self.mode = "Demo"
        self.heartbeat = time.monotonic()

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def touch(self):
        self.heartbeat = time.monotonic()

    def ingest(self, packet):
        try:
            record = parse_packet(packet)
        except Exception:
            with self.lock:
                self.parse_errors += 1
            return
        with self.lock:
            self.total += 1
            record["id"] = self.total
            self.records.append(record)

    def snapshot(self):
        with self.lock:
            return list(self.records), self.total, self.parse_errors

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        if self.running:
            self.error = "Capture is still stopping. Wait before starting a new session."

    def clear(self):
        self.stop()
        if self.running:
            return
        with self.lock:
            self.records.clear()
            self.total = self.parse_errors = 0
        self.error = ""

    def seed_demo(self):
        rng = random.Random(42)
        start = int(time.time()) - 90
        for second in range(90):
            for packet in demo_packets(start + second, 95 if second in (35, 70) else rng.randint(6, 16), rng):
                self.ingest(packet)

    def start(self, mode, interface=None, bpf=""):
        self.stop()
        if self.running:
            return
        self.error = ""
        self.mode = mode
        self.touch()
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, args=(mode, interface, bpf), daemon=True)
        self.thread.start()

    def _run(self, mode, interface, bpf):
        rng = random.Random()
        tick = 0
        socket = None
        try:
            if mode != "Demo":
                socket = conf.L2listen(iface=interface, filter=bpf or None, promisc=False)
            while not self.stop_event.is_set() and time.monotonic() - self.heartbeat < 60:
                if mode == "Demo":
                    for packet in demo_packets(int(time.time()) - 1, 95 if tick % 30 == 29 else rng.randint(6, 16), rng):
                        self.ingest(packet)
                    tick += 1
                    self.stop_event.wait(1)
                else:
                    sniff(opened_socket=socket, prn=self.ingest, store=False, timeout=1)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            if socket is not None:
                socket.close()

    def load_pcap(self, data):
        self.clear()
        if self.running:
            return 0
        self.mode = "PCAP file"
        # Bound parsing work as well as storage; do not load an entire capture into RAM.
        count = 0
        try:
            with PcapReader(BytesIO(data)) as reader:
                for packet in reader:
                    self.ingest(packet)
                    count += 1
                    if count >= CAPACITY:
                        break
        except Exception as exc:
            self.error = f"Could not fully read capture: {exc}"
        return count


def interfaces():
    return {str(iface.network_name): f"{iface.name} — {iface.description}" for iface in conf.ifaces.values()}
