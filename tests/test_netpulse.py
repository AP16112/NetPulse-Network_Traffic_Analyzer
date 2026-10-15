from io import BytesIO
import pandas as pd
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, Dot1Q, Ether, ICMP, IP, IPv6, TCP, UDP, wrpcap
from netpulse.packets import parse_packet
from netpulse.analysis import detect_spikes, traffic_series
from netpulse.capture import CaptureSession
from scapy.layers.inet6 import ICMPv6EchoRequest


def ethernet():
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def test_tcp_headers():
    result = parse_packet(ethernet()/IP(src="192.0.2.1", dst="198.51.100.2", ttl=32)/TCP(sport=1234, dport=443, flags="SA"))
    assert result["source"] == "192.0.2.1"
    assert result["destination_port"] == 443
    assert result["tcp_flags"] == "SA"
    assert result["ttl"] == 32
    assert "L4 · TCP" in result["layers"]


def test_dns_and_ipv6():
    result = parse_packet(ethernet()/IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP()/DNS(qd=DNSQR(qname="example.com")))
    assert result["protocol"] == "DNS"
    assert result["dns_query"] == "example.com"
    assert "L3 · IPv6" in result["layers"]
    assert result["dns_direction"] == "Query"


def test_icmp_and_arp():
    icmp = parse_packet(IP()/ICMP(type=8))
    assert icmp["protocol"] == "ICMP"
    assert icmp["source_port"] is None
    assert icmp["icmp_type"] == 8
    assert parse_packet(ethernet()/ARP(psrc="192.0.2.3", hwsrc="02:00:00:00:00:01"))["source"] == "192.0.2.3"


def test_vlan_and_dhcp():
    packet = ethernet()/Dot1Q(vlan=42)/IP()/UDP(sport=68, dport=67)/BOOTP()/DHCP(options=[("message-type", 1), "end"])
    decoded = parse_packet(Ether(bytes(packet)))
    assert decoded["vlan_id"] == 42
    assert decoded["dhcp_message"] == "Discover"
    assert decoded["protocol"] == "DHCP"


def test_icmpv6_and_udp():
    assert parse_packet(IPv6()/ICMPv6EchoRequest())["protocol"] == "ICMPv6"
    assert parse_packet(IP()/UDP(sport=1234, dport=1235))["protocol"] == "UDP"


def test_bounded_storage():
    capture = CaptureSession(capacity=2)
    for _ in range(4):
        capture.ingest(IP()/TCP())
    rows, total, errors = capture.snapshot()
    assert len(rows) == 2 and total == 4 and errors == 0
    assert [row["id"] for row in rows] == [3, 4]
    capture.clear()
    assert capture.snapshot() == ([], 0, 0)


def test_spikes_exclude_current_from_baseline():
    series = pd.DataFrame({"packets": [10]*20 + [100], "bytes": [100]*21})
    alerts = detect_spikes(series)
    assert list(alerts.index) == [20]
    assert alerts.iloc[0].baseline == 10
    assert detect_spikes(series, minimum=200).empty


def test_idle_seconds_count():
    result = traffic_series(pd.DataFrame({"timestamp": [100, 102], "length": [80, 120]}))
    assert result.packets.tolist() == [1, 0, 1]
    assert result.bytes.sum() == 200


def test_pcap_roundtrip(tmp_path):
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), [ethernet()/IP()/TCP(), ethernet()/IP()/UDP()/DNS(qd=DNSQR(qname="example.com"))])
    capture = CaptureSession()
    assert capture.load_pcap(path.read_bytes()) == 2
    assert capture.snapshot()[0][1]["dns_query"] == "example.com"


def test_invalid_capture_reports_error():
    capture = CaptureSession()
    assert capture.load_pcap(b"invalid") == 0
    assert capture.error


def test_demo_has_alerts():
    capture = CaptureSession()
    capture.seed_demo()
    series = traffic_series(pd.DataFrame(capture.snapshot()[0]))
    assert len(detect_spikes(series)) == 2


def test_sparse_capture_has_bounded_time_axis():
    frame = pd.DataFrame({"timestamp": [100, 2_000_000_000], "length": [80, 120]})
    assert len(traffic_series(frame)) == 1


def test_capture_failure_is_visible(monkeypatch):
    def fail(**kwargs):
        raise PermissionError("Capture permission denied")
    monkeypatch.setattr("netpulse.capture.conf.L2listen", fail)
    capture = CaptureSession()
    capture.start("Live capture", "fake")
    capture.thread.join(timeout=2)
    assert not capture.running
    assert "permission denied" in capture.error


def test_demo_stops_cleanly():
    capture = CaptureSession()
    capture.start("Demo")
    capture.stop()
    assert not capture.running
