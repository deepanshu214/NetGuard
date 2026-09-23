"""Unit tests for the NetGuard packet parser."""
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from netguard.parsing.packet_parser import parse_scapy_packet


def test_parse_ipv4_tcp_syn():
    """Test parsing an IPv4 TCP SYN packet."""
    pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="S", seq=1000)
    event = parse_scapy_packet(pkt, capture_time=1700000000.0)

    assert event is not None
    assert event.ip_ver == 4
    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "192.168.1.1"
    assert event.proto == "TCP"
    assert event.src_port == 54321
    assert event.dst_port == 80
    assert "S" in event.tcp_flags
    assert event.seq == 1000
    assert event.ts == 1700000000.0


def test_parse_ipv4_udp():
    """Test parsing an IPv4 UDP packet (e.g. DNS)."""
    pkt = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=43210, dport=53)
    event = parse_scapy_packet(pkt, capture_time=1700000001.5)

    assert event is not None
    assert event.ip_ver == 4
    assert event.src_ip == "10.0.0.2"
    assert event.dst_ip == "8.8.8.8"
    assert event.proto == "UDP"
    assert event.src_port == 43210
    assert event.dst_port == 53


def test_parse_icmp():
    """Test parsing an ICMP echo request packet."""
    pkt = IP(src="192.168.1.10", dst="192.168.1.1") / ICMP(type=8)
    event = parse_scapy_packet(pkt, capture_time=1700000002.0)

    assert event is not None
    assert event.proto == "ICMP"
    assert event.src_port is None
    assert event.dst_port is None


def test_parse_ipv6_tcp():
    """Test parsing an IPv6 TCP packet."""
    pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=8080, dport=443, flags="SA")
    event = parse_scapy_packet(pkt, capture_time=1700000003.0)

    assert event is not None
    assert event.ip_ver == 6
    assert event.src_ip == "2001:db8::1"
    assert event.dst_ip == "2001:db8::2"
    assert event.proto == "TCP"
    assert "S" in event.tcp_flags and "A" in event.tcp_flags
