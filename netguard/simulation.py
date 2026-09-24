"""
Traffic and attack simulation engine for NetGuard.

Enables safe, reproducible demonstrations of Port Scans, SYN Floods,
and RST/FIN Abuse without requiring root permissions, secondary machines,
or putting hostile packets onto local university Wi-Fi.
"""
import logging
import random
import time
from typing import Callable, List, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP

from netguard.models import PacketEvent
from netguard.parsing.packet_parser import parse_scapy_packet

logger = logging.getLogger("netguard.simulation")


class TrafficSimulator:
    """Generates synthetic network packets for normal baseline traffic and cyber attacks."""

    def __init__(self, on_packet_callback: Callable[[PacketEvent], None]):
        self.on_packet = on_packet_callback

    def generate_normal_packet(self) -> PacketEvent:
        """Generates a realistic background network packet (HTTP, DNS, TLS, NTP)."""
        protos = [("TCP", 443), ("TCP", 80), ("UDP", 53), ("UDP", 123), ("ICMP", None)]
        weights = [0.55, 0.25, 0.12, 0.05, 0.03]
        choice = random.choices(protos, weights=weights)[0]
        proto, dport = choice

        src_ip = f"192.168.1.{random.randint(10, 50)}"
        dst_ip = random.choice(["142.250.190.46", "1.1.1.1", "8.8.8.8", "151.101.1.69"])
        sport = random.randint(30000, 65000)
        length = random.randint(60, 1460)

        flags = ""
        if proto == "TCP":
            flags = random.choice(["A", "PA", "SA", "A"])

        return PacketEvent(
            ts=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_ver=4,
            proto=proto,
            src_port=sport,
            dst_port=dport,
            tcp_flags=flags,
            seq=random.randint(10000, 9000000),
            ack=random.randint(10000, 9000000) if "A" in flags else None,
            length=length,
            iface="simulation",
        )

    def simulate_vertical_port_scan(
        self,
        src_ip: str = "192.168.1.189",
        dst_ip: str = "192.168.1.10",
        num_ports: int = 20,
    ) -> dict:
        """Simulates an attacker scanning multiple ports on a single target machine."""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080,
        ]
        target_ports = common_ports[:num_ports]

        logger.info("Simulating Vertical Port Scan: %s -> %s (%d ports)", src_ip, dst_ip, len(target_ports))

        now = time.time()
        for i, port in enumerate(target_ports):
            pkt = PacketEvent(
                ts=now + (i * 0.05),
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_ver=4,
                proto="TCP",
                src_port=random.randint(40000, 60000),
                dst_port=port,
                tcp_flags="S",
                seq=random.randint(1000, 50000),
                length=64,
                iface="simulation",
            )
            self.on_packet(pkt)
            time.sleep(0.01)

        return {
            "attack": "Vertical Port Scan",
            "attacker": src_ip,
            "target": dst_ip,
            "probed_ports": target_ports,
        }

    def simulate_horizontal_port_scan(
        self,
        src_ip: str = "10.10.10.45",
        target_subnet: str = "192.168.1.",
        port: int = 22,
        num_hosts: int = 18,
    ) -> dict:
        """Simulates an attacker sweeping an entire subnet looking for SSH port 22."""
        logger.info("Simulating Horizontal Port Scan: %s sweeping port %d", src_ip, port)
        now = time.time()
        scanned_hosts = []

        for i in range(1, num_hosts + 1):
            dst_ip = f"{target_subnet}{i}"
            scanned_hosts.append(dst_ip)
            pkt = PacketEvent(
                ts=now + (i * 0.04),
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_ver=4,
                proto="TCP",
                src_port=random.randint(40000, 60000),
                dst_port=port + i,  # Mix of sweep ports
                tcp_flags="S",
                length=64,
                iface="simulation",
            )
            self.on_packet(pkt)
            time.sleep(0.01)

        return {
            "attack": "Horizontal Subnet Scan",
            "attacker": src_ip,
            "scanned_hosts_count": len(scanned_hosts),
            "target_port": port,
        }

    def simulate_syn_flood(
        self,
        src_ip: str = "185.220.101.5",
        victim_ip: str = "192.168.1.1",
        target_port: int = 80,
        syn_count: int = 65,
    ) -> dict:
        """Simulates a TCP SYN Flood Denial of Service against a web server."""
        logger.info("Simulating TCP SYN Flood: %s -> %s:%d (%d SYNs)", src_ip, victim_ip, target_port, syn_count)
        now = time.time()

        for i in range(syn_count):
            pkt = PacketEvent(
                ts=now + (i * 0.015),
                src_ip=src_ip,
                dst_ip=victim_ip,
                ip_ver=4,
                proto="TCP",
                src_port=random.randint(1024, 65535),
                dst_port=target_port,
                tcp_flags="S",
                seq=random.randint(10000, 999999),
                length=60,
                iface="simulation",
            )
            self.on_packet(pkt)
            # Notice: No ACK is ever sent back! Attacker leaves connection half-open.
            time.sleep(0.005)

        return {
            "attack": "TCP SYN Flood",
            "attacker": src_ip,
            "victim": victim_ip,
            "target_port": target_port,
            "packets_sent": syn_count,
        }

    def simulate_rst_abuse(
        self,
        src_ip: str = "198.51.100.33",
        dst_ip: str = "192.168.1.1",
        target_port: int = 443,
        burst_count: int = 12,
    ) -> dict:
        """Simulates an attacker injecting unsolicited RST packets to tear down TLS sessions."""
        logger.info("Simulating RST Abuse: %s -> %s:%d (%d RSTs)", src_ip, dst_ip, target_port, burst_count)
        now = time.time()

        for i in range(burst_count):
            pkt = PacketEvent(
                ts=now + (i * 0.1),
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_ver=4,
                proto="TCP",
                src_port=random.randint(30000, 60000),
                dst_port=target_port,
                tcp_flags="R",
                seq=random.randint(10000, 999999),
                length=54,
                iface="simulation",
            )
            self.on_packet(pkt)
            time.sleep(0.02)

        return {
            "attack": "RST/FIN Abuse",
            "attacker": src_ip,
            "victim": dst_ip,
            "target_port": target_port,
            "rst_packets_sent": burst_count,
        }

    def simulate_icmp_flood(
        self,
        src_ip: str = "203.0.113.88",
        dst_ip: str = "192.168.1.1",
        packet_count: int = 80,
    ) -> dict:
        """Simulates an ICMP Echo Request (Ping) flood spiking network PPS."""
        logger.info("Simulating ICMP Ping Flood: %s -> %s (%d packets)", src_ip, dst_ip, packet_count)
        now = time.time()

        for i in range(packet_count):
            pkt = PacketEvent(
                ts=now + (i * 0.01),
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_ver=4,
                proto="ICMP",
                length=84,
                info="Echo Request (Ping)",
                iface="simulation",
            )
            self.on_packet(pkt)
            time.sleep(0.005)

        return {
            "attack": "ICMP Echo Flood",
            "attacker": src_ip,
            "victim": dst_ip,
            "packets_sent": packet_count,
        }

    def simulate_udp_flood(
        self,
        src_ip: str = "45.33.32.156",
        dst_ip: str = "192.168.1.1",
        target_port: int = 53,
        packet_count: int = 50,
    ) -> dict:
        """Simulates a UDP Flood / DNS amplification attack."""
        logger.info("Simulating UDP Flood: %s -> %s:%d (%d packets)", src_ip, dst_ip, target_port, packet_count)
        now = time.time()
        for i in range(packet_count):
            pkt = PacketEvent(
                ts=now + (i * 0.02),
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_ver=4,
                proto="UDP",
                src_port=random.randint(1024, 65535),
                dst_port=target_port,
                length=random.randint(512, 4096),
                info="DNS Response (Amplified)" if target_port == 53 else "UDP Flood Packet",
                iface="simulation",
            )
            self.on_packet(pkt)
            time.sleep(0.005)
        return {
            "attack": "UDP Flood",
            "attacker": src_ip,
            "victim": dst_ip,
            "target_port": target_port,
            "packets_sent": packet_count,
        }

    def simulate_dns_tunneling(
        self,
        src_ip: str = "192.168.1.145",
        target_dns: str = "8.8.8.8",
        query_count: int = 20,
    ) -> dict:
        """Simulates covert DNS tunneling and data exfiltration."""
        logger.info("Simulating DNS Tunneling / Exfiltration: %s -> %s (%d queries)", src_ip, target_dns, query_count)
        now = time.time()
        for i in range(query_count):
            encoded_chunk = f"chunk{i}.a8f9c1b3d7e502.corp-secrets.c2.attacker.com"
            pkt = PacketEvent(
                ts=now + (i * 0.08),
                src_ip=src_ip,
                dst_ip=target_dns,
                ip_ver=4,
                proto="UDP",
                src_port=random.randint(40000, 65000),
                dst_port=53,
                length=random.randint(140, 280),
                info=f"DNS Query TXT: {encoded_chunk}",
                iface="simulation",
            )
            self.on_packet(pkt)
            time.sleep(0.01)
        return {
            "attack": "DNS Tunneling",
            "attacker": src_ip,
            "dns_server": target_dns,
            "queries_sent": query_count,
            "technique": "Base64 DNS Subdomain Exfiltration",
        }
