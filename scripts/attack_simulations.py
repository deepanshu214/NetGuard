#!/usr/bin/env python3
"""
NetGuard Attack Simulation CLI Script.

Allows testing the detection engine by generating synthetic attack traffic
either via the local NetGuard REST API or directly using Scapy packet crafting.

Usage:
    # Trigger via NetGuard Web API:
    python scripts/attack_simulations.py --via-api --attack port_scan
    python scripts/attack_simulations.py --via-api --attack syn_flood
    python scripts/attack_simulations.py --via-api --attack rst_abuse

    # Trigger via raw Scapy packets (requires root/sudo for raw sockets):
    sudo python scripts/attack_simulations.py --attack port_scan --target 127.0.0.1
"""
import argparse
import sys
import time
import urllib.request
import json

try:
    from scapy.all import IP, TCP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def trigger_via_api(api_url: str, attack_type: str):
    """Sends a trigger request to NetGuard's simulation endpoint."""
    endpoint = f"{api_url.rstrip('/')}/api/simulate"
    payload = json.dumps({"type": attack_type}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    print(f"[+] Sending simulation request to {endpoint} (attack: {attack_type})...")
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            print(f"[✓] Success: {res_data.get('status')}")
            print(f"    Details: {json.dumps(res_data.get('details'), indent=2)}")
            print("[*] Check your NetGuard Web Dashboard to see the alert and charts!")
    except urllib.error.URLError as e:
        print(f"[-] Error contacting NetGuard server at {api_url}: {e}")
        print("    Make sure NetGuard is running: python netguard/main.py")
        sys.exit(1)


def raw_port_scan(target_ip: str, port_count: int = 20):
    """Sends raw TCP SYN packets to multiple destination ports using Scapy."""
    if not SCAPY_AVAILABLE:
        print("[-] Scapy is not installed. Use --via-api instead.")
        return

    print(f"[+] Crafting and sending {port_count} TCP SYN packets to {target_ip}...")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
    ports = common_ports[:port_count]

    for port in ports:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.05)
    print(f"[✓] Sent {len(ports)} SYN probes to {target_ip}.")


def raw_syn_flood(target_ip: str, count: int = 60, target_port: int = 80):
    """Sends raw TCP SYN flood packets without acknowledgements using Scapy."""
    if not SCAPY_AVAILABLE:
        print("[-] Scapy is not installed. Use --via-api instead.")
        return

    print(f"[+] Sending {count} SYN flood packets to {target_ip}:{target_port}...")
    for i in range(count):
        sport = 40000 + (i % 20000)
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=1000 + i)
        send(pkt, verbose=0)
        time.sleep(0.01)
    print(f"[✓] Completed SYN flood simulation against {target_ip}.")


def raw_rst_abuse(target_ip: str, count: int = 15, target_port: int = 443):
    """Sends abnormal burst of RST packets to sensitive port using Scapy."""
    if not SCAPY_AVAILABLE:
        print("[-] Scapy is not installed. Use --via-api instead.")
        return

    print(f"[+] Sending {count} TCP RST packets to {target_ip}:{target_port}...")
    for i in range(count):
        pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="R")
        send(pkt, verbose=0)
        time.sleep(0.05)
    print(f"[✓] Completed RST abuse simulation against {target_ip}.")


def main():
    parser = argparse.ArgumentParser(description="NetGuard Attack Simulator CLI")
    parser.add_argument(
        "--attack",
        choices=["port_scan", "port_scan_horizontal", "syn_flood", "rst_abuse"],
        default="port_scan",
        help="Type of attack to simulate",
    )
    parser.add_argument(
        "--via-api",
        action="store_true",
        default=True,
        help="Trigger simulation via NetGuard HTTP API (Recommended, no sudo needed)",
    )
    parser.add_argument(
        "--raw-packets",
        action="store_true",
        help="Send actual raw packets on the network interface (Requires sudo)",
    )
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:5000",
        help="NetGuard web server URL",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IP address for raw packet sending",
    )

    args = parser.parse_args()

    if args.raw_packets:
        if args.attack in ("port_scan", "port_scan_horizontal"):
            raw_port_scan(args.target)
        elif args.attack == "syn_flood":
            raw_syn_flood(args.target)
        elif args.attack == "rst_abuse":
            raw_rst_abuse(args.target)
    else:
        trigger_via_api(args.api_url, args.attack)


if __name__ == "__main__":
    main()
