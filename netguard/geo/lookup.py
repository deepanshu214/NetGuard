"""
IP Geolocation lookup for NetGuard.

Uses a built-in mapping of known IP ranges to approximate locations.
For simulation IPs, returns deterministic mock locations so the map
always has interesting data to show during demos.
"""
import hashlib
import ipaddress
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("netguard.geo")

KNOWN_IPS: Dict[str, Dict[str, Any]] = {
    "8.8.8.8": {"lat": 37.386, "lon": -122.084, "city": "Mountain View", "country": "US", "org": "Google DNS"},
    "8.8.4.4": {"lat": 37.386, "lon": -122.084, "city": "Mountain View", "country": "US", "org": "Google DNS"},
    "1.1.1.1": {"lat": -33.868, "lon": 151.207, "city": "Sydney", "country": "AU", "org": "Cloudflare"},
    "142.250.190.46": {"lat": 37.419, "lon": -122.078, "city": "Mountain View", "country": "US", "org": "Google"},
    "151.101.1.69": {"lat": 37.774, "lon": -122.419, "city": "San Francisco", "country": "US", "org": "Fastly"},
    "185.220.101.5": {"lat": 52.520, "lon": 13.405, "city": "Berlin", "country": "DE", "org": "Tor Exit Node"},
    "198.51.100.33": {"lat": 51.507, "lon": -0.128, "city": "London", "country": "GB", "org": "Test Network"},
    "203.0.113.88": {"lat": 35.689, "lon": 139.692, "city": "Tokyo", "country": "JP", "org": "Test Network"},
    "10.10.10.45": {"lat": 48.857, "lon": 2.352, "city": "Paris", "country": "FR", "org": "Internal Scanner"},
}

DEMO_LOCATIONS = [
    {"lat": 40.713, "lon": -74.006, "city": "New York", "country": "US"},
    {"lat": 55.755, "lon": 37.617, "city": "Moscow", "country": "RU"},
    {"lat": 39.904, "lon": 116.407, "city": "Beijing", "country": "CN"},
    {"lat": -23.550, "lon": -46.633, "city": "São Paulo", "country": "BR"},
    {"lat": 28.613, "lon": 77.209, "city": "New Delhi", "country": "IN"},
    {"lat": 1.352, "lon": 103.820, "city": "Singapore", "country": "SG"},
    {"lat": 37.566, "lon": 126.978, "city": "Seoul", "country": "KR"},
    {"lat": -33.869, "lon": 18.424, "city": "Cape Town", "country": "ZA"},
    {"lat": 19.433, "lon": -99.133, "city": "Mexico City", "country": "MX"},
    {"lat": 41.009, "lon": 28.978, "city": "Istanbul", "country": "TR"},
]


def _is_private(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True


def _deterministic_location(ip_str: str) -> Dict[str, Any]:
    """Returns a deterministic mock location based on IP hash."""
    h = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
    loc = DEMO_LOCATIONS[h % len(DEMO_LOCATIONS)]
    return {**loc, "org": "Simulated Host"}


def lookup_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Returns geolocation data for an IP address."""
    if ip in KNOWN_IPS:
        return {**KNOWN_IPS[ip], "ip": ip}
    if _is_private(ip):
        return None
    loc = _deterministic_location(ip)
    return {**loc, "ip": ip}


def lookup_alert_ips(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Returns unique geolocated attacker IPs from a list of alerts."""
    seen = set()
    results = []
    for alert in alerts:
        src_ip = alert.get("src_ip", "")
        if src_ip and src_ip not in seen:
            seen.add(src_ip)
            geo = lookup_ip(src_ip)
            if geo:
                geo["alert_count"] = sum(1 for a in alerts if a.get("src_ip") == src_ip)
                geo["last_type"] = alert.get("type", "UNKNOWN")
                geo["last_severity"] = alert.get("severity", "MEDIUM")
                results.append(geo)
    return results
