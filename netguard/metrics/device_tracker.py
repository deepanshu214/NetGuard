import ipaddress
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set
from netguard.models import PacketEvent

@dataclass
class DeviceProfile:
    ip: str
    first_seen: float
    last_seen: float
    total_packets: int = 0
    total_bytes: int = 0
    protocols_used: Set[str] = field(default_factory=set)
    ports_seen: Set[int] = field(default_factory=set)
    role: str = 'external'
    is_flagged: bool = False
    alert_count: int = 0

class DeviceTracker:
    """
    Builds profiles of all communicating hosts on the network.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.devices: Dict[str, DeviceProfile] = {}

    def _classify_role(self, ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return 'external'
            
        if isinstance(ip, ipaddress.IPv4Address):
            # Check for common gateway endings
            if ip_str.endswith('.1') or ip_str.endswith('.254'):
                return 'gateway'
            elif ip.is_private:
                return 'local'
            else:
                return 'external'
        elif isinstance(ip, ipaddress.IPv6Address):
            if ip.is_private:
                return 'local'
            return 'external'
        return 'external'

    def on_packet(self, event: PacketEvent):
        if not event.src_ip:
            return
            
        current_time = time.time()
        
        with self._lock:
            if event.src_ip not in self.devices:
                self.devices[event.src_ip] = DeviceProfile(
                    ip=event.src_ip,
                    first_seen=current_time,
                    last_seen=current_time,
                    role=self._classify_role(event.src_ip)
                )
                
            profile = self.devices[event.src_ip]
            profile.last_seen = current_time
            profile.total_packets += 1
            if hasattr(event, 'length') and event.length is not None:
                profile.total_bytes += event.length
            if event.proto:
                profile.protocols_used.add(event.proto)
            if event.dst_port is not None:
                profile.ports_seen.add(event.dst_port)

    def flag_attacker(self, ip: str):
        with self._lock:
            if ip in self.devices:
                self.devices[ip].is_flagged = True
                self.devices[ip].alert_count += 1
                self.devices[ip].role = 'attacker'
            else:
                self.devices[ip] = DeviceProfile(
                    ip=ip,
                    first_seen=time.time(),
                    last_seen=time.time(),
                    role='attacker',
                    is_flagged=True,
                    alert_count=1
                )

    def get_devices(self, limit: int = 50) -> List[dict]:
        with self._lock:
            # Sort by total_packets descending
            sorted_devices = sorted(
                self.devices.values(),
                key=lambda d: d.total_packets,
                reverse=True
            )
            
            result = []
            for d in sorted_devices[:limit]:
                result.append({
                    'ip': d.ip,
                    'first_seen': d.first_seen,
                    'last_seen': d.last_seen,
                    'total_packets': d.total_packets,
                    'total_bytes': d.total_bytes,
                    'protocols_used': list(d.protocols_used),
                    'ports_seen': list(d.ports_seen),
                    'role': d.role,
                    'is_flagged': d.is_flagged,
                    'alert_count': d.alert_count
                })
            return result

    def get_device_count(self) -> int:
        with self._lock:
            return len(self.devices)

    def reset(self):
        with self._lock:
            self.devices.clear()
