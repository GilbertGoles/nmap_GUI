from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    reason: str = ""

@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    state: str = "unknown"
    os_family: str = ""
    os_details: str = ""
    ports: List[PortInfo] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)

@dataclass
class ScanResult:
    scan_id: str
    config: 'ScanConfig'
    hosts: List[HostInfo] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    status: str = "pending"
    raw_xml: str = ""
    
    def get_open_ports_count(self) -> int:
        """Возвращает количество открытых портов"""
        count = 0
        for host in self.hosts:
            for port in host.ports:
                if port.state == "open":
                    count += 1
        return count
    
    def get_hosts_count(self) -> int:
        """Возвращает количество хостов"""
        return len(self.hosts)
