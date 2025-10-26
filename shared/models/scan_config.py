from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class ScanType(Enum):
    QUICK = "quick"
    STEALTH = "stealth"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"

@dataclass
class ScanConfig:
    """Конфигурация сканирования NMAP"""
    scan_id: str
    targets: List[str]
    scan_type: ScanType = ScanType.QUICK
    custom_command: str = ""
    threads: int = 4
    timing_template: str = "T4"
    port_range: str = "1-1000"
    service_version: bool = False
    os_detection: bool = False
    script_scan: bool = False
    output_format: str = "xml"
    
    def to_nmap_command(self) -> str:
        """Генерирует команду nmap из конфигурации"""
        cmd_parts = ["nmap"]
        
        # Базовые опции
        if self.timing_template:
            cmd_parts.append(f"-{self.timing_template}")
        
        if self.threads and self.threads > 1:
            cmd_parts.append(f"--min-parallelism {self.threads}")
        
        # Тип сканирования
        if self.scan_type == ScanType.QUICK:
            cmd_parts.append("-F")
        elif self.scan_type == ScanType.STEALTH:
            cmd_parts.append("-sS")
        elif self.scan_type == ScanType.COMPREHENSIVE:
            cmd_parts.extend([-"-sS", "-sV", "-O", "-A"])
        
        # Дополнительные опции
        if self.service_version:
            cmd_parts.append("-sV")
        if self.os_detection:
            cmd_parts.append("-O")
        if self.script_scan:
            cmd_parts.append("-sC")
        
        # Порты
        if self.port_range:
            cmd_parts.append(f"-p {self.port_range}")
        
        # Цели
        cmd_parts.extend(self.targets)
        
        # Вывод
        cmd_parts.append("-oX -")  # XML в stdout
        
        return " ".join(cmd_parts)
