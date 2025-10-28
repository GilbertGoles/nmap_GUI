from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class ScanType(Enum):
    """Типы сканирования NMAP"""
    QUICK = "quick"
    STEALTH = "stealth" 
    COMPREHENSIVE = "comprehensive"
    DISCOVERY = "discovery"
    CUSTOM = "custom"

@dataclass
class ScanConfig:
    """Конфигурация сканирования NMAP"""
    targets: List[str]
    scan_type: ScanType = ScanType.QUICK
    scan_id: Optional[str] = None  # ✅ Сделать опциональным
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
            cmd_parts.extend(["-sS", "-sV", "-O", "-A"])
        elif self.scan_type == ScanType.DISCOVERY:
            cmd_parts.append("-sn")
        
        # Дополнительные опции (игнорируем для quick и discovery сканирования)
        if self.scan_type not in [ScanType.QUICK, ScanType.DISCOVERY]:
            if self.service_version:
                cmd_parts.append("-sV")
            if self.os_detection:
                cmd_parts.append("-O")
            if self.script_scan:
                cmd_parts.append("-sC")
        
        # Порты (игнорируем для quick и discovery сканирования)
        if self.port_range and self.scan_type not in [ScanType.QUICK, ScanType.DISCOVERY]:
            cmd_parts.append(f"-p {self.port_range}")
        
        # Пользовательская команда (имеет приоритет для custom сканирования)
        if (self.scan_type == ScanType.CUSTOM and 
            self.custom_command and 
            self.custom_command.strip()):
            custom_cmd = self.custom_command.strip()
            if "-oX" not in custom_cmd:
                custom_cmd += " -oX -"
            return custom_cmd
        
        # Цели
        cmd_parts.extend(self.targets)
        
        # Вывод
        cmd_parts.append("-oX -")  # XML в stdout
        
        return " ".join(cmd_parts)
