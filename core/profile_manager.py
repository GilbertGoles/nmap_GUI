import json
import os
import logging
from typing import Dict, List, Optional
from enum import Enum
from dataclasses import dataclass, asdict

from core.event_bus import EventBus
from shared.models.scan_config import ScanConfig, ScanType

@dataclass
class ScanProfile:
    """Профиль сканирования"""
    name: str
    description: str
    scan_type: ScanType
    options: Dict
    custom_command: str = ""
    category: str = "Custom"

class ProfileCategory(Enum):
    QUICK = "Quick Scans"
    STEALTH = "Stealth Scans"
    COMPREHENSIVE = "Comprehensive Scans"
    SERVICE = "Service Detection"
    OS_DETECTION = "OS Detection"
    VULNERABILITY = "Vulnerability Scanning"
    CUSTOM = "Custom Scans"

class ProfileManager:
    """Менеджер профилей сканирования"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, event_bus: EventBus):
        if cls._instance is None:
            cls._instance = ProfileManager(event_bus)
        return cls._instance
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.logger = self._setup_logging()
        self.profiles: Dict[str, ScanProfile] = {}
        self.profiles_file = "profiles.json"
        
        # Загружаем профили при инициализации
        self._load_profiles()
        self._create_default_profiles()
    
    def _setup_logging(self):
        """Настройка логирования"""
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(__name__)
    
    def _create_default_profiles(self):
        """Создает стандартные профили сканирования"""
        default_profiles = [
            ScanProfile(
                name="Quick Scan",
                description="Fast port scan of common ports",
                scan_type=ScanType.QUICK,
                category=ProfileCategory.QUICK.value,
                options={
                    "port_range": "1-1000",
                    "timing_template": "T4",
                    "threads": 4
                }
            ),
            ScanProfile(
                name="Stealth SYN Scan",
                description="Stealth SYN scan without completing TCP handshake",
                scan_type=ScanType.STEALTH,
                category=ProfileCategory.STEALTH.value,
                options={
                    "port_range": "1-1000",
                    "timing_template": "T2",
                    "threads": 2
                }
            ),
            ScanProfile(
                name="Comprehensive Scan",
                description="Full scan with OS detection, version detection and scripts",
                scan_type=ScanType.COMPREHENSIVE,
                category=ProfileCategory.COMPREHENSIVE.value,
                options={
                    "port_range": "1-65535",
                    "timing_template": "T4",
                    "threads": 4,
                    "service_version": True,
                    "os_detection": True,
                    "script_scan": True
                }
            ),
            ScanProfile(
                name="Service Detection",
                description="Detect service versions on open ports",
                scan_type=ScanType.CUSTOM,
                category=ProfileCategory.SERVICE.value,
                options={
                    "port_range": "1-10000",
                    "timing_template": "T4",
                    "service_version": True,
                    "script_scan": True
                },
                custom_command="nmap -sV -sC -T4"
            ),
            ScanProfile(
                name="OS Detection",
                description="Detect operating systems of targets",
                scan_type=ScanType.CUSTOM,
                category=ProfileCategory.OS_DETECTION.value,
                options={
                    "port_range": "1-1000",
                    "timing_template": "T4",
                    "os_detection": True
                },
                custom_command="nmap -O -T4"
            ),
            ScanProfile(
                name="Vulnerability Scan",
                description="Run vulnerability detection scripts",
                scan_type=ScanType.CUSTOM,
                category=ProfileCategory.VULNERABILITY.value,
                options={
                    "port_range": "1-10000",
                    "timing_template": "T3",
                    "service_version": True,
                    "script_scan": True
                },
                custom_command="nmap -sV --script vuln -T3"
            ),
            ScanProfile(
                name="Full TCP Connect",
                description="Complete TCP connection scan",
                scan_type=ScanType.CUSTOM,
                category=ProfileCategory.CUSTOM.value,
                options={
                    "port_range": "1-1000",
                    "timing_template": "T3",
                    "threads": 2
                },
                custom_command="nmap -sT -T3"
            ),
            ScanProfile(
                name="UDP Scan",
                description="Scan common UDP ports",
                scan_type=ScanType.CUSTOM,
                category=ProfileCategory.CUSTOM.value,
                options={
                    "port_range": "53,67,68,69,123,135,137,138,139,161,162,445,514,520,631,1434,1900,4500,49152",
                    "timing_template": "T2"
                },
                custom_command="nmap -sU -T2"
            )
        ]
        
        # Добавляем стандартные профили, если их еще нет
        for profile in default_profiles:
            if profile.name not in self.profiles:
                self.profiles[profile.name] = profile
        
        self._save_profiles()
    
    def create_profile_from_config(self, name: str, description: str, config: ScanConfig, category: str = "Custom") -> ScanProfile:
        """Создает профиль из конфигурации сканирования"""
        profile = ScanProfile(
            name=name,
            description=description,
            scan_type=config.scan_type,
            category=category,
            custom_command=config.custom_command,
            options={
                "port_range": config.port_range,
                "timing_template": config.timing_template,
                "threads": config.threads,
                "service_version": config.service_version,
                "os_detection": config.os_detection,
                "script_scan": config.script_scan
            }
        )
        
        return profile
    
    def add_profile(self, profile: ScanProfile) -> bool:
        """Добавляет новый профиль"""
        if profile.name in self.profiles:
            self.logger.warning(f"Profile '{profile.name}' already exists")
            return False
        
        self.profiles[profile.name] = profile
        self._save_profiles()
        self.logger.info(f"Profile '{profile.name}' added")
        return True
    
    def update_profile(self, name: str, profile: ScanProfile) -> bool:
        """Обновляет существующий профиль"""
        if name not in self.profiles:
            self.logger.warning(f"Profile '{name}' not found")
            return False
        
        self.profiles[name] = profile
        self._save_profiles()
        self.logger.info(f"Profile '{name}' updated")
        return True
    
    def delete_profile(self, name: str) -> bool:
        """Удаляет профиль"""
        if name not in self.profiles:
            self.logger.warning(f"Profile '{name}' not found")
            return False
        
        del self.profiles[name]
        self._save_profiles()
        self.logger.info(f"Profile '{name}' deleted")
        return True
    
    def get_profile(self, name: str) -> Optional[ScanProfile]:
        """Возвращает профиль по имени"""
        return self.profiles.get(name)
    
    def get_all_profiles(self) -> List[ScanProfile]:
        """Возвращает все профили"""
        return list(self.profiles.values())
    
    def get_profiles_by_category(self, category: str) -> List[ScanProfile]:
        """Возвращает профили по категории"""
        return [profile for profile in self.profiles.values() if profile.category == category]
    
    def get_categories(self) -> List[str]:
        """Возвращает список категорий"""
        categories = set(profile.category for profile in self.profiles.values())
        return sorted(list(categories))
    
    def apply_profile_to_config(self, profile_name: str, config: ScanConfig) -> ScanConfig:
        """Применяет настройки профиля к конфигурации"""
        profile = self.get_profile(profile_name)
        if not profile:
            self.logger.warning(f"Profile '{profile_name}' not found")
            return config
        
        # Обновляем конфигурацию
        config.scan_type = profile.scan_type
        config.custom_command = profile.custom_command
        
        # Применяем опции
        options = profile.options
        config.port_range = options.get("port_range", config.port_range)
        config.timing_template = options.get("timing_template", config.timing_template)
        config.threads = options.get("threads", config.threads)
        config.service_version = options.get("service_version", config.service_version)
        config.os_detection = options.get("os_detection", config.os_detection)
        config.script_scan = options.get("script_scan", config.script_scan)
        
        return config
    
    def export_profiles(self, file_path: str) -> bool:
        """Экспортирует профили в файл"""
        try:
            profiles_data = {}
            for name, profile in self.profiles.items():
                profiles_data[name] = {
                    "description": profile.description,
                    "scan_type": profile.scan_type.value,
                    "category": profile.category,
                    "custom_command": profile.custom_command,
                    "options": profile.options
                }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(profiles_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Profiles exported to {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting profiles: {e}")
            return False
    
    def import_profiles(self, file_path: str) -> bool:
        """Импортирует профили из файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                profiles_data = json.load(f)
            
            imported_count = 0
            for name, data in profiles_data.items():
                try:
                    profile = ScanProfile(
                        name=name,
                        description=data.get("description", ""),
                        scan_type=ScanType(data.get("scan_type", "custom")),
                        category=data.get("category", "Custom"),
                        custom_command=data.get("custom_command", ""),
                        options=data.get("options", {})
                    )
                    
                    self.profiles[name] = profile
                    imported_count += 1
                    
                except Exception as e:
                    self.logger.warning(f"Error importing profile '{name}': {e}")
                    continue
            
            self._save_profiles()
            self.logger.info(f"Imported {imported_count} profiles from {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing profiles: {e}")
            return False
    
    def _load_profiles(self):
        """Загружает профили из файла"""
        if not os.path.exists(self.profiles_file):
            self.logger.info("Profiles file not found, will create default profiles")
            return
        
        try:
            with open(self.profiles_file, 'r', encoding='utf-8') as f:
                profiles_data = json.load(f)
            
            for name, data in profiles_data.items():
                try:
                    profile = ScanProfile(
                        name=name,
                        description=data.get("description", ""),
                        scan_type=ScanType(data.get("scan_type", "custom")),
                        category=data.get("category", "Custom"),
                        custom_command=data.get("custom_command", ""),
                        options=data.get("options", {})
                    )
                    
                    self.profiles[name] = profile
                    
                except Exception as e:
                    self.logger.warning(f"Error loading profile '{name}': {e}")
                    continue
            
            self.logger.info(f"Loaded {len(self.profiles)} profiles")
            
        except Exception as e:
            self.logger.error(f"Error loading profiles: {e}")
    
    def _save_profiles(self):
        """Сохраняет профили в файл"""
        try:
            profiles_data = {}
            for name, profile in self.profiles.items():
                profiles_data[name] = {
                    "description": profile.description,
                    "scan_type": profile.scan_type.value,
                    "category": profile.category,
                    "custom_command": profile.custom_command,
                    "options": profile.options
                }
            
            with open(self.profiles_file, 'w', encoding='utf-8') as f:
                json.dump(profiles_data, f, indent=2, ensure_ascii=False)
            
            self.logger.debug(f"Saved {len(self.profiles)} profiles")
            
        except Exception as e:
            self.logger.error(f"Error saving profiles: {e}")
    
    def create_profile_from_current_scan(self, name: str, description: str, config: ScanConfig) -> bool:
        """Создает профиль из текущего сканирования"""
        profile = self.create_profile_from_config(name, description, config)
        return self.add_profile(profile)
    
    def get_recommended_profile(self, target_count: int, scan_type: str = "comprehensive") -> Optional[ScanProfile]:
        """Возвращает рекомендованный профиль на основе целей и типа сканирования"""
        if target_count > 100:
            # Для большого количества целей используем быстрые сканирования
            if scan_type == "comprehensive":
                return self.get_profile("Quick Scan")
            else:
                return self.get_profile("Stealth SYN Scan")
        else:
            # Для малого количества целей можно использовать детальные сканирования
            if scan_type == "comprehensive":
                return self.get_profile("Comprehensive Scan")
            elif scan_type == "vulnerability":
                return self.get_profile("Vulnerability Scan")
            elif scan_type == "service":
                return self.get_profile("Service Detection")
            else:
                return self.get_profile("Quick Scan")
