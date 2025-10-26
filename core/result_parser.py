import xml.etree.ElementTree as ET
import logging
from datetime import datetime
from typing import List, Dict, Optional
from shared.models.scan_result import ScanResult, HostInfo, PortInfo

class NmapResultParser:
    """Парсер XML вывода nmap"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, event_bus=None):
        if cls._instance is None:
            cls._instance = NmapResultParser(event_bus)
        return cls._instance
    
    def __init__(self, event_bus=None):
        self.event_bus = event_bus
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        """Настройка логирования"""
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(__name__)
    
    def parse_xml(self, xml_content: str, scan_config=None) -> ScanResult:
        """
        Парсит XML вывод nmap и возвращает структурированные результаты
        
        Args:
            xml_content: XML строка с результатами nmap
            scan_config: Конфигурация сканирования (опционально)
            
        Returns:
            ScanResult: Структурированные результаты сканирования
        """
        try:
            root = ET.fromstring(xml_content)
            
            # Создаем объект результатов
            scan_result = ScanResult(
                scan_id=scan_config.scan_id if scan_config else "unknown",
                config=scan_config,
                start_time=datetime.now(),
                raw_xml=xml_content
            )
            
            # Парсим информацию о сканировании
            self._parse_scan_info(root, scan_result)
            
            # Парсим хосты
            self._parse_hosts(root, scan_result)
            
            scan_result.end_time = datetime.now()
            scan_result.status = "completed"
            
            self.logger.info(f"Parsed {len(scan_result.hosts)} hosts from nmap output")
            return scan_result
            
        except ET.ParseError as e:
            self.logger.error(f"XML parsing error: {e}")
            raise ValueError(f"Invalid XML content: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing nmap results: {e}")
            raise
    
    def _parse_scan_info(self, root: ET.Element, scan_result: ScanResult):
        """Парсит общую информацию о сканировании"""
        try:
            # Время начала и окончания
            scan_info = root.find("scaninfo")
            if scan_info is not None:
                scan_result.scan_type = scan_info.get("type", "unknown")
                scan_result.protocol = scan_info.get("protocol", "tcp")
            
            # Статистика сканирования
            run_stats = root.find("runstats")
            if run_stats is not None:
                finished = run_stats.find("finished")
                if finished is not None:
                    time_str = finished.get("time", "")
                    if time_str:
                        try:
                            scan_result.end_time = datetime.fromtimestamp(int(time_str))
                        except ValueError:
                            pass
            
            self.logger.debug("Scan info parsed successfully")
            
        except Exception as e:
            self.logger.warning(f"Error parsing scan info: {e}")
    
    def _parse_hosts(self, root: ET.Element, scan_result: ScanResult):
        """Парсит информацию о хостах"""
        hosts = root.findall("host")
        
        for host_elem in hosts:
            try:
                host_info = self._parse_single_host(host_elem)
                if host_info:
                    scan_result.hosts.append(host_info)
            except Exception as e:
                self.logger.warning(f"Error parsing host: {e}")
                continue
    
    def _parse_single_host(self, host_elem: ET.Element) -> Optional[HostInfo]:
        """Парсит информацию об одном хосте"""
        try:
            # Базовая информация о хосте
            host_info = HostInfo(ip="", state="unknown")
            
            # IP адрес и статус
            address_elem = host_elem.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host_elem.find("address[@addrtype='ipv6']")
            
            if address_elem is not None:
                host_info.ip = address_elem.get("addr", "")
            
            # Статус хоста
            status_elem = host_elem.find("status")
            if status_elem is not None:
                host_info.state = status_elem.get("state", "unknown")
            
            # Хостнейм
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find("hostname")
                if hostname_elem is not None:
                    host_info.hostname = hostname_elem.get("name", "")
            
            # Парсим порты
            self._parse_ports(host_elem, host_info)
            
            # Парсим информацию об ОС
            self._parse_os_info(host_elem, host_info)
            
            # Парсим скрипты
            self._parse_scripts(host_elem, host_info)
            
            return host_info if host_info.ip else None
            
        except Exception as e:
            self.logger.error(f"Error parsing single host: {e}")
            return None
    
    def _parse_ports(self, host_elem: ET.Element, host_info: HostInfo):
        """Парсит информацию о портах"""
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            return
        
        port_elems = ports_elem.findall("port")
        for port_elem in port_elems:
            try:
                port_info = PortInfo(
                    port=int(port_elem.get("portid", 0)),
                    protocol=port_elem.get("protocol", "tcp"),
                    state="unknown",
                    service="unknown"
                )
                
                # Статус порта
                state_elem = port_elem.find("state")
                if state_elem is not None:
                    port_info.state = state_elem.get("state", "unknown")
                    port_info.reason = state_elem.get("reason", "")
                
                # Информация о сервисе
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    port_info.service = service_elem.get("name", "unknown")
                    port_info.version = service_elem.get("product", "")
                    
                    # Добавляем версию если есть
                    if service_elem.get("version"):
                        if port_info.version:
                            port_info.version += " " + service_elem.get("version")
                        else:
                            port_info.version = service_elem.get("version")
                
                # Дополнительная информация из скриптов
                script_elems = port_elem.findall("script")
                for script_elem in script_elems:
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    
                    if script_id and script_output:
                        host_info.scripts[f"{script_id}_port{port_info.port}"] = script_output
                
                host_info.ports.append(port_info)
                
            except (ValueError, AttributeError) as e:
                self.logger.warning(f"Error parsing port: {e}")
                continue
    
    def _parse_os_info(self, host_elem: ET.Element, host_info: HostInfo):
        """Парсит информацию об операционной системе"""
        os_elem = host_elem.find("os")
        if os_elem is None:
            return
        
        try:
            # Берем наиболее вероятное совпадение OS
            os_match_elem = os_elem.find("osmatch")
            if os_match_elem is not None:
                host_info.os_family = os_match_elem.get("name", "")
                
                # Детали OS
                os_class_elems = os_match_elem.findall("osclass")
                if os_class_elems:
                    # Берем первый класс для основных деталей
                    first_class = os_class_elems[0]
                    vendor = first_class.get("vendor", "")
                    os_family = first_class.get("osfamily", "")
                    os_gen = first_class.get("osgen", "")
                    
                    details = []
                    if vendor:
                        details.append(vendor)
                    if os_family:
                        details.append(os_family)
                    if os_gen:
                        details.append(f"Gen {os_gen}")
                    
                    host_info.os_details = " ".join(details)
            
        except Exception as e:
            self.logger.warning(f"Error parsing OS info: {e}")
    
    def _parse_scripts(self, host_elem: ET.Element, host_info: HostInfo):
        """Парсит вывод скриптов nmap"""
        host_script_elem = host_elem.find("hostscript")
        if host_script_elem is None:
            return
        
        script_elems = host_script_elem.findall("script")
        for script_elem in script_elems:
            try:
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")
                
                if script_id and script_output:
                    host_info.scripts[script_id] = script_output
                    
            except Exception as e:
                self.logger.warning(f"Error parsing script {script_id}: {e}")
    
    def parse_from_file(self, file_path: str, scan_config=None) -> ScanResult:
        """
        Парсит результаты nmap из XML файла
        
        Args:
            file_path: Путь к XML файлу
            scan_config: Конфигурация сканирования (опционально)
            
        Returns:
            ScanResult: Структурированные результаты
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                xml_content = file.read()
            
            return self.parse_xml(xml_content, scan_config)
            
        except Exception as e:
            self.logger.error(f"Error reading XML file {file_path}: {e}")
            raise
    
    def get_statistics(self, scan_result: ScanResult) -> Dict:
        """
        Возвращает статистику по результатам сканирования
        
        Returns:
            Dict: Статистика сканирования
        """
        stats = {
            "total_hosts": len(scan_result.hosts),
            "up_hosts": 0,
            "down_hosts": 0,
            "total_ports": 0,
            "open_ports": 0,
            "unique_services": set(),
            "os_detected": 0
        }
        
        for host in scan_result.hosts:
            if host.state == "up":
                stats["up_hosts"] += 1
            else:
                stats["down_hosts"] += 1
            
            if host.os_family:
                stats["os_detected"] += 1
            
            for port in host.ports:
                stats["total_ports"] += 1
                if port.state == "open":
                    stats["open_ports"] += 1
                    if port.service and port.service != "unknown":
                        stats["unique_services"].add(port.service)
        
        stats["unique_services"] = list(stats["unique_services"])
        stats["unique_services_count"] = len(stats["unique_services"])
        
        return stats
    
    def filter_hosts_by_service(self, scan_result: ScanResult, service_name: str) -> List[HostInfo]:
        """Фильтрует хосты по имени сервиса"""
        filtered_hosts = []
        
        for host in scan_result.hosts:
            for port in host.ports:
                if port.service.lower() == service_name.lower():
                    filtered_hosts.append(host)
                    break
        
        return filtered_hosts
    
    def filter_hosts_by_port(self, scan_result: ScanResult, port_number: int) -> List[HostInfo]:
        """Фильтрует хосты по номеру порта"""
        filtered_hosts = []
        
        for host in scan_result.hosts:
            for port in host.ports:
                if port.port == port_number and port.state == "open":
                    filtered_hosts.append(host)
                    break
        
        return filtered_hosts
    
    def find_vulnerable_services(self, scan_result: ScanResult, version_patterns: Dict[str, List[str]]) -> List[Dict]:
        """
        Ищет потенциально уязвимые сервисы по версиям
        
        Args:
            scan_result: Результаты сканирования
            version_patterns: Словарь с паттернами уязвимых версий
                Пример: {"apache": ["2.4.49", "2.4.50"], "openssh": ["8.0"]}
                
        Returns:
            List[Dict]: Список найденных уязвимых сервисов
        """
        vulnerable_services = []
        
        for host in scan_result.hosts:
            for port in host.ports:
                if port.state == "open" and port.version:
                    for service_name, vulnerable_versions in version_patterns.items():
                        if service_name.lower() in port.service.lower() or service_name.lower() in port.version.lower():
                            for vulnerable_version in vulnerable_versions:
                                if vulnerable_version in port.version:
                                    vulnerable_services.append({
                                        "host": host.ip,
                                        "port": port.port,
                                        "service": port.service,
                                        "version": port.version,
                                        "vulnerable_to": f"{service_name} {vulnerable_version}",
                                        "hostname": host.hostname
                                    })
                                    break
        
        return vulnerable_services
