import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Optional
from datetime import datetime

from shared.models.scan_result import ScanResult, HostInfo, PortInfo
from shared.models.scan_config import ScanConfig

class NmapResultParser:
    """Парсер результатов nmap сканирования"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, *args, **kwargs):
        """
        Возвращает единственный экземпляр класса (Singleton)
        
        Args:
            *args: Позиционные аргументы (игнорируются для совместимости)
            **kwargs: Именованные аргументы (игнорируются для совместимости)
        """
        if cls._instance is None:
            cls._instance = NmapResultParser()
        return cls._instance
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_xml(self, xml_content: str, scan_config: ScanConfig) -> ScanResult:
        """
        Парсит XML вывод nmap и возвращает структурированные результаты
        
        Args:
            xml_content: XML строка с результатами nmap
            scan_config: Конфигурация сканирования
            
        Returns:
            ScanResult: Структурированные результаты сканирования
        """
        try:
            root = ET.fromstring(xml_content)
            scan_result = ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                start_time=datetime.now(),
                status="completed"
            )
            
            # Парсим информацию о сканировании
            self._parse_scan_info(root, scan_result)
            
            # Парсим хосты
            for host_element in root.findall('.//host'):
                host_info = self._parse_host(host_element)
                if host_info:
                    scan_result.hosts.append(host_info)
            
            scan_result.end_time = datetime.now()
            self.logger.info(f"Parsed {len(scan_result.hosts)} hosts from nmap output")
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Error parsing nmap XML: {e}")
            return ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                status="error",
                raw_xml=xml_content
            )
    
    def _parse_scan_info(self, root: ET.Element, scan_result: ScanResult):
        """Парсит общую информацию о сканировании"""
        try:
            scan_info = root.find('scaninfo')
            if scan_info is not None:
                scan_result.raw_xml = ET.tostring(root, encoding='unicode')
        except:
            pass
    
    def _parse_host(self, host_element: ET.Element) -> Optional[HostInfo]:
        """Парсит информацию о хосте - УЛУЧШЕННАЯ ВЕРСИЯ"""
        try:
            # IP адрес
            address_element = host_element.find(".//address[@addrtype='ipv4']")
            if address_element is None:
                address_element = host_element.find(".//address[@addrtype='ipv6']")
            if address_element is None:
                self.logger.warning("No IP address found for host")
                return None
                
            ip = address_element.get('addr')
            if not ip:
                return None
            
            host_info = HostInfo(ip=ip)
            
            # Hostname - ИСПРАВЛЕННЫЙ ПАРСИНГ
            hostnames_element = host_element.find('hostnames')
            if hostnames_element is not None:
                hostnames = []
                for hostname_element in hostnames_element.findall('hostname'):
                    hostname = hostname_element.get('name', '').strip()
                    if hostname:
                        hostnames.append(hostname)
                
                if hostnames:
                    host_info.hostname = hostnames[0]  # Берем первый хостнейм
            
            # Состояние хоста
            status_element = host_element.find('status')
            if status_element is not None:
                host_info.state = status_element.get('state', 'unknown')
            
            # Парсим порты - ВАЖНО: проверяем наличие открытых портов
            ports_element = host_element.find('ports')
            if ports_element is not None:
                host_info.ports = self._parse_ports(ports_element)
                self.logger.info(f"Found {len(host_info.ports)} ports for host {ip}")
            
            # Парсим информацию об ОС - УЛУЧШЕННЫЙ ПАРСИНГ
            os_element = host_element.find('os')
            if os_element is not None:
                self._parse_os_info(os_element, host_info)
            
            # Парсим скрипты
            hostscript_element = host_element.find('hostscript')
            if hostscript_element is not None:
                self._parse_host_scripts(hostscript_element, host_info)
            
            self.logger.info(f"Parsed host {ip}: {len(host_info.ports)} ports, OS: {host_info.os_family}")
            return host_info
            
        except Exception as e:
            self.logger.error(f"Error parsing host: {e}")
            return None
    
    def _parse_ports(self, ports_element: ET.Element) -> List[PortInfo]:
        """Парсит информацию о портах - ИСПРАВЛЕННАЯ ВЕРСИЯ"""
        ports = []
        
        for port_element in ports_element.findall('port'):
            try:
                port_id = port_element.get('portid')
                protocol = port_element.get('protocol')
                
                if not port_id or not protocol:
                    continue
                
                state_element = port_element.find('state')
                service_element = port_element.find('service')
                script_elements = port_element.findall('script')
                
                # ВАЖНОЕ ИСПРАВЛЕНИЕ: Правильно получаем состояние порта
                state = 'unknown'
                if state_element is not None:
                    state = state_element.get('state', 'unknown')
                
                port_info = PortInfo(
                    port=int(port_id),
                    protocol=protocol,
                    state=state,  # Используем исправленное состояние
                    service=service_element.get('name', 'unknown') if service_element else 'unknown',
                    version=service_element.get('product', '') if service_element else '',
                    reason=state_element.get('reason', '') if state_element else ''
                )
                
                # Добавляем версию сервиса если есть
                if service_element is not None:
                    version_parts = []
                    if service_element.get('product'):
                        version_parts.append(service_element.get('product'))
                    if service_element.get('version'):
                        version_parts.append(service_element.get('version'))
                    if service_element.get('extrainfo'):
                        version_parts.append(service_element.get('extrainfo'))
                    
                    port_info.version = ' '.join(version_parts)
                
                # Парсим скрипты nmap для порта
                port_scripts = {}
                for script_element in script_elements:
                    script_id = script_element.get('id')
                    script_output = script_element.get('output', '')
                    if script_id and script_output:
                        port_scripts[script_id] = script_output
                
                if port_scripts:
                    port_info.scripts = port_scripts
                
                ports.append(port_info)
                
                # ДЕБАГ ЛОГИРОВАНИЕ
                self.logger.debug(f"Parsed port: {port_id}/{protocol} - State: {state}")
                
            except Exception as e:
                self.logger.error(f"Error parsing port {port_id}: {e}")
                continue
        
        return ports
    
    def _parse_os_info(self, os_element: ET.Element, host_info: HostInfo):
        """Парсит информацию об операционной системе - УЛУЧШЕННАЯ ВЕРСИЯ"""
        try:
            # Ищем наиболее точное совпадение ОС
            best_match = None
            highest_accuracy = 0
            
            for os_match in os_element.findall('osmatch'):
                accuracy_str = os_match.get('accuracy', '0')
                try:
                    accuracy = int(accuracy_str)
                    if accuracy > highest_accuracy:
                        highest_accuracy = accuracy
                        best_match = os_match
                except ValueError:
                    continue
            
            if best_match is not None:
                os_name = best_match.get('name', 'Unknown OS')
                host_info.os_family = os_name
                host_info.os_details = f"{os_name} (Accuracy: {highest_accuracy}%)"
                
                # Дополнительная информация из osclass
                for os_class in best_match.findall('osclass'):
                    os_family = os_class.get('osfamily', '')
                    os_gen = os_class.get('osgen', '')
                    vendor = os_class.get('vendor', '')
                    
                    if os_family and not host_info.os_family:
                        host_info.os_family = os_family
                    if vendor and vendor not in host_info.os_details:
                        host_info.os_details += f" {vendor}"
            
        except Exception as e:
            self.logger.debug(f"Error parsing OS info: {e}")
    
    def _parse_host_scripts(self, hostscript_element: ET.Element, host_info: HostInfo):
        """Парсит скрипты nmap на уровне хоста"""
        try:
            for script_element in hostscript_element.findall('script'):
                script_id = script_element.get('id')
                script_output = script_element.get('output', '')
                
                if script_id and script_output:
                    host_info.scripts[script_id] = script_output
                    
                    # Анализируем специфические скрипты
                    if script_id == "smb-os-discovery":
                        self._parse_smb_os_discovery(script_output, host_info)
                    elif script_id == "snmp-sysdescr":
                        self._parse_snmp_sysdescr(script_output, host_info)
        
        except Exception as e:
            self.logger.debug(f"Error parsing host scripts: {e}")
    
    def _parse_smb_os_discovery(self, output: str, host_info: HostInfo):
        """Парсит вывод скрипта smb-os-discovery"""
        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if 'OS:' in line and not host_info.os_family:
                    host_info.os_family = line.split('OS:')[1].strip()
                elif 'Computer name:' in line and not host_info.hostname:
                    host_info.hostname = line.split('Computer name:')[1].strip()
                elif 'Domain name:' in line:
                    domain = line.split('Domain name:')[1].strip()
                    if host_info.hostname and '.' not in host_info.hostname:
                        host_info.hostname += f".{domain}"
        except:
            pass
    
    def _parse_snmp_sysdescr(self, output: str, host_info: HostInfo):
        """Парсит вывод скрипта snmp-sysdescr"""
        try:
            # Извлекаем информацию о системе из SNMP
            if 'Linux' in output:
                host_info.os_family = "Linux"
                host_info.os_details = output.strip()
            elif 'Windows' in output:
                host_info.os_family = "Windows"
                host_info.os_details = output.strip()
            elif 'Cisco' in output:
                host_info.os_family = "Cisco IOS"
                host_info.os_details = output.strip()
        except:
            pass
