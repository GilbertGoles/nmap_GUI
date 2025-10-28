import subprocess
import threading
import tempfile
import os
import signal
import psutil
from typing import List, Optional, Callable
from datetime import datetime
import xml.etree.ElementTree as ET
import logging

from core.event_bus import EventBus
from shared.models.scan_config import ScanConfig, ScanType
from shared.models.scan_result import ScanResult

class NmapEngine:
    """Движок для выполнения nmap сканирований"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls, event_bus: EventBus):
        if cls._instance is None:
            cls._instance = NmapEngine(event_bus)
        return cls._instance
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.logger = self._setup_logging()
        self.active_processes = {}
        
    def _setup_logging(self):
        """Настройка логирования"""
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(__name__)
    
    def execute_scan(self, scan_config: ScanConfig) -> ScanResult:
        """
        Выполняет nmap сканирование
        """
        try:
            self.logger.info(f"Starting nmap scan: {scan_config.scan_id}")
            
            # Генерируем команду nmap
            command = self._build_nmap_command(scan_config)
            self.logger.info(f"Nmap command: {command}")
            
            # Создаем временный файл для XML вывода
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False, encoding='utf-8') as temp_file:
                xml_file_path = temp_file.name
            
            # Запускаем nmap процесс
            self.logger.info(f"Executing: {command}")
            
            # ИСПРАВЛЕНИЕ: используем правильный подход для чтения вывода
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Сохраняем процесс
            self.active_processes[scan_config.scan_id] = {
                'process': process,
                'config': scan_config,
                'start_time': datetime.now(),
                'xml_file': xml_file_path
            }
            
            # Запускаем основной поток для обработки вывода
            output_thread = threading.Thread(
                target=self._process_nmap_output,
                args=(process, scan_config, xml_file_path)
            )
            output_thread.daemon = True
            output_thread.start()
            
            # Ждем завершения процесса
            return_code = process.wait()
            self.logger.info(f"Nmap process finished with return code: {return_code}")
            
            # Даем потоку время завершиться
            output_thread.join(timeout=5)
            
            # Читаем XML результаты
            scan_result = self._parse_xml_results(xml_file_path, scan_config)
            
            # Очищаем
            if scan_config.scan_id in self.active_processes:
                del self.active_processes[scan_config.scan_id]
            
            try:
                os.unlink(xml_file_path)
            except Exception as e:
                self.logger.debug(f"Error removing temp file: {e}")
            
            self.logger.info(f"Scan completed: {scan_config.scan_id}")
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Error executing nmap scan: {e}")
            return ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                hosts=[],
                status="error",
                raw_xml=""
            )

    def execute_comprehensive_scan(self, scan_config: ScanConfig) -> ScanResult:
        """
        Выполняет комплексное сканирование с определением ОС, сервисов и уязвимостей
        """
        try:
            self.logger.info(f"Starting comprehensive scan: {scan_config.scan_id}")
            
            # Базовая команда для комплексного сканирования
            base_cmd = "nmap -sS -sV -O -A --script vuln,safe,default"
            
            # Добавляем цели и вывод
            command = f"{base_cmd} {' '.join(scan_config.targets)} -oX -"
            
            self.logger.info(f"Comprehensive scan command: {command}")
            
            # Создаем временный файл для XML
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False, encoding='utf-8') as temp_file:
                xml_file_path = temp_file.name
            
            # Запускаем процесс
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Сохраняем процесс
            self.active_processes[scan_config.scan_id] = {
                'process': process,
                'config': scan_config,
                'start_time': datetime.now(),
                'xml_file': xml_file_path
            }
            
            # Обрабатываем вывод
            output_thread = threading.Thread(
                target=self._process_comprehensive_output,
                args=(process, scan_config, xml_file_path)
            )
            output_thread.daemon = True
            output_thread.start()
            
            # Ждем завершения
            return_code = process.wait()
            output_thread.join(timeout=10)
            
            # Парсим результаты
            scan_result = self._parse_xml_results(xml_file_path, scan_config)
            
            # Очищаем
            if scan_config.scan_id in self.active_processes:
                del self.active_processes[scan_config.scan_id]
            
            try:
                os.unlink(xml_file_path)
            except:
                pass
            
            self.logger.info(f"Comprehensive scan completed: {scan_config.scan_id}")
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Error executing comprehensive scan: {e}")
            return ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                hosts=[],
                status="error",
                raw_xml=""
            )
    
    def _process_nmap_output(self, process: subprocess.Popen, scan_config: ScanConfig, xml_file_path: str):
        """Обрабатывает вывод nmap (stdout и stderr)"""
        try:
            xml_content = []
            in_xml = False
            last_progress = 0
            
            # Читаем stdout
            for line in process.stdout:
                line = line.strip()
                
                # Определяем начало XML
                if line.startswith('<?xml'):
                    in_xml = True
                    self.logger.debug("Found XML start")
                
                if in_xml:
                    xml_content.append(line)
                    # Проверяем конец XML
                    if '</nmaprun>' in line:
                        break
                else:
                    # Логируем не-XML вывод для отладки
                    if line:
                        self.logger.debug(f"Nmap stdout: {line}")
                    
                    # Парсим прогресс из текстового вывода
                    progress = self._parse_progress_from_output(line, last_progress)
                    if progress is not None and progress > last_progress:
                        last_progress = progress
                        self.event_bus.scan_progress.emit({
                            'scan_id': scan_config.scan_id,
                            'progress': progress,
                            'status': line[:100]
                        })
            
            # Сохраняем XML
            if xml_content:
                with open(xml_file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(xml_content))
                self.logger.debug(f"Saved {len(xml_content)} lines of XML")
            else:
                self.logger.warning("No XML content received from nmap")
                    
        except Exception as e:
            self.logger.error(f"Error processing nmap output: {e}")
        
        # Обрабатываем stderr в отдельном потоке
        stderr_thread = threading.Thread(
            target=self._read_stderr,
            args=(process, scan_config)
        )
        stderr_thread.daemon = True
        stderr_thread.start()

    def _process_comprehensive_output(self, process: subprocess.Popen, scan_config: ScanConfig, xml_file_path: str):
        """Обрабатывает вывод комплексного сканирования"""
        try:
            xml_content = []
            in_xml = False
            last_progress = 0
            
            for line in process.stdout:
                line = line.strip()
                
                if line.startswith('<?xml'):
                    in_xml = True
                    self.logger.debug("Found XML start in comprehensive scan")
                
                if in_xml:
                    xml_content.append(line)
                    if '</nmaprun>' in line:
                        break
                else:
                    if line:
                        self.logger.debug(f"Comprehensive scan: {line}")
                    
                    # Улучшенный парсинг прогресса для комплексного сканирования
                    progress = self._parse_comprehensive_progress(line, last_progress)
                    if progress is not None and progress > last_progress:
                        last_progress = progress
                        self.event_bus.scan_progress.emit({
                            'scan_id': scan_config.scan_id,
                            'progress': progress,
                            'status': line[:100]
                        })
            
            # Сохраняем XML
            if xml_content:
                with open(xml_file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(xml_content))
        
        except Exception as e:
            self.logger.error(f"Error processing comprehensive output: {e}")
    
    def _read_stderr(self, process: subprocess.Popen, scan_config: ScanConfig):
        """Читает stderr процесса nmap"""
        try:
            for line in process.stderr:
                line = line.strip()
                if line:
                    self.logger.warning(f"Nmap stderr: {line}")
                    self.event_bus.scan_progress.emit({
                        'scan_id': scan_config.scan_id,
                        'progress': -1,
                        'status': f"Error: {line[:100]}"
                    })
        except Exception as e:
            self.logger.error(f"Error reading stderr: {e}")

    def _parse_progress_from_output(self, line: str, last_progress: int) -> Optional[int]:
        """
        Парсит прогресс из вывода nmap
        """
        try:
            if "Nmap scan report for" in line:
                return min(last_progress + 20, 80)
            elif "PORT" in line and "STATE" in line and "SERVICE" in line:
                return min(last_progress + 10, 90)
            elif "Nmap done:" in line:
                return 100
            elif "discovered" in line and "open port" in line:
                return min(last_progress + 5, 95)
            elif "scan initiated" in line:
                return 10
            elif "Host is up" in line:
                return 30
            elif "Scanning" in line and "hosts" in line:
                return 15
            elif "Completed" in line and "scan" in line:
                return 85
        except:
            pass
        return None

    def _parse_comprehensive_progress(self, line: str, last_progress: int) -> Optional[int]:
        """
        Парсит прогресс для комплексного сканирования
        """
        try:
            line_lower = line.lower()
            
            if "nmap scan report for" in line:
                return min(last_progress + 10, 20)
            elif "host is up" in line:
                return min(last_progress + 5, 25)
            elif "port" in line_lower and "state" in line_lower and "service" in line_lower:
                return min(last_progress + 10, 35)
            elif "service detection" in line_lower:
                return min(last_progress + 15, 50)
            elif "os detection" in line_lower:
                return min(last_progress + 15, 65)
            elif "script scanning" in line_lower:
                return min(last_progress + 20, 85)
            elif "nmap done:" in line:
                return 100
            elif "scan initiated" in line:
                return 5
            elif "scanning" in line_lower:
                return min(last_progress + 2, 15)
                
        except:
            pass
        return None

    def _build_nmap_command(self, scan_config: ScanConfig) -> str:
        """
        Строит команду nmap из конфигурации - ИСПРАВЛЕННАЯ ВЕРСИЯ
        """
        cmd_parts = ["nmap"]
        
        # Базовые опции производительности
        if scan_config.timing_template:
            cmd_parts.append(f"-{scan_config.timing_template}")
        
        # Тип сканирования - ИСПРАВЛЕНИЕ ДЛЯ QUICK SCAN
        if scan_config.scan_type == ScanType.QUICK:
            cmd_parts.append("-F")  # Быстрое сканирование основных портов
        elif scan_config.scan_type == ScanType.STEALTH:
            cmd_parts.append("-sS")
        elif scan_config.scan_type == ScanType.COMPREHENSIVE:
            cmd_parts.extend(["-sS", "-sV", "-O", "-A"])
        elif scan_config.scan_type == ScanType.DISCOVERY:
            cmd_parts.append("-sn")
        elif scan_config.scan_type == ScanType.CUSTOM:
            # Для кастомного сканирования используем пользовательскую команду
            if scan_config.custom_command and scan_config.custom_command.strip():
                custom_cmd = scan_config.custom_command.strip()
                if "-oX" not in custom_cmd:
                    custom_cmd += " -oX -"
                return custom_cmd
        
        # Дополнительные опции (не для discovery сканирования)
        if scan_config.scan_type != ScanType.DISCOVERY:
            if scan_config.service_version and "-sV" not in cmd_parts:
                cmd_parts.append("-sV")
            if scan_config.os_detection and "-O" not in cmd_parts:
                cmd_parts.append("-O")
            if scan_config.script_scan and "-sC" not in cmd_parts:
                cmd_parts.append("-sC")
        
        # Диапазон портов (не для quick и discovery)
        if (scan_config.port_range and 
            scan_config.scan_type not in [ScanType.QUICK, ScanType.DISCOVERY]):
            cmd_parts.append(f"-p {scan_config.port_range}")
        
        # Цели
        cmd_parts.extend(scan_config.targets)
        
        # Вывод в XML
        cmd_parts.append("-oX -")
        
        command = " ".join(cmd_parts)
        self.logger.info(f"Generated nmap command: {command}")
        return command
    
    def _parse_xml_results(self, xml_file_path: str, scan_config: ScanConfig) -> ScanResult:
        """
        Парсит XML результаты nmap
        """
        try:
            # Проверяем существует ли файл
            if not os.path.exists(xml_file_path):
                self.logger.warning("XML file does not exist")
                return ScanResult(
                    scan_id=scan_config.scan_id,
                    config=scan_config,
                    hosts=[],
                    status="error",
                    raw_xml=""
                )
            
            file_size = os.path.getsize(xml_file_path)
            if file_size == 0:
                self.logger.warning("XML file is empty")
                return ScanResult(
                    scan_id=scan_config.scan_id,
                    config=scan_config,
                    hosts=[],
                    status="error",
                    raw_xml=""
                )
            
            self.logger.info(f"XML file size: {file_size} bytes")
            
            with open(xml_file_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            
            if not xml_content.strip():
                self.logger.warning("XML content is empty")
                return ScanResult(
                    scan_id=scan_config.scan_id,
                    config=scan_config,
                    hosts=[],
                    status="error", 
                    raw_xml=""
                )
            
            # Проверяем что XML валидный
            if not xml_content.startswith('<?xml'):
                self.logger.warning("XML content doesn't start with <?xml")
                return ScanResult(
                    scan_id=scan_config.scan_id,
                    config=scan_config,
                    hosts=[],
                    status="error",
                    raw_xml=xml_content
                )
            
            from core.result_parser import NmapResultParser
            parser = NmapResultParser.get_instance()
            
            result = parser.parse_xml(xml_content, scan_config)
            self.logger.info(f"Parsed {len(result.hosts)} hosts from XML")
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing XML results: {e}")
            return ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                hosts=[],
                status="error",
                raw_xml=""
            )
    
    def stop_scan(self, scan_id: str):
        """Останавливает сканирование"""
        if scan_id in self.active_processes:
            process_info = self.active_processes[scan_id]
            process = process_info['process']
            
            try:
                process.terminate()
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except:
                    pass
            
            finally:
                if 'xml_file' in process_info:
                    try:
                        os.unlink(process_info['xml_file'])
                    except:
                        pass
                
                if scan_id in self.active_processes:
                    del self.active_processes[scan_id]
                
            self.logger.info(f"Scan stopped: {scan_id}")
