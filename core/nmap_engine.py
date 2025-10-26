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
from shared.models.scan_config import ScanConfig
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
        
        Args:
            scan_config: Конфигурация сканирования
            
        Returns:
            ScanResult: Результаты сканирования
        """
        try:
            self.logger.info(f"Starting nmap scan: {scan_config.scan_id}")
            
            # Генерируем команду nmap
            command = self._build_nmap_command(scan_config)
            self.logger.info(f"Nmap command: {command}")
            
            # Создаем временный файл для XML вывода
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False) as temp_file:
                xml_file_path = temp_file.name
            
            # Запускаем nmap процесс
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
            
            # Запускаем поток для чтения вывода в реальном времени
            output_thread = threading.Thread(
                target=self._read_process_output,
                args=(process, scan_config)
            )
            output_thread.daemon = True
            output_thread.start()
            
            # Ждем завершения процесса
            return_code = process.wait()
            
            # Читаем XML результаты
            scan_result = self._parse_xml_results(xml_file_path, scan_config)
            
            # Очищаем
            if scan_config.scan_id in self.active_processes:
                del self.active_processes[scan_config.scan_id]
            
            try:
                os.unlink(xml_file_path)
            except:
                pass
            
            if return_code != 0:
                self.logger.warning(f"Nmap process exited with code: {return_code}")
            
            self.logger.info(f"Scan completed: {scan_config.scan_id}")
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Error executing nmap scan: {e}")
            # Возвращаем пустой результат в случае ошибки
            return ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                hosts=[],
                status="error",
                raw_xml=""
            )

    def _read_process_output(self, process: subprocess.Popen, scan_config: ScanConfig):
        """Читает вывод процесса nmap в реальном времени"""
        try:
            xml_content = []
            in_xml = False
            last_progress = 0
            has_xml_data = False
            
            # Читаем stdout
            for line in process.stdout:
                line = line.strip()
                
                # Определяем начало XML
                if line.startswith('<?xml'):
                    in_xml = True
                    has_xml_data = True
                
                if in_xml:
                    xml_content.append(line)
                else:
                    # Парсим прогресс из текстового вывода
                    progress = self._parse_progress_from_output(line, last_progress)
                    if progress is not None and progress > last_progress:
                        last_progress = progress
                        self.event_bus.scan_progress.emit({
                            'scan_id': scan_config.scan_id,
                            'progress': progress,
                            'status': line[:100]
                        })
            
            # Сохраняем XML для парсинга только если есть данные
            if has_xml_data and xml_content and scan_config.scan_id in self.active_processes:
                xml_file = self.active_processes[scan_config.scan_id]['xml_file']
                with open(xml_file, 'w') as f:
                    f.write('\n'.join(xml_content))
            elif not has_xml_data:
                # Если XML нет, создаем базовый результат
                self._create_fallback_result(scan_config)
                    
        except Exception as e:
            self.logger.error(f"Error reading process output: {e}")
            self._create_fallback_result(scan_config)

    def _create_fallback_result(self, scan_config: ScanConfig):
        """Создает fallback результат когда XML недоступен"""
        try:
            # Парсим текстовый вывод чтобы получить базовую информацию
            fallback_result = ScanResult(
                scan_id=scan_config.scan_id,
                config=scan_config,
                hosts=[],
                status="completed",
                raw_xml=""
            )
            
            # Здесь можно добавить парсинг текстового вывода nmap
            # для извлечения базовой информации о хостах
            
            self.event_bus.scan_completed.emit({
                'scan_id': scan_config.scan_id,
                'results': fallback_result
            })
            
        except Exception as e:
            self.logger.error(f"Error creating fallback result: {e}")

    def _parse_progress_from_output(self, line: str, last_progress: int) -> Optional[int]:
        """
        Парсит прогресс из вывода nmap
        """
        try:
            # Пример строки: "Nmap scan report for scanme.nmap.org (45.33.32.156)"
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
        except:
            pass
        return None

    def _build_nmap_command(self, scan_config: ScanConfig) -> str:
        """
        Строит команду nmap из конфигурации
        """
        cmd_parts = ["nmap"]
        
        # Для сканирования сети добавляем traceroute и discovery
        if any('/' in target for target in scan_config.targets) or \
           any('-' in target for target in scan_config.targets):
            cmd_parts.append("--traceroute")  # Трассировка маршрута
            cmd_parts.append("--reason")      # Причины решений
        
        # Базовые опции производительности
        if scan_config.timing_template:
            cmd_parts.append(f"-{scan_config.timing_template}")
        
        # Опции сканирования на основе типа
        if scan_config.scan_type.value == "quick":
            cmd_parts.append("-F")  # Быстрое сканирование
        elif scan_config.scan_type.value == "stealth":
            cmd_parts.append("-sS")  # SYN сканирование
        elif scan_config.scan_type.value == "comprehensive":
            cmd_parts.extend(["-sS", "-sV", "-O", "-A"])
        
        # Дополнительные опции
        if scan_config.service_version:
            cmd_parts.append("-sV")
        
        if scan_config.os_detection:
            cmd_parts.append("-O")
        
        if scan_config.script_scan:
            cmd_parts.append("-sC")
        
        # Диапазон портов
        if scan_config.port_range:
            cmd_parts.append(f"-p {scan_config.port_range}")
        
        # Пользовательская команда (имеет приоритет)
        if (scan_config.scan_type.value == "custom" and 
            scan_config.custom_command and 
            scan_config.custom_command.strip()):
            custom_cmd = scan_config.custom_command.strip()
            if "-oX" not in custom_cmd:
                # Добавляем вывод в XML если его нет
                custom_cmd += " -oX -"
            return custom_cmd
        
        # Цели
        cmd_parts.extend(scan_config.targets)
        
        # Вывод в XML в stdout - ОБЯЗАТЕЛЬНО!
        cmd_parts.append("-oX -")
        
        # НЕ добавляем -v, так как он может конфликтовать с XML выводом
        
        return " ".join(cmd_parts)
    
    def _parse_xml_results(self, xml_file_path: str, scan_config: ScanConfig) -> ScanResult:
        """
        Парсит XML результаты nmap
        """
        try:
            # Проверяем существует ли файл и не пустой ли он
            if not os.path.exists(xml_file_path) or os.path.getsize(xml_file_path) == 0:
                self.logger.warning("XML file is empty or does not exist")
                return ScanResult(
                    scan_id=scan_config.scan_id,
                    config=scan_config,
                    hosts=[],
                    status="error",
                    raw_xml=""
                )
            
            with open(xml_file_path, 'r') as f:
                xml_content = f.read()
            
            # Проверяем что XML не пустой
            if not xml_content.strip():
                self.logger.warning("XML content is empty")
                return ScanResult(
                    scan_id=scan_config.scan_id,
                    config=scan_config,
                    hosts=[],
                    status="error", 
                    raw_xml=""
                )
            
            from core.result_parser import NmapResultParser
            parser = NmapResultParser.get_instance()
            
            return parser.parse_xml(xml_content, scan_config)
            
        except Exception as e:
            self.logger.error(f"Error parsing XML results: {e}")
            # Возвращаем пустой результат в случае ошибки
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
                # Останавливаем процесс
                process.terminate()
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except:
                    pass
            
            finally:
                # Очищаем временный файл
                if 'xml_file' in process_info:
                    try:
                        os.unlink(process_info['xml_file'])
                    except:
                        pass
                
                if scan_id in self.active_processes:
                    del self.active_processes[scan_id]
                
            self.logger.info(f"Scan stopped: {scan_id}")
