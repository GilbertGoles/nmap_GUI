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
        self.output_handlers = {}
        
    def _setup_logging(self):
        """Настройка логирования"""
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(__name__)
    
    def execute_scan(self, scan_config: ScanConfig, 
                    progress_callback: Optional[Callable] = None,
                    output_callback: Optional[Callable] = None) -> ScanResult:
        """
        Выполняет nmap сканирование
        
        Args:
            scan_config: Конфигурация сканирования
            progress_callback: Callback для прогресса
            output_callback: Callback для вывода
            
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
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            # Сохраняем процесс
            self.active_processes[scan_config.scan_id] = {
                'process': process,
                'config': scan_config,
                'start_time': datetime.now(),
                'xml_file': xml_file_path
            }
            
            # Запускаем потоки для чтения вывода
            stdout_thread = threading.Thread(
                target=self._read_stdout,
                args=(process, scan_config, output_callback)
            )
            stderr_thread = threading.Thread(
                target=self._read_stderr,
                args=(process, scan_config)
            )
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            
            stdout_thread.start()
            stderr_thread.start()
            
            # Ждем завершения процесса
            return_code = process.wait()
            
            # Читаем XML результаты
            scan_result = self._parse_xml_results(xml_file_path, scan_config)
            
            # Очищаем
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
            raise
    
    def execute_scan_async(self, scan_config: ScanConfig,
                          progress_callback: Optional[Callable] = None,
                          output_callback: Optional[Callable] = None) -> threading.Thread:
        """
        Выполняет nmap сканирование асинхронно
        
        Returns:
            threading.Thread: Поток выполнения
        """
        thread = threading.Thread(
            target=self._async_scan_wrapper,
            args=(scan_config, progress_callback, output_callback)
        )
        thread.daemon = True
        thread.start()
        return thread
    
    def _async_scan_wrapper(self, scan_config: ScanConfig,
                           progress_callback: Optional[Callable],
                           output_callback: Optional[Callable]):
        """Обертка для асинхронного выполнения"""
        try:
            result = self.execute_scan(scan_config, progress_callback, output_callback)
            
            # Публикуем событие завершения
            if self.event_bus:
                self.event_bus.scan_completed.emit({
                    'scan_id': scan_config.scan_id,
                    'results': result
                })
                
        except Exception as e:
            self.logger.error(f"Async scan error: {e}")
            if self.event_bus:
                self.event_bus.scan_progress.emit({
                    'scan_id': scan_config.scan_id,
                    'progress': 0,
                    'status': f'error: {e}'
                })
    
    def _build_nmap_command(self, scan_config: ScanConfig) -> str:
        """
        Строит команду nmap из конфигурации
        
        Args:
            scan_config: Конфигурация сканирования
            
        Returns:
            str: Команда nmap
        """
        cmd_parts = ["nmap"]
        
        # Базовые опции производительности
        if scan_config.timing_template:
            cmd_parts.append(f"-{scan_config.timing_template}")
        
        if scan_config.threads and scan_config.threads > 1:
            cmd_parts.append(f"--min-parallelism {scan_config.threads}")
        
        # Опции сканирования на основе типа
        if scan_config.scan_type.value == "quick":
            cmd_parts.append("-F")  # Быстрое сканирование
        elif scan_config.scan_type.value == "stealth":
            cmd_parts.append("-sS")  # SYN сканирование
        elif scan_config.scan_type.value == "comprehensive":
            cmd_parts.extend(["-sS", "-sV", "-O", "-A", "--script=default"])
        
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
            # Используем пользовательскую команду, но добавляем вывод в XML
            custom_cmd = scan_config.custom_command.strip()
            if "-oX" not in custom_cmd:
                custom_cmd += " -oX -"
            return custom_cmd
        
        # Цели
        cmd_parts.extend(scan_config.targets)
        
        # Вывод в XML в stdout
        cmd_parts.append("-oX -")
        
        # Добавляем вывод прогресса
        cmd_parts.append("--stats-every 1s")
        
        return " ".join(cmd_parts)
    
    def _read_stdout(self, process: subprocess.Popen, scan_config: ScanConfig, 
                    output_callback: Optional[Callable]):
        """Читает stdout процесса nmap"""
        try:
            xml_content = []
            in_xml = False
            
            for line in process.stdout:
                line = line.strip()
                
                if output_callback:
                    output_callback(line)
                
                # Определяем начало XML
                if line.startswith('<?xml'):
                    in_xml = True
                
                if in_xml:
                    xml_content.append(line)
                
                # Парсим прогресс из вывода
                progress_info = self._parse_progress_line(line)
                if progress_info and self.event_bus:
                    self.event_bus.scan_progress.emit({
                        'scan_id': scan_config.scan_id,
                        'progress': progress_info.get('percent', 0),
                        'status': progress_info.get('status', ''),
                        'remaining': progress_info.get('remaining', ''),
                        'raw_line': line
                    })
            
            # Сохраняем XML для парсинга
            if xml_content and scan_config.scan_id in self.active_processes:
                xml_file = self.active_processes[scan_config.scan_id]['xml_file']
                with open(xml_file, 'w') as f:
                    f.write('\n'.join(xml_content))
                    
        except Exception as e:
            self.logger.error(f"Error reading stdout: {e}")
    
    def _read_stderr(self, process: subprocess.Popen, scan_config: ScanConfig):
        """Читает stderr процесса nmap"""
        try:
            for line in process.stderr:
                line = line.strip()
                if line:
                    self.logger.warning(f"Nmap stderr [{scan_config.scan_id}]: {line}")
                    
                    # Публикуем ошибки через event bus
                    if self.event_bus:
                        self.event_bus.scan_progress.emit({
                            'scan_id': scan_config.scan_id,
                            'progress': 0,
                            'status': f'warning: {line}',
                            'raw_line': line
                        })
        except Exception as e:
            self.logger.error(f"Error reading stderr: {e}")
    
    def _parse_progress_line(self, line: str) -> Optional[dict]:
        """
        Парсит строку прогресса nmap
        
        Args:
            line: Строка вывода nmap
            
        Returns:
            dict: Информация о прогрессе или None
        """
        try:
            # Пример: "Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan"
            if line.startswith("Stats:"):
                parts = line.split(';')
                if len(parts) >= 2:
                    time_part = parts[0].replace("Stats:", "").strip()
                    progress_part = parts[1].strip()
                    
                    # Парсим время
                    time_elapsed = time_part.split()[0]
                    
                    # Парсим прогресс хостов
                    hosts_match = None
                    if "completed" in progress_part:
                        import re
                        hosts_match = re.search(r'(\d+) hosts completed', progress_part)
                    
                    percent = 0
                    if hosts_match:
                        completed_hosts = int(hosts_match.group(1))
                        # Это упрощенная логика - в реальности нужно знать общее количество хостов
                        percent = min(completed_hosts * 10, 100)  # Эвристика
                    
                    return {
                        'percent': percent,
                        'status': progress_part,
                        'elapsed': time_elapsed,
                        'raw': line
                    }
            
            # Другие форматы прогресса nmap
            elif "scan report for" in line.lower():
                return {
                    'percent': 0,
                    'status': f'Scanning: {line}',
                    'raw': line
                }
                
        except Exception as e:
            self.logger.debug(f"Error parsing progress line: {e}")
        
        return None
    
    def _parse_xml_results(self, xml_file_path: str, scan_config: ScanConfig) -> ScanResult:
        """
        Парсит XML результаты nmap
        
        Args:
            xml_file_path: Путь к XML файлу
            scan_config: Конфигурация сканирования
            
        Returns:
            ScanResult: Результаты сканирования
        """
        try:
            from core.result_parser import NmapResultParser
            parser = NmapResultParser.get_instance()
            
            with open(xml_file_path, 'r') as f:
                xml_content = f.read()
            
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
                # Останавливаем процесс и все дочерние процессы
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                else:
                    process.terminate()
                
                # Ждем завершения
                process.wait(timeout=5)
                
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    else:
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
                
                del self.active_processes[scan_id]
                
            self.logger.info(f"Scan stopped: {scan_id}")
    
    def pause_scan(self, scan_id: str):
        """Приостанавливает сканирование"""
        if scan_id in self.active_processes:
            process = self.active_processes[scan_id]['process']
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGSTOP)
                else:
                    # На Windows приостановка сложнее
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.suspend()
            except Exception as e:
                self.logger.error(f"Error pausing scan: {e}")
    
    def resume_scan(self, scan_id: str):
        """Возобновляет сканирование"""
        if scan_id in self.active_processes:
            process = self.active_processes[scan_id]['process']
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(process.pid), signal.SIGCONT)
                else:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.resume()
            except Exception as e:
                self.logger.error(f"Error resuming scan: {e}")
    
    def get_scan_status(self, scan_id: str) -> dict:
        """Возвращает статус сканирования"""
        if scan_id in self.active_processes:
            process_info = self.active_processes[scan_id]
            process = process_info['process']
            
            return {
                'running': process.poll() is None,
                'return_code': process.returncode,
                'start_time': process_info['start_time'],
                'config': process_info['config']
            }
        else:
            return {'running': False, 'return_code': None}
    
    def validate_nmap_installation(self) -> bool:
        """Проверяет наличие nmap в системе"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def get_nmap_version(self) -> str:
        """Возвращает версию nmap"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.startswith('Nmap version'):
                        return line.strip()
            return "Unknown"
        except:
            return "Not installed"
