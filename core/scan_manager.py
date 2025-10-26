import threading
import queue
import uuid
import time
from typing import Dict, List
from enum import Enum

from core.event_bus import EventBus
from core.nmap_engine import NmapEngine
from shared.models.scan_config import ScanConfig
from shared.models.scan_result import ScanResult

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running" 
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"

class ScanJob:
    def __init__(self, config: ScanConfig):
        self.id = str(uuid.uuid4())
        self.config = config
        self.status = ScanStatus.PENDING
        self.result = None
        self.progress = 0
        self.thread = None
        self.nmap_engine = None

class ScanManager:
    _instance = None
    
    @classmethod
    def get_instance(cls, event_bus: EventBus):
        if cls._instance is None:
            cls._instance = ScanManager(event_bus)
        return cls._instance
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.scan_queue = queue.Queue()
        self.active_scans: Dict[str, ScanJob] = {}
        self.scan_history: List[ScanJob] = []
        self.is_running = True
        self.nmap_engine = NmapEngine.get_instance(event_bus)
        
        # Запускаем worker thread
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()
        
        # Подписываемся на события
        self.event_bus.scan_paused.connect(self._on_scan_paused)
        self.event_bus.scan_resumed.connect(self._on_scan_resumed)
        self.event_bus.scan_stopped.connect(self._on_scan_stopped)
    
    def submit_scan(self, config: ScanConfig) -> str:
        """Добавляет сканирование в очередь"""
        job = ScanJob(config)
        self.active_scans[job.id] = job
        self.scan_queue.put(job)
        
        self.event_bus.scan_started.emit({
            'scan_id': job.id,
            'config': config
        })
        
        return job.id
    
    def _process_queue(self):
        """Обрабатывает очередь сканирований"""
        while self.is_running:
            try:
                job = self.scan_queue.get(timeout=1)
                self._execute_scan(job)
                self.scan_queue.task_done()
            except queue.Empty:
                continue
    
    def _execute_scan(self, job: ScanJob):
        """Выполняет сканирование через nmap движок"""
        try:
            job.status = ScanStatus.RUNNING
            
            # Callback для прогресса
            def progress_callback(data):
                if job.status == ScanStatus.PAUSED:
                    while job.status == ScanStatus.PAUSED:
                        time.sleep(0.5)
                
                if job.status == ScanStatus.STOPPED:
                    # Останавливаем сканирование
                    self.nmap_engine.stop_scan(job.id)
                    return
                
                job.progress = data.get('progress', job.progress)
                self.event_bus.scan_progress.emit({
                    'scan_id': job.id,
                    'progress': job.progress,
                    'status': data.get('status', ''),
                    'remaining': data.get('remaining', ''),
                    'raw_line': data.get('raw_line', '')
                })
            
            # Callback для вывода
            def output_callback(line):
                if line and not line.startswith('<?xml'):
                    self.event_bus.scan_progress.emit({
                        'scan_id': job.id,
                        'progress': job.progress,
                        'status': f'Output: {line[:100]}...' if len(line) > 100 else line,
                        'raw_line': line
                    })
            
            # Выполняем сканирование
            job.result = self.nmap_engine.execute_scan(
                job.config,
                progress_callback=progress_callback,
                output_callback=output_callback
            )
            
            if job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.COMPLETED
                job.progress = 100
                
                self.event_bus.scan_completed.emit({
                    'scan_id': job.id,
                    'results': job.result
                })
                
                # Добавляем в историю
                self.scan_history.append(job)
                
        except Exception as e:
            job.status = ScanStatus.ERROR
            self.event_bus.scan_progress.emit({
                'scan_id': job.id,
                'progress': 0,
                'status': f'error: {e}'
            })
    
    def _on_scan_paused(self, data):
        """Обрабатывает паузу сканирования"""
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            job = self.active_scans[scan_id]
            job.status = ScanStatus.PAUSED
            self.nmap_engine.pause_scan(scan_id)
    
    def _on_scan_resumed(self, data):
        """Обрабатывает возобновление сканирования"""
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            job = self.active_scans[scan_id]
            job.status = ScanStatus.RUNNING
            self.nmap_engine.resume_scan(scan_id)
    
    def _on_scan_stopped(self, data):
        """Обрабатывает остановку сканирования"""
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            job = self.active_scans[scan_id]
            job.status = ScanStatus.STOPPED
            self.nmap_engine.stop_scan(scan_id)
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Возвращает статус сканирования"""
        return self.active_scans.get(scan_id, ScanStatus.ERROR).status
    
    def get_queue_size(self) -> int:
        """Возвращает размер очереди"""
        return self.scan_queue.qsize()
    
    def get_active_scans_count(self) -> int:
        """Возвращает количество активных сканирований"""
        return len([job for job in self.active_scans.values() 
                   if job.status in [ScanStatus.RUNNING, ScanStatus.PAUSED]])
    
    def get_scan_history(self, limit: int = 10) -> List[ScanJob]:
        """Возвращает историю сканирований"""
        return self.scan_history[-limit:] if self.scan_history else []
    
    def validate_nmap(self) -> bool:
        """Проверяет доступность nmap"""
        return self.nmap_engine.validate_nmap_installation()
    
    def get_nmap_version(self) -> str:
        """Возвращает версию nmap"""
        return self.nmap_engine.get_nmap_version()
