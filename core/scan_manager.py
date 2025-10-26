import threading
import queue
import uuid
import time
from typing import Dict, List
from enum import Enum

from core.event_bus import EventBus
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
        """Выполняет сканирование"""
        try:
            job.status = ScanStatus.RUNNING
            
            # Здесь будет интеграция с nmap_engine
            # Пока эмулируем прогресс
            for i in range(10):
                if job.status == ScanStatus.PAUSED:
                    while job.status == ScanStatus.PAUSED:
                        time.sleep(0.5)
                
                if job.status == ScanStatus.STOPPED:
                    break
                    
                job.progress = (i + 1) * 10
                self.event_bus.scan_progress.emit({
                    'scan_id': job.id,
                    'progress': job.progress,
                    'status': 'running'
                })
                time.sleep(1)
            
            if job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.COMPLETED
                job.progress = 100
                
                self.event_bus.scan_completed.emit({
                    'scan_id': job.id,
                    'results': job.result
                })
                
        except Exception as e:
            job.status = ScanStatus.ERROR
            self.event_bus.scan_progress.emit({
                'scan_id': job.id,
                'progress': 0,
                'status': f'error: {e}'
            })
    
    def _on_scan_paused(self, data):
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            self.active_scans[scan_id].status = ScanStatus.PAUSED
    
    def _on_scan_resumed(self, data):
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            self.active_scans[scan_id].status = ScanStatus.RUNNING
    
    def _on_scan_stopped(self, data):
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            self.active_scans[scan_id].status = ScanStatus.STOPPED
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Возвращает статус сканирования"""
        return self.active_scans.get(scan_id, ScanStatus.ERROR)
    
    def get_queue_size(self) -> int:
        """Возвращает размер очереди"""
        return self.scan_queue.qsize()
