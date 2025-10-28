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
        
        # Подписываемся на события
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_paused.connect(self._on_scan_paused)
        self.event_bus.scan_resumed.connect(self._on_scan_resumed)
        self.event_bus.scan_stopped.connect(self._on_scan_stopped)
        
        # Запускаем worker thread
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()
    
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
            # === ИСПРАВЛЕНИЕ: Убедимся, что ScanConfig содержит уникальный ID из ScanJob ===
            # Чтобы NmapEngine логировал правильный ID вместо "scan_1"
            job.config.scan_id = job.id 
            # ===============================================================================
            
            job.status = ScanStatus.RUNNING
            
            # Выполняем реальное сканирование
            job.result = self.nmap_engine.execute_scan(job.config)
            
            if job.status == ScanStatus.RUNNING:
                job.status = ScanStatus.COMPLETED
                job.progress = 100
                
                # Публикуем завершение сканирования
                self.event_bus.scan_completed.emit({
                    'scan_id': job.id,
                    'results': job.result,
                    'status': ScanStatus.COMPLETED.value
                })
                
                # Также публикуем обновление результатов для других модулей
                self.event_bus.results_updated.emit({
                    'scan_id': job.id,
                    'results': job.result
                })
                
                # Добавляем в историю
                self.scan_history.append(job)
                
                # Удаляем из активных сканирований НЕМЕДЛЕННО после отправки сигнала
                if job.id in self.active_scans:
                    del self.active_scans[job.id]  # <-- Это решает проблему "Stopped scan"
                
        except Exception as e:
            job.status = ScanStatus.ERROR
            self.event_bus.scan_progress.emit({
                'scan_id': job.id,
                'progress': 0,
                'status': f'error: {e}'
            })
            
            # Публикуем ошибку как обновление результатов
            self.event_bus.results_updated.emit({
                'scan_id': job.id,
                'results': None,
                'error': str(e)
            })
            
            # В случае ошибки тоже удаляем из активных
            if job.id in self.active_scans:
                del self.active_scans[job.id]
    
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса"""
        scan_id = data.get('scan_id')
        progress = data.get('progress', 0)
        
        if scan_id in self.active_scans:
            job = self.active_scans[scan_id]
            job.progress = progress
    
    def _on_scan_paused(self, data):
        """Обрабатывает паузу сканирования"""
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            self.active_scans[scan_id].status = ScanStatus.PAUSED
    
    def _on_scan_resumed(self, data):
        """Обрабатывает возобновление сканирования"""
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            self.active_scans[scan_id].status = ScanStatus.RUNNING
    
    def _on_scan_stopped(self, data):
        """Обрабатывает остановку сканирования"""
        scan_id = data.get('scan_id')
        if scan_id in self.active_scans:
            job = self.active_scans[scan_id]
            job.status = ScanStatus.STOPPED
            
            # Публикуем событие обновления результатов с пустым результатом
            self.event_bus.results_updated.emit({
                'scan_id': scan_id,
                'results': None,
                'status': 'stopped'
            })
            
            # Останавливаем сканирование в движке
            self.nmap_engine.stop_scan(scan_id)
            
            # Удаляем из активных сканирований НЕМЕДЛЕННО
            del self.active_scans[scan_id]
    
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Возвращает статус сканирования"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id].status
        return ScanStatus.ERROR
    
    def get_queue_size(self) -> int:
        """Возвращает размер очереди"""
        return self.scan_queue.qsize()
    
    def get_active_scans(self) -> Dict[str, ScanJob]:
        """Возвращает активные сканирования"""
        return self.active_scans.copy()
    
    def get_scan_history(self, limit: int = None) -> List[ScanJob]:
        """Возвращает историю сканирований"""
        if limit:
            return self.scan_history[-limit:]
        return self.scan_history
    
    def pause_scan(self, scan_id: str):
        """Приостанавливает сканирование"""
        if scan_id in self.active_scans and self.active_scans[scan_id].status == ScanStatus.RUNNING:
            self.active_scans[scan_id].status = ScanStatus.PAUSED
            # Note: NmapEngine не поддерживает паузу напрямую, но можно реализовать через сигналы
    
    def resume_scan(self, scan_id: str):
        """Возобновляет сканирование"""
        if scan_id in self.active_scans and self.active_scans[scan_id].status == ScanStatus.PAUSED:
            self.active_scans[scan_id].status = ScanStatus.RUNNING
            # Note: NmapEngine не поддерживает возобновление напрямую, но можно реализовать через сигналы
    
    def stop_scan(self, scan_id: str):
        """Останавливает сканирование"""
        if scan_id in self.active_scans:
            self._on_scan_stopped({'scan_id': scan_id})
    
    def shutdown(self):
        """Корректное завершение работы менеджера"""
        self.is_running = False
        
        # Останавливаем все активные сканирования
        for scan_id in list(self.active_scans.keys()):
            self.stop_scan(scan_id)
