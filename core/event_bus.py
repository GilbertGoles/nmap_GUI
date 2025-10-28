import logging
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Any, Dict, List, Callable

class EventBus(QObject):
    """Центральная шина событий для межмодульной коммуникации"""
    
    # Основные события сканирования
    scan_started = pyqtSignal(dict)  # {scan_id, config}
    scan_progress = pyqtSignal(dict)  # {scan_id, progress, status}
    scan_completed = pyqtSignal(dict)  # {scan_id, results}
    scan_paused = pyqtSignal(dict)    # {scan_id}
    scan_resumed = pyqtSignal(dict)   # {scan_id}  
    scan_stopped = pyqtSignal(dict)   # {scan_id}
    scan_failed = pyqtSignal(dict)    # {scan_id, error}
    
    # События данных
    targets_updated = pyqtSignal(list)  # [targets]
    results_updated = pyqtSignal(dict)  # {scan_id, results}
    
    # События UI
    command_updated = pyqtSignal(str)   # nmap_command
    status_message = pyqtSignal(str)    # message
    notification = pyqtSignal(dict)     # {type, title, message}

    def __init__(self):
        super().__init__()
        self._listeners: Dict[str, List[Callable]] = {}
        self.logger = logging.getLogger('core.event_bus')
        self.logger.info("EventBus initialized")
    
    def subscribe(self, event_type: str, callback: Callable):
        """Подписка на кастомные события"""
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)
    
    def publish(self, event_type: str, data: Any = None):
        """Публикация кастомных событий"""
        if event_type in self._listeners:
            for callback in self._listeners[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    self.logger.error(f"Error in event listener: {e}")

    # Методы для эмитации событий с логированием
    def emit_scan_started(self, scan_data: Dict[str, Any]):
        """Эмитирует событие начала сканирования"""
        scan_id = scan_data.get('scan_id', 'unknown')
        targets = scan_data.get('config', {}).get('targets', [])
        self.logger.info(f"📢 [EventBus] Emitting scan_started: {scan_id}, targets: {targets}")
        self.scan_started.emit(scan_data)
    
    def emit_scan_completed(self, scan_data: Dict[str, Any]):
        """Эмитирует событие завершения сканирования"""
        scan_id = scan_data.get('scan_id', 'unknown')
        has_results = scan_data.get('results') is not None
        host_count = len(scan_data.get('results', {}).get('hosts', [])) if has_results else 0
        self.logger.info(f"📢 [EventBus] Emitting scan_completed: {scan_id}, has_results: {has_results}, hosts: {host_count}")
        self.scan_completed.emit(scan_data)
    
    def emit_scan_failed(self, scan_data: Dict[str, Any]):
        """Эмитирует событие ошибки сканирования"""
        scan_id = scan_data.get('scan_id', 'unknown')
        error = scan_data.get('error', 'unknown error')
        self.logger.info(f"📢 [EventBus] Emitting scan_failed: {scan_id}, error: {error}")
        self.scan_failed.emit(scan_data)
    
    def emit_results_updated(self, results_data: Dict[str, Any]):
        """Эмитирует событие обновления результатов"""
        scan_id = results_data.get('scan_id', 'unknown')
        has_results = results_data.get('results') is not None
        host_count = len(results_data.get('results', {}).get('hosts', [])) if has_results else 0
        self.logger.info(f"📢 [EventBus] Emitting results_updated: {scan_id}, has_results: {has_results}, hosts: {host_count}")
        self.results_updated.emit(results_data)
    
    def emit_scan_progress(self, progress_data: Dict[str, Any]):
        """Эмитирует событие прогресса сканирования"""
        scan_id = progress_data.get('scan_id', 'unknown')
        progress = progress_data.get('progress', 0)
        status = progress_data.get('status', '')
        self.logger.debug(f"📢 [EventBus] Emitting scan_progress: {scan_id}, progress: {progress}%, status: {status}")
        self.scan_progress.emit(progress_data)
    
    def emit_targets_updated(self, targets: List[str]):
        """Эмитирует событие обновления целей"""
        self.logger.info(f"📢 [EventBus] Emitting targets_updated: {len(targets)} targets")
        self.targets_updated.emit(targets)
    
    def emit_status_message(self, message: str):
        """Эмитирует статусное сообщение"""
        self.logger.info(f"📢 [EventBus] Emitting status_message: {message}")
        self.status_message.emit(message)
    
    def emit_notification(self, notification_data: Dict[str, Any]):
        """Эмитирует уведомление"""
        title = notification_data.get('title', 'No title')
        self.logger.info(f"📢 [EventBus] Emitting notification: {title}")
        self.notification.emit(notification_data)

    # Автоматическое логирование всех стандартных сигналов
    def _log_signal_emit(self, signal_name: str, data: dict):
        """Логирует эмитацию сигнала"""
        scan_id = data.get('scan_id', 'unknown')
        self.logger.debug(f"📢 [EventBus] Signal emitted: {signal_name}, scan_id: {scan_id}")

    # Переопределяем методы эмитации для автоматического логирования
    def _emit_scan_started(self, data):
        self._log_signal_emit('scan_started', data)
        super().scan_started.emit(data)
    
    def _emit_scan_completed(self, data):
        self._log_signal_emit('scan_completed', data)
        super().scan_completed.emit(data)
    
    def _emit_results_updated(self, data):
        self._log_signal_emit('results_updated', data)
        super().results_updated.emit(data)
