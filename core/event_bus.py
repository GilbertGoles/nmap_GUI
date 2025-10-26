from PyQt6.QtCore import QObject, pyqtSignal
from typing import Any, Callable, Dict, List

class EventBus(QObject):
    """Центральная шина событий для межмодульной коммуникации"""
    
    # Основные события сканирования
    scan_started = pyqtSignal(dict)  # {scan_id, config}
    scan_progress = pyqtSignal(dict)  # {scan_id, progress, status}
    scan_completed = pyqtSignal(dict)  # {scan_id, results}
    scan_paused = pyqtSignal(dict)    # {scan_id}
    scan_resumed = pyqtSignal(dict)   # {scan_id}  
    scan_stopped = pyqtSignal(dict)   # {scan_id}
    
    # События данных
    targets_updated = pyqtSignal(list)  # [targets]
    results_updated = pyqtSignal(dict)  # {scan_id, results}
    
    # События UI
    command_updated = pyqtSignal(str)   # nmap_command
    
    def __init__(self):
        super().__init__()
        self._listeners: Dict[str, List[Callable]] = {}
    
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
                    print(f"Error in event listener: {e}")
