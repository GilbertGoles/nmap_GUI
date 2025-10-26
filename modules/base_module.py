from PyQt6.QtWidgets import QWidget
from abc import ABC
from core.event_bus import EventBus

class BaseTabModule(QWidget, ABC):
    """Базовый класс для модулей-вкладок"""
    
    TAB_NAME = "Unnamed Tab"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        QWidget.__init__(self)
        self.event_bus = event_bus
        self.dependencies = dependencies or {}
        self._setup_event_handlers()
        self._create_ui()
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий (можно переопределить)"""
        pass
    
    def _create_ui(self):
        """Создает UI компонент (должен быть переопределен)"""
        pass
