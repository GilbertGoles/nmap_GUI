from PyQt6.QtWidgets import QWidget
from abc import ABC, abstractmethod
from core.event_bus import EventBus

class BaseModule(ABC):
    """Базовый класс для всех модулей"""
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        self.event_bus = event_bus
        self.dependencies = dependencies or {}
        self._setup_event_handlers()
    
    @abstractmethod
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        pass

class BaseTabModule(BaseModule, QWidget):
    """Базовый класс для модулей-вкладок"""
    
    TAB_NAME = "Unnamed Tab"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        QWidget.__init__(self)
        BaseModule.__init__(self, event_bus, dependencies)
        self._create_ui()
    
    @abstractmethod
    def _create_ui(self):
        """Создает UI компонент"""
        pass
