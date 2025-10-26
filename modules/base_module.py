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
    
    @abstractmethod
    def get_ui(self) -> QWidget:
        """Возвращает UI компонент модуля"""
        pass

class BaseTabModule(BaseModule):
    """Базовый класс для модулей-вкладок"""
    
    TAB_NAME = "Unnamed Tab"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self._widget = None
    
    def get_ui(self) -> QWidget:
        """Возвращает виджет вкладки"""
        if self._widget is None:
            self._widget = self._create_ui()
        return self._widget
    
    @abstractmethod
    def _create_ui(self) -> QWidget:
        """Создает UI компонент"""
        pass
