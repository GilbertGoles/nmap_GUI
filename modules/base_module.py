from PyQt6.QtWidgets import QWidget
from core.event_bus import EventBus

class BaseTabModule(QWidget):
    """Базовый класс для модулей-вкладок"""
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        print(f"🟣 [BaseTabModule] Initializing base module")
        super().__init__()
        self.event_bus = event_bus
        self.dependencies = dependencies or {}
        
        # Вызываем методы инициализации
        self._setup_event_handlers()
        self._create_ui()
        print(f"🟣 [BaseTabModule] Initialization completed")
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий (можно переопределить)"""
        pass
    
    def _create_ui(self):
        """Создает UI компонент (должен быть переопределен)"""
        pass
