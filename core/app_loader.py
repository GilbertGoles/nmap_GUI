import os
import importlib
import logging
from PyQt6.QtWidgets import QMainWindow, QTabWidget, QVBoxLayout, QWidget
from core.event_bus import EventBus

class ApplicationLoader:
    def __init__(self):
        self.event_bus = EventBus()
        self.modules = {}
        self.logger = self._setup_logging()
        
    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)
    
    def load_application(self):
        """Загружает основное окно приложения со всеми модулями"""
        try:
            # Создаем главное окно
            main_window = QMainWindow()
            main_window.setWindowTitle("NMAP GUI Scanner")
            main_window.setGeometry(100, 100, 1400, 900)
            
            # Создаем центральный виджет с вкладками
            central_widget = QWidget()
            main_window.setCentralWidget(central_widget)
            layout = QVBoxLayout(central_widget)
            
            # Создаем виджет вкладок
            tab_widget = QTabWidget()
            layout.addWidget(tab_widget)
            
            # Загружаем основные модули
            self._load_core_modules()
            
            # Загружаем модули-вкладки
            self._load_tab_modules(tab_widget)
            
            self.logger.info("Application loaded successfully")
            return main_window
            
        except Exception as e:
            self.logger.error(f"Failed to load application: {e}")
            return None
    
    def _load_core_modules(self):
        """Загружает основные системные модули"""
        core_modules = [
            'scan_manager',
            'profile_manager',
            'result_parser'
        ]
        
        for module_name in core_modules:
            try:
                module = importlib.import_module(f'core.{module_name}')
                if hasattr(module, 'get_instance'):
                    instance = module.get_instance(self.event_bus)
                    self.modules[module_name] = instance
                    self.logger.info(f"Loaded core module: {module_name}")
            except Exception as e:
                self.logger.error(f"Failed to load core module {module_name}: {e}")
    
    def _load_tab_modules(self, tab_widget):
        """Загружает модули в виде вкладок"""
        tab_modules = [
            'scan_launcher',
            'target_manager', 
            'results_table',
            'monitoring'
        ]
        
        for module_name in tab_modules:
            try:
                module = importlib.import_module(f'modules.{module_name}')
                if hasattr(module, 'create_tab'):
                    tab = module.create_tab(self.event_bus, self.modules)
                    if tab:
                        tab_widget.addTab(tab, getattr(tab, 'TAB_NAME', module_name))
                        self.logger.info(f"Loaded tab module: {module_name}")
            except Exception as e:
                self.logger.error(f"Failed to load tab module {module_name}: {e}")
