import os
import importlib
import logging
from PyQt6.QtWidgets import QMainWindow, QTabWidget, QVBoxLayout, QWidget, QMessageBox, QLabel
from core.event_bus import EventBus
from core.scan_manager import ScanManager
from core.profile_manager import ProfileManager
from core.result_parser import NmapResultParser

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
            QMessageBox.critical(None, "Error", f"Failed to load application: {e}")
            return None
    
    def _load_core_modules(self):
        """Загружает основные системные модули"""
        try:
            # Инициализируем основные модули вручную
            self.modules['scan_manager'] = ScanManager.get_instance(self.event_bus)
            self.modules['profile_manager'] = ProfileManager.get_instance(self.event_bus)
            self.modules['result_parser'] = NmapResultParser.get_instance(self.event_bus)
            
            self.logger.info("Core modules loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load core modules: {e}")
            raise

    def _load_tab_modules(self, tab_widget):
        """Загружает модули в виде вкладок"""
        tab_modules = [
            ('scan_launcher', 'Scan Launcher'),
            ('target_manager', 'Target Manager'), 
            ('results_table', 'Results'),
            ('visualization', 'Visualization'),  # Добавляем визуализацию
            ('monitoring', 'Monitoring')
        ]
        
        for module_name, tab_name in tab_modules:
            try:
                # Динамически импортируем модуль
                module = importlib.import_module(f'modules.{module_name}')
                
                # Создаем вкладку
                tab_widget_instance = module.create_tab(self.event_bus, self.modules)
                if tab_widget_instance and isinstance(tab_widget_instance, QWidget):
                    tab_widget.addTab(tab_widget_instance, tab_name)
                    self.logger.info(f"Loaded tab module: {module_name}")
                else:
                    self.logger.warning(f"Module {module_name} returned invalid type")
                    # Создаем заглушку
                    stub = QWidget()
                    layout = QVBoxLayout(stub)
                    layout.addWidget(QLabel(f"Module {module_name} failed to load"))
                    tab_widget.addTab(stub, f"{tab_name} (Error)")
                    
            except Exception as e:
                self.logger.error(f"Failed to load tab module {module_name}: {e}")
                # Создаем заглушку для вкладки
                stub_widget = QWidget()
                stub_layout = QVBoxLayout(stub_widget)
                stub_layout.addWidget(QLabel(f"Failed to load {tab_name}"))
                stub_layout.addWidget(QLabel(f"Error: {str(e)}"))
                tab_widget.addTab(stub_widget, f"{tab_name} (Error)")
