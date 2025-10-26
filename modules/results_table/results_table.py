from PyQt6.QtWidgets import (QVBoxLayout, QGroupBox,
                             QLabel, QTableWidget, QTableWidgetItem,
                             QHeaderView, QTextEdit)
from PyQt6.QtCore import pyqtSlot
from modules.base_module import BaseTabModule
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ResultsTableTab(event_bus, dependencies)

class ResultsTableTab(BaseTabModule):
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_completed.connect(self._on_scan_completed)
        self.event_bus.results_updated.connect(self._on_results_updated)
    
    def _create_ui(self):
        """Создает UI компонент таблицы результатов"""
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("Scan Results")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Таблица результатов
        table_group = QGroupBox("Scan Results")
        table_layout = QVBoxLayout(table_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "Status", "OS", "Open Ports", "Services"
        ])
        
        # Настройка таблицы
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        table_layout.addWidget(self.results_table)
        layout.addWidget(table_group)
        
        # Детальная информация
        details_group = QGroupBox("Host Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_group)
        
        # Статус
        self.status_label = QLabel("No results available")
        layout.addWidget(self.status_label)
        
        # Инициализируем результаты
        self.current_results = None
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results:
            self.current_results = results
            self._display_results(results)
    
    @pyqtSlot(dict)
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results:
            self.current_results = results
            self._display_results(results)
    
    def _display_results(self, results):
        """Отображает результаты в таблице"""
        if not results or not hasattr(results, 'hosts'):
            self.status_label.setText("No results to display")
            return
        
        hosts = results.hosts
        
        self.results_table.setRowCount(len(hosts))
        
        for row, host in enumerate(hosts):
            self.results_table.setItem(row, 0, QTableWidgetItem(host.ip))
            self.results_table.setItem(row, 1, QTableWidgetItem(host.hostname or "N/A"))
            self.results_table.setItem(row, 2, QTableWidgetItem(host.state))
            self.results_table.setItem(row, 3, QTableWidgetItem(host.os_family or "Unknown"))
            
            # Количество открытых портов
            open_ports = sum(1 for port in host.ports if port.state == "open")
            self.results_table.setItem(row, 4, QTableWidgetItem(str(open_ports)))
            
            # Список сервисов
            services = []
            for port in host.ports:
                if port.state == "open" and port.service != "unknown":
                    services.append(port.service)
            
            services_text = ", ".join(set(services)) if services else "None"
            self.results_table.setItem(row, 5, QTableWidgetItem(services_text))
        
        self.status_label.setText(f"Displaying {len(hosts)} hosts")
