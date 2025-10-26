from PyQt6.QtWidgets import (QVBoxLayout, QGroupBox,
                             QLabel, QTableWidget, QTableWidgetItem,
                             QHeaderView, QTextEdit)
from PyQt6.QtCore import pyqtSlot
from modules.base_module import BaseTabModule
from core.event_bus import EventBus
from shared.models.scan_result import HostInfo  # Добавляем импорт

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
        
        # Подключаем обработчик выбора строки
        self.results_table.itemSelectionChanged.connect(self._on_row_selected)
        
        table_layout.addWidget(self.results_table)
        layout.addWidget(table_group)
        
        # Детальная информация
        details_group = QGroupBox("Host Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
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
            self.results_table.setRowCount(0)
            return
        
        hosts = results.hosts
        
        self.results_table.setRowCount(len(hosts))
        
        for row, host in enumerate(hosts):
            self.results_table.setItem(row, 0, QTableWidgetItem(host.ip))
            self.results_table.setItem(row, 1, QTableWidgetItem(host.hostname or "N/A"))
            self.results_table.setItem(row, 2, QTableWidgetItem(host.state))
            
            # OS информация
            os_info = ""
            if host.os_family:
                os_info = host.os_family
                if host.os_details:
                    os_info += f" ({host.os_details})"
            else:
                os_info = "Unknown"
            self.results_table.setItem(row, 3, QTableWidgetItem(os_info))
            
            # Количество открытых портов
            open_ports = [p for p in host.ports if p.state == "open"]
            self.results_table.setItem(row, 4, QTableWidgetItem(str(len(open_ports))))
            
            # Список сервисов
            services = []
            for port in open_ports:
                if port.service and port.service != "unknown":
                    services.append(f"{port.service}:{port.port}")
            
            services_text = ", ".join(services) if services else "None"
            self.results_table.setItem(row, 5, QTableWidgetItem(services_text))
        
        # Обновляем статус с общей статистикой
        total_open_ports = sum(len([p for p in h.ports if p.state == "open"]) for h in hosts)
        self.status_label.setText(f"Displaying {len(hosts)} hosts, {total_open_ports} open ports")
        
        # Показываем детали первого хоста, если есть результаты
        if hosts:
            self.results_table.selectRow(0)  # Автоматически выбираем первую строку
            self._show_host_details(hosts[0])
    
    def _show_host_details(self, host: HostInfo):
        """Показывает детальную информацию о хосте"""
        details = f"Host: {host.ip}\n"
        details += f"Hostname: {host.hostname or 'N/A'}\n"
        details += f"Status: {host.state}\n"
        details += f"OS: {host.os_family or 'Unknown'} {host.os_details or ''}\n\n"
        
        open_ports = [p for p in host.ports if p.state == "open"]
        if open_ports:
            details += "Open Ports:\n"
            details += "-" * 40 + "\n"
            for port in open_ports:
                details += f"Port: {port.port}/{port.protocol}\n"
                details += f"  Service: {port.service}\n"
                if port.version:
                    details += f"  Version: {port.version}\n"
                details += f"  State: {port.state}\n"
                
                # Добавляем информацию о скриптах если есть
                if hasattr(host, 'scripts') and host.scripts:
                    port_scripts = {k: v for k, v in host.scripts.items() if f"port{port.port}" in k}
                    if port_scripts:
                        details += f"  Scripts: {', '.join(port_scripts.keys())}\n"
                
                details += "-" * 20 + "\n"
        else:
            details += "No open ports found\n"
        
        self.details_text.setPlainText(details)
    
    def _on_row_selected(self):
        """Обрабатывает выбор строки в таблице"""
        selected_items = self.results_table.selectedItems()
        if not selected_items or not self.current_results:
            return
        
        row = selected_items[0].row()
        host_ip = self.results_table.item(row, 0).text()
        
        # Находим выбранный хост
        for host in self.current_results.hosts:
            if host.ip == host_ip:
                self._show_host_details(host)
                break
    
    def clear_results(self):
        """Очищает результаты"""
        self.results_table.setRowCount(0)
        self.details_text.clear()
        self.status_label.setText("No results available")
        self.current_results = None
