from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QLabel, QPushButton, QComboBox, QLineEdit,
                             QSplitter, QTextEdit, QTabWidget, QProgressBar,
                             QMenu, QInputDialog, QMessageBox, QCheckBox)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QAction, QColor, QBrush
from datetime import datetime
from modules.base_module import BaseTabModule
from core.event_bus import EventBus
from shared.models.scan_result import ScanResult, HostInfo, PortInfo

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ResultsTableTab(event_bus, dependencies)

class ResultsTableTab(BaseTabModule):
    TAB_NAME = "Results Table"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.scan_results = {}
        self.current_scan_id = None
        self.result_parser = dependencies.get('result_parser') if dependencies else None
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_completed.connect(self._on_scan_completed)
        self.event_bus.results_updated.connect(self._on_results_updated)
    
    def _create_ui(self) -> QWidget:
        """Создает UI компонент таблицы результатов"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Панель управления результатами
        layout.addWidget(self._create_control_panel())
        
        # Сплиттер для разделения таблицы и деталей
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Верхняя часть - таблица результатов
        splitter.addWidget(self._create_results_table_widget())
        
        # Нижняя часть - детальная информация
        splitter.addWidget(self._create_details_widget())
        
        splitter.setSizes([400, 200])
        layout.addWidget(splitter)
        
        return widget
    
    def _create_control_panel(self) -> QGroupBox:
        """Создает панель управления результатами"""
        group = QGroupBox("Results Control")
        layout = QHBoxLayout(group)
        
        # Выбор сканирования
        layout.addWidget(QLabel("Scan:"))
        self.scan_combo = QComboBox()
        self.scan_combo.currentTextChanged.connect(self._on_scan_selected)
        layout.addWidget(self.scan_combo, 1)
        
        # Фильтры
        layout.addWidget(QLabel("Filter:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "All Hosts",
            "Up Hosts Only", 
            "With Open Ports",
            "With Specific Service",
            "OS Detected"
        ])
        self.filter_combo.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(self.filter_combo)
        
        self.service_filter_input = QLineEdit()
        self.service_filter_input.setPlaceholderText("Service name...")
        self.service_filter_input.textChanged.connect(self._apply_filters)
        self.service_filter_input.setVisible(False)
        layout.addWidget(self.service_filter_input)
        
        # Кнопки экспорта
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self._export_results)
        layout.addWidget(self.export_btn)
        
        # Статистика
        self.stats_label = QLabel("No results loaded")
        layout.addWidget(self.stats_label)
        
        return group
    
    def _create_results_table_widget(self) -> QGroupBox:
        """Создает виджет таблицы результатов"""
        group = QGroupBox("Scan Results")
        layout = QVBoxLayout(group)
        
        # Таблица хостов
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(8)
        self.hosts_table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "Status", "OS", "Open Ports", 
            "Services", "Last Scan", "Details"
        ])
        
        # Настройка таблицы
        header = self.hosts_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        
        self.hosts_table.itemSelectionChanged.connect(self._on_host_selected)
        self.hosts_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hosts_table.customContextMenuRequested.connect(self._show_context_menu)
        
        layout.addWidget(self.hosts_table)
        
        return group
    
    def _create_details_widget(self) -> QTabWidget:
        """Создает виджет детальной информации"""
        tab_widget = QTabWidget()
        
        # Вкладка портов
        self.ports_text = QTextEdit()
        self.ports_text.setReadOnly(True)
        tab_widget.addTab(self.ports_text, "Ports")
        
        # Вкладка ОС и сервисов
        self.services_text = QTextEdit()
        self.services_text.setReadOnly(True)
        tab_widget.addTab(self.services_text, "Services & OS")
        
        # Вкладка сырых данных
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        tab_widget.addTab(self.raw_text, "Raw Data")
        
        return tab_widget
    
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results and hasattr(results, 'hosts'):
            self.scan_results[scan_id] = results
            self.scan_combo.addItem(f"{scan_id[:8]} - {len(results.hosts)} hosts")
            
            if self.current_scan_id is None:
                self.current_scan_id = scan_id
                self._display_results(results)
    
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if scan_id and results:
            self.scan_results[scan_id] = results
            self._display_results(results)
    
    def _on_scan_selected(self, scan_text):
        """Обрабатывает выбор сканирования"""
        if not scan_text:
            return
        
        # Извлекаем scan_id из текста (первые 8 символов)
        scan_id = scan_text.split(' - ')[0]
        
        if scan_id in self.scan_results:
            self.current_scan_id = scan_id
            self._display_results(self.scan_results[scan_id])
    
    def _display_results(self, scan_result: ScanResult):
        """Отображает результаты сканирования в таблице"""
        if not scan_result or not scan_result.hosts:
            self.hosts_table.setRowCount(0)
            self.stats_label.setText("No hosts found")
            return
        
        self.hosts_table.setRowCount(len(scan_result.hosts))
        
        for row, host in enumerate(scan_result.hosts):
            # IP Address
            self.hosts_table.setItem(row, 0, QTableWidgetItem(host.ip))
            
            # Hostname
            hostname = host.hostname if host.hostname else "N/A"
            self.hosts_table.setItem(row, 1, QTableWidgetItem(hostname))
            
            # Status
            status_item = QTableWidgetItem(host.state.upper())
            if host.state == "up":
                status_item.setBackground(QBrush(QColor(200, 255, 200)))  # Зеленый
            else:
                status_item.setBackground(QBrush(QColor(255, 200, 200)))  # Красный
            self.hosts_table.setItem(row, 2, status_item)
            
            # OS
            os_info = host.os_details if host.os_details else "Unknown"
            if host.os_family:
                os_info = f"{host.os_family} ({os_info})"
            self.hosts_table.setItem(row, 3, QTableWidgetItem(os_info))
            
            # Open Ports Count
            open_ports = sum(1 for port in host.ports if port.state == "open")
            self.hosts_table.setItem(row, 4, QTableWidgetItem(str(open_ports)))
            
            # Services (первые несколько уникальных сервисов)
            services = set()
            for port in host.ports:
                if port.state == "open" and port.service != "unknown":
                    services.add(port.service)
            services_text = ", ".join(list(services)[:3])
            if len(services) > 3:
                services_text += f" ... (+{len(services) - 3})"
            self.hosts_table.setItem(row, 5, QTableWidgetItem(services_text))
            
            # Last Scan
            scan_time = scan_result.end_time.strftime("%H:%M:%S") if scan_result.end_time else "N/A"
            self.hosts_table.setItem(row, 6, QTableWidgetItem(scan_time))
            
            # Details
            details_btn = QPushButton("View Details")
            details_btn.clicked.connect(lambda checked, r=row: self._show_host_details(r))
            self.hosts_table.setCellWidget(row, 7, details_btn)
        
        # Обновляем статистику
        stats = self._calculate_statistics(scan_result)
        self.stats_label.setText(
            f"Hosts: {stats['total']} | "
            f"Up: {stats['up']} | "
            f"Open Ports: {stats['open_ports']} | "
            f"Services: {stats['services']}"
        )
    
    def _calculate_statistics(self, scan_result: ScanResult) -> dict:
        """Вычисляет статистику по результатам"""
        stats = {
            'total': len(scan_result.hosts),
            'up': 0,
            'open_ports': 0,
            'services': set()
        }
        
        for host in scan_result.hosts:
            if host.state == "up":
                stats['up'] += 1
            
            for port in host.ports:
                if port.state == "open":
                    stats['open_ports'] += 1
                    if port.service != "unknown":
                        stats['services'].add(port.service)
        
        stats['services'] = len(stats['services'])
        return stats
    
    def _on_host_selected(self):
        """Обрабатывает выбор хоста в таблице"""
        selected_items = self.hosts_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        host_ip = self.hosts_table.item(row, 0).text()
        
        if self.current_scan_id and self.current_scan_id in self.scan_results:
            scan_result = self.scan_results[self.current_scan_id]
            host = next((h for h in scan_result.hosts if h.ip == host_ip), None)
            
            if host:
                self._display_host_details(host)
    
    def _display_host_details(self, host: HostInfo):
        """Отображает детальную информацию о хосте"""
        # Вкладка портов
        ports_text = "OPEN PORTS:\n"
        ports_text += "-" * 50 + "\n"
        
        for port in host.ports:
            if port.state == "open":
                ports_text += f"Port: {port.port}/{port.protocol}\n"
                ports_text += f"  Service: {port.service}\n"
                if port.version:
                    ports_text += f"  Version: {port.version}\n"
                ports_text += f"  State: {port.state}\n"
                ports_text += "-" * 30 + "\n"
        
        self.ports_text.setPlainText(ports_text)
        
        # Вкладка сервисов и ОС
        services_text = f"HOST: {host.ip}\n"
        services_text += f"Hostname: {host.hostname}\n"
        services_text += f"Status: {host.state}\n\n"
        
        services_text += "OPERATING SYSTEM:\n"
        services_text += f"  Family: {host.os_family}\n"
        services_text += f"  Details: {host.os_details}\n\n"
        
        services_text += "SERVICES:\n"
        for port in host.ports:
            if port.state == "open":
                services_text += f"  {port.service} on {port.port}/{port.protocol}\n"
                if port.version:
                    services_text += f"    Version: {port.version}\n"
        
        self.services_text.setPlainText(services_text)
        
        # Вкладка сырых данных (симулируем)
        raw_text = f"Raw data for {host.ip}\n\n"
        raw_text += f"Host discovery: {host.state}\n"
        raw_text += f"Ports scanned: {len(host.ports)}\n"
        raw_text += f"OS detection: {host.os_family}\n"
        
        self.raw_text.setPlainText(raw_text)
    
    def _show_host_details(self, row: int):
        """Показывает детали хоста по кнопке"""
        host_ip = self.hosts_table.item(row, 0).text()
        
        if self.current_scan_id and self.current_scan_id in self.scan_results:
            scan_result = self.scan_results[self.current_scan_id]
            host = next((h for h in scan_result.hosts if h.ip == host_ip), None)
            
            if host:
                self._display_host_details(host)
                # Выделяем строку
                self.hosts_table.selectRow(row)
    
    def _apply_filters(self):
        """Применяет фильтры к таблице"""
        if not self.current_scan_id or self.current_scan_id not in self.scan_results:
            return
        
        filter_type = self.filter_combo.currentText()
        scan_result = self.scan_results[self.current_scan_id]
        
        # Показываем/скрываем поле фильтра сервиса
        self.service_filter_input.setVisible(filter_type == "With Specific Service")
        
        filtered_hosts = []
        
        if filter_type == "All Hosts":
            filtered_hosts = scan_result.hosts
        elif filter_type == "Up Hosts Only":
            filtered_hosts = [h for h in scan_result.hosts if h.state == "up"]
        elif filter_type == "With Open Ports":
            filtered_hosts = [h for h in scan_result.hosts if any(p.state == "open" for p in h.ports)]
        elif filter_type == "With Specific Service":
            service_name = self.service_filter_input.text().lower()
            if service_name:
                filtered_hosts = [h for h in scan_result.hosts if any(
                    p.state == "open" and service_name in p.service.lower() for p in h.ports
                )]
            else:
                filtered_hosts = scan_result.hosts
        elif filter_type == "OS Detected":
            filtered_hosts = [h for h in scan_result.hosts if h.os_family]
        
        # Обновляем таблицу с отфильтрованными данными
        self._display_filtered_results(filtered_hosts, scan_result)
    
    def _display_filtered_results(self, hosts: list, original_scan_result: ScanResult):
        """Отображает отфильтрованные результаты"""
        # Создаем временный объект ScanResult для отфильтрованных хостов
        filtered_result = ScanResult(
            scan_id=original_scan_result.scan_id,
            config=original_scan_result.config,
            hosts=hosts,
            start_time=original_scan_result.start_time,
            end_time=original_scan_result.end_time
        )
        
        self._display_results(filtered_result)
    
    def _show_context_menu(self, position):
        """Показывает контекстное меню для таблицы"""
        menu = QMenu()
        
        export_action = QAction("Export Selected Hosts", self.get_ui())
        export_action.triggered.connect(self._export_selected_hosts)
        menu.addAction(export_action)
        
        scan_again_action = QAction("Scan Selected Hosts Again", self.get_ui())
        scan_again_action.triggered.connect(self._scan_selected_hosts_again)
        menu.addAction(scan_again_action)
        
        menu.exec(self.hosts_table.mapToGlobal(position))
    
    def _export_results(self):
        """Экспортирует результаты"""
        if not self.current_scan_id or self.current_scan_id not in self.scan_results:
            QMessageBox.warning(self.get_ui(), "Warning", "No results to export!")
            return
        
        # TODO: Реализовать экспорт в разные форматы
        QMessageBox.information(self.get_ui(), "Export", "Export functionality will be implemented")
    
    def _export_selected_hosts(self):
        """Экспортирует выбранные хосты"""
        selected_rows = set(item.row() for item in self.hosts_table.selectedItems())
        
        if not selected_rows:
            QMessageBox.warning(self.get_ui(), "Warning", "No hosts selected!")
            return
        
        hosts = []
        for row in selected_rows:
            ip = self.hosts_table.item(row, 0).text()
            hosts.append(ip)
        
        # TODO: Реализовать экспорт выбранных хостов
        QMessageBox.information(self.get_ui(), "Export Selected", f"Selected {len(hosts)} hosts for export")
    
    def _scan_selected_hosts_again(self):
        """Запускает повторное сканирование выбранных хостов"""
        selected_rows = set(item.row() for item in self.hosts_table.selectedItems())
        
        if not selected_rows:
            QMessageBox.warning(self.get_ui(), "Warning", "No hosts selected!")
            return
        
        hosts = []
        for row in selected_rows:
            ip = self.hosts_table.item(row, 0).text()
            hosts.append(ip)
        
        # Публикуем событие с целями для сканирования
        self.event_bus.targets_updated.emit(hosts)
        
        QMessageBox.information(
            self.get_ui(), 
            "Scan Again", 
            f"Sent {len(hosts)} hosts to Scan Launcher for rescanning"
        )
