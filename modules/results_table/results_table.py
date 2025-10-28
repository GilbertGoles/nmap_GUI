from PyQt6.QtWidgets import (QVBoxLayout, QGroupBox,
                             QLabel, QTableWidget, QTableWidgetItem,
                             QHeaderView, QTextEdit, QHBoxLayout, QPushButton, 
                             QMessageBox)  # Добавляем QMessageBox
from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QColor  # ДОБАВЛЯЕМ ЭТОТ ИМПОРТ
from modules.base_module import BaseTabModule
from core.event_bus import EventBus
from shared.models.scan_result import HostInfo

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
        
        # Панель управления
        control_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self._export_results)
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        
        control_layout.addWidget(self.export_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Таблица результатов
        table_group = QGroupBox("Scan Results")
        table_layout = QVBoxLayout(table_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "Status", "OS", "Open Ports", "Services", "Vulnerabilities"
        ])
        
        # Настройка таблицы
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
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
    
    def _export_results(self):
        """Экспортирует результаты в файл"""
        if not self.current_results:
            QMessageBox.warning(self, "Warning", "No results to export!")
            return
        
        try:
            # Простой экспорт в текстовый формат
            export_content = self._generate_export_text()
            
            from PyQt6.QtWidgets import QFileDialog
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Results", "scan_results.txt", "Text Files (*.txt)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(export_content)
                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export results: {e}")
    
    def _generate_export_text(self):
        """Генерирует текст для экспорта"""
        if not self.current_results:
            return "No results available"
        
        lines = []
        lines.append("NMAP SCAN RESULTS")
        lines.append("=" * 50)
        
        for host in self.current_results.hosts:
            lines.append(f"\nHost: {host.ip}")
            lines.append(f"Hostname: {host.hostname or 'N/A'}")
            lines.append(f"Status: {host.state}")
            lines.append(f"OS: {host.os_family or 'Unknown'} {host.os_details or ''}")
            
            open_ports = [p for p in host.ports if p.state == "open"]
            if open_ports:
                lines.append("Open Ports:")
                for port in open_ports:
                    lines.append(f"  {port.port}/{port.protocol}: {port.service} {port.version or ''}")
            else:
                lines.append("No open ports")
        
        return '\n'.join(lines)
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        print(f"🔵 [ResultsTable] Scan completed: {scan_id}, has results: {results is not None}")  # ДЕБАГ
        
        if results:
            self.current_results = results
            self._display_results(results)
    
    @pyqtSlot(dict)
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        print(f"🔵 [ResultsTable] Results updated: {scan_id}, has results: {results is not None}")  # ДЕБАГ
        
        if results:
            self.current_results = results
            self._display_results(results)
    
    def _display_results(self, results):
        """Отображает результаты в таблице"""
        print(f"🔵 [ResultsTable] Displaying results: {len(results.hosts) if results and hasattr(results, 'hosts') else 0} hosts")  # ДЕБАГ
        
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
            
            # Индикатор уязвимостей
            vulnerability_count = self._count_vulnerabilities(host)
            vuln_text = f"{vulnerability_count} found" if vulnerability_count > 0 else "None"
            vuln_item = QTableWidgetItem(vuln_text)
            if vulnerability_count > 0:
                vuln_item.setBackground(QColor(255, 200, 200))  # Красный фон для уязвимостей
            self.results_table.setItem(row, 6, vuln_item)
        
        # Обновляем статус с общей статистикой
        total_open_ports = sum(len([p for p in h.ports if p.state == "open"]) for h in hosts)
        total_vulnerabilities = sum(self._count_vulnerabilities(h) for h in hosts)
        self.status_label.setText(
            f"Displaying {len(hosts)} hosts, {total_open_ports} open ports, {total_vulnerabilities} vulnerabilities"
        )
        
        # Показываем детали первого хоста, если есть результаты
        if hosts:
            self.results_table.selectRow(0)
            self._show_host_details(hosts[0])
    
    def _count_vulnerabilities(self, host: HostInfo) -> int:
        """Считает количество уязвимостей для хоста"""
        count = 0
        
        # Проверяем скрипты nmap на наличие индикаторов уязвимостей
        for script_name, script_output in host.scripts.items():
            script_lower = script_output.lower()
            # Простые индикаторы уязвимостей в выводе скриптов
            if any(keyword in script_lower for keyword in ['vulnerable', 'vulnerability', 'cve', 'exploit', 'risk']):
                count += 1
        
        # Проверяем версии сервисов на известные уязвимости
        for port in host.ports:
            if port.version:
                version_lower = port.version.lower()
                # Простые проверки уязвимых версий
                if any(vuln in version_lower for vuln in ['2.4.49', '2.4.50', 'vsftpd 2.3.4']):
                    count += 1
        
        return count
    
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
        
        # Добавляем информацию об уязвимостях
        vulnerabilities = self._count_vulnerabilities(host)
        if vulnerabilities > 0:
            details += f"\n⚠️  Potential Vulnerabilities Found: {vulnerabilities}\n"
            details += "Check the scripts output for details.\n"
        
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
