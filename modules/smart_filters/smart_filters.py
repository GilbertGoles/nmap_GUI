from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QLineEdit, QComboBox, QPushButton, QListWidget,
                             QListWidgetItem, QCheckBox, QFormLayout, QLabel,
                             QTextEdit, QSplitter, QTableWidget, QTableWidgetItem,
                             QHeaderView, QInputDialog, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSlot
import re
from modules.base_module import BaseTabModule
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return SmartFiltersTab(event_bus, dependencies)

class SmartFiltersTab(BaseTabModule):
    TAB_NAME = "Smart Filters"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.saved_filters = {}
        self.current_results = None
        self.result_parser = dependencies.get('result_parser') if dependencies else None
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.results_updated.connect(self._on_results_updated)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
    
    def _create_ui(self) -> QWidget:
        """Создает UI компонент умных фильтров"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Сплиттер для разделения фильтров и результатов
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая часть - фильтры
        splitter.addWidget(self._create_filters_widget())
        
        # Правая часть - результаты фильтрации
        splitter.addWidget(self._create_results_widget())
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        return widget
    
    def _create_filters_widget(self) -> QGroupBox:
        """Создает виджет управления фильтрами"""
        group = QGroupBox("Smart Filters")
        layout = QVBoxLayout(group)
        
        # Быстрые фильтры
        layout.addWidget(self._create_quick_filters())
        
        # Пользовательские фильтры
        layout.addWidget(self._create_custom_filters())
        
        # Сохраненные фильтры
        layout.addWidget(self._create_saved_filters())
        
        return group
    
    def _create_quick_filters(self) -> QGroupBox:
        """Создает виджет быстрых фильтров"""
        group = QGroupBox("Quick Filters")
        layout = QFormLayout(group)
        
        # Фильтр по сервису и версии
        self.service_filter = QLineEdit()
        self.service_filter.setPlaceholderText("e.g., apache, ssh, http")
        layout.addRow("Service:", self.service_filter)
        
        self.version_filter = QLineEdit()
        self.version_filter.setPlaceholderText("e.g., 2.4.49, OpenSSH 8.0")
        layout.addRow("Version:", self.version_filter)
        
        # Фильтр по портам
        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("e.g., 80, 443, 22, 1-1000")
        layout.addRow("Ports:", self.port_filter)
        
        # Фильтр по ОС
        self.os_filter = QLineEdit()
        self.os_filter.setPlaceholderText("e.g., Linux, Windows, Cisco")
        layout.addRow("OS:", self.os_filter)
        
        # Критические сервисы
        self.critical_services_check = QCheckBox("Show only critical services")
        layout.addRow(self.critical_services_check)
        
        # Фильтр по уязвимостям
        self.vulnerable_only_check = QCheckBox("Show only potentially vulnerable services")
        layout.addRow(self.vulnerable_only_check)
        
        # Кнопка применения
        self.apply_quick_filters_btn = QPushButton("Apply Quick Filters")
        self.apply_quick_filters_btn.clicked.connect(self._apply_quick_filters)
        layout.addRow(self.apply_quick_filters_btn)
        
        return group
    
    def _create_custom_filters(self) -> QGroupBox:
        """Создает виджет пользовательских фильтров"""
        group = QGroupBox("Custom Filters")
        layout = QVBoxLayout(group)
        
        # Поле для регулярных выражений
        layout.addWidget(QLabel("Banner/Service Regex:"))
        self.regex_filter = QTextEdit()
        self.regex_filter.setMaximumHeight(60)
        self.regex_filter.setPlaceholderText("Enter regular expression to match in banners/service output...")
        layout.addWidget(self.regex_filter)
        
        # Поле для тегов nmap
        layout.addWidget(QLabel("Nmap Script Tags:"))
        self.tags_filter = QLineEdit()
        self.tags_filter.setPlaceholderText("e.g., ssl-cert, vuln, safe, version")
        layout.addWidget(self.tags_filter)
        
        # Кнопки управления
        filter_buttons_layout = QHBoxLayout()
        self.apply_custom_btn = QPushButton("Apply Custom Filter")
        self.save_filter_btn = QPushButton("Save Filter")
        
        self.apply_custom_btn.clicked.connect(self._apply_custom_filters)
        self.save_filter_btn.clicked.connect(self._save_current_filter)
        
        filter_buttons_layout.addWidget(self.apply_custom_btn)
        filter_buttons_layout.addWidget(self.save_filter_btn)
        
        layout.addLayout(filter_buttons_layout)
        
        return group
    
    def _create_saved_filters(self) -> QGroupBox:
        """Создает виджет сохраненных фильтров"""
        group = QGroupBox("Saved Filters")
        layout = QVBoxLayout(group)
        
        self.saved_filters_list = QListWidget()
        self.saved_filters_list.itemDoubleClicked.connect(self._load_saved_filter)
        layout.addWidget(self.saved_filters_list)
        
        # Кнопки управления сохраненными фильтрами
        saved_buttons_layout = QHBoxLayout()
        self.apply_saved_btn = QPushButton("Apply Selected")
        self.delete_saved_btn = QPushButton("Delete Selected")
        
        self.apply_saved_btn.clicked.connect(self._apply_saved_filter)
        self.delete_saved_btn.clicked.connect(self._delete_saved_filter)
        
        saved_buttons_layout.addWidget(self.apply_saved_btn)
        saved_buttons_layout.addWidget(self.delete_saved_btn)
        
        layout.addLayout(saved_buttons_layout)
        
        # Загружаем предустановленные фильтры
        self._load_preset_filters()
        
        return group
    
    def _create_results_widget(self) -> QGroupBox:
        """Создает виджет результатов фильтрации"""
        group = QGroupBox("Filtered Results")
        layout = QVBoxLayout(group)
        
        # Статистика фильтрации
        self.filter_stats_label = QLabel("No filters applied")
        layout.addWidget(self.filter_stats_label)
        
        # Таблица отфильтрованных хостов
        self.filtered_results_table = QTableWidget()
        self.filtered_results_table.setColumnCount(6)
        self.filtered_results_table.setHorizontalHeaderLabels([
            "Host", "Service", "Port", "Version", "Risk Level", "Match Reason"
        ])
        
        header = self.filtered_results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.filtered_results_table)
        
        return group
    
    def _load_preset_filters(self):
        """Загружает предустановленные фильтры"""
        preset_filters = {
            "Web Servers": {
                "service": "http|https|apache|nginx|iis",
                "ports": "80,443,8080,8443"
            },
            "SSH Servers": {
                "service": "ssh",
                "ports": "22",
                "critical": True
            },
            "Database Servers": {
                "service": "mysql|postgresql|mongodb|redis",
                "ports": "3306,5432,27017,6379",
                "critical": True
            },
            "Potentially Vulnerable HTTP": {
                "service": "apache|nginx|iis",
                "version": "2.4.49|2.4.50",
                "critical": True,
                "vulnerable": True
            },
            "SSL/TLS Services": {
                "tags": "ssl-cert",
                "ports": "443,993,995,465"
            },
            "High Risk Services": {
                "service": "ftp|telnet|vnc|rdp",
                "critical": True,
                "vulnerable": True
            }
        }
        
        for name, config in preset_filters.items():
            self.saved_filters[name] = config
            self.saved_filters_list.addItem(name)
    
    def _apply_quick_filters(self):
        """Применяет быстрые фильтры"""
        if not self.current_results:
            self._show_message("No scan results available")
            return
        
        filtered_hosts = []
        
        # Применяем фильтры
        service_pattern = self.service_filter.text().lower()
        version_pattern = self.version_filter.text().lower()
        port_filter = self.port_filter.text()
        os_pattern = self.os_filter.text().lower()
        critical_only = self.critical_services_check.isChecked()
        vulnerable_only = self.vulnerable_only_check.isChecked()
        
        for host in self.current_results.hosts:
            if host.state != "up":
                continue
                
            # Фильтр по ОС
            if os_pattern and not self._match_os(host, os_pattern):
                continue
                
            # Проверяем порты хоста
            for port in host.ports:
                if port.state != "open":
                    continue
                
                match_reasons = []
                
                # Фильтр по сервису
                if service_pattern and self._match_service(port, service_pattern):
                    match_reasons.append(f"Service: {port.service}")
                
                # Фильтр по версии
                if version_pattern and self._match_version(port, version_pattern):
                    match_reasons.append(f"Version: {port.version}")
                
                # Фильтр по порту
                if port_filter and self._match_port(port, port_filter):
                    match_reasons.append(f"Port: {port.port}")
                
                # Критические сервисы
                if critical_only and not self._is_critical_service(port):
                    continue
                
                # Потенциально уязвимые сервисы
                if vulnerable_only and not self._is_potentially_vulnerable(host, port):
                    continue
                
                if match_reasons or (not service_pattern and not version_pattern and not port_filter):
                    risk_level = self._assess_risk_level(host, port)
                    filtered_hosts.append({
                        'host': host,
                        'port': port,
                        'match_reasons': match_reasons or ['All ports'],
                        'risk_level': risk_level
                    })
        
        self._display_filtered_results(filtered_hosts)
    
    def _apply_custom_filters(self):
        """Применяет пользовательские фильтры"""
        if not self.current_results:
            self._show_message("No scan results available")
            return
        
        regex_pattern = self.regex_filter.toPlainText().strip()
        tags_filter = self.tags_filter.text().lower()
        
        filtered_hosts = []
        
        for host in self.current_results.hosts:
            if host.state != "up":
                continue
                
            for port in host.ports:
                if port.state != "open":
                    continue
                
                match_reasons = []
                
                # Регулярные выражения в баннерах/сервисах
                if regex_pattern:
                    try:
                        if self._match_regex(port, host, regex_pattern):
                            match_reasons.append(f"Regex: {regex_pattern}")
                    except re.error as e:
                        self._show_message(f"Invalid regex: {e}")
                        return
                
                # Фильтр по тегам nmap скриптов
                if tags_filter and self._match_tags(host, port, tags_filter):
                    match_reasons.append(f"Tags: {tags_filter}")
                
                if match_reasons:
                    risk_level = self._assess_risk_level(host, port)
                    filtered_hosts.append({
                        'host': host,
                        'port': port,
                        'match_reasons': match_reasons,
                        'risk_level': risk_level
                    })
        
        self._display_filtered_results(filtered_hosts)
    
    def _apply_saved_filter(self):
        """Применяет выбранный сохраненный фильтр"""
        selected_items = self.saved_filters_list.selectedItems()
        if not selected_items:
            self._show_message("No filter selected")
            return
        
        filter_name = selected_items[0].text()
        if filter_name in self.saved_filters:
            filter_config = self.saved_filters[filter_name]
            
            # Применяем настройки фильтра
            self.service_filter.setText(filter_config.get('service', ''))
            self.version_filter.setText(filter_config.get('version', ''))
            self.port_filter.setText(filter_config.get('ports', ''))
            self.os_filter.setText(filter_config.get('os', ''))
            self.critical_services_check.setChecked(filter_config.get('critical', False))
            self.vulnerable_only_check.setChecked(filter_config.get('vulnerable', False))
            
            # Применяем фильтр
            self._apply_quick_filters()
    
    def _save_current_filter(self):
        """Сохраняет текущий фильтр"""
        filter_name, ok = QInputDialog.getText(
            self, 
            "Save Filter", 
            "Enter filter name:"
        )
        
        if ok and filter_name:
            filter_config = {
                'service': self.service_filter.text(),
                'version': self.version_filter.text(),
                'ports': self.port_filter.text(),
                'os': self.os_filter.text(),
                'critical': self.critical_services_check.isChecked(),
                'vulnerable': self.vulnerable_only_check.isChecked()
            }
            
            self.saved_filters[filter_name] = filter_config
            self.saved_filters_list.addItem(filter_name)
            self._show_message(f"Filter '{filter_name}' saved")
    
    def _load_saved_filter(self, item):
        """Загружает сохраненный фильтр по двойному клику"""
        filter_name = item.text()
        if filter_name in self.saved_filters:
            filter_config = self.saved_filters[filter_name]
            
            # Загружаем настройки фильтра
            self.service_filter.setText(filter_config.get('service', ''))
            self.version_filter.setText(filter_config.get('version', ''))
            self.port_filter.setText(filter_config.get('ports', ''))
            self.os_filter.setText(filter_config.get('os', ''))
            self.critical_services_check.setChecked(filter_config.get('critical', False))
            self.vulnerable_only_check.setChecked(filter_config.get('vulnerable', False))
    
    def _delete_saved_filter(self):
        """Удаляет выбранный сохраненный фильтр"""
        selected_items = self.saved_filters_list.selectedItems()
        if not selected_items:
            self._show_message("No filter selected")
            return
        
        filter_name = selected_items[0].text()
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Delete filter '{filter_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            del self.saved_filters[filter_name]
            self.saved_filters_list.takeItem(self.saved_filters_list.row(selected_items[0]))
    
    def _match_service(self, port, pattern):
        """Проверяет совпадение сервиса с паттерном"""
        return pattern in port.service.lower()
    
    def _match_version(self, port, pattern):
        """Проверяет совпадение версии с паттерном"""
        return port.version and pattern in port.version.lower()
    
    def _match_os(self, host, pattern):
        """Проверяет совпадение ОС с паттерном"""
        os_text = f"{host.os_family} {host.os_details}".lower()
        return pattern in os_text
    
    def _match_port(self, port, port_filter):
        """Проверяет совпадение порта с фильтром"""
        try:
            # Простая проверка для отдельных портов
            if ',' in port_filter:
                ports = [p.strip() for p in port_filter.split(',')]
                return str(port.port) in ports
            # Проверка для диапазонов
            elif '-' in port_filter:
                start, end = map(int, port_filter.split('-'))
                return start <= port.port <= end
            else:
                return str(port.port) == port_filter
        except ValueError:
            return False
    
    def _is_critical_service(self, port):
        """Определяет является ли сервис критическим"""
        critical_services = {
            'ssh', 'telnet', 'ftp', 'smtp', 'domain', 'http', 'https',
            'microsoft-ds', 'netbios-ssn', 'rpcbind', 'nfs', 'mysql',
            'postgresql', 'mongodb', 'redis', 'vnc', 'rdp', 'snmp'
        }
        return port.service in critical_services
    
    def _is_potentially_vulnerable(self, host, port):
        """Определяет потенциально уязвимый сервис"""
        # Проверяем версии на известные уязвимости
        if port.version:
            version_lower = port.version.lower()
            vulnerable_indicators = ['2.4.49', '2.4.50', 'vsftpd 2.3.4', '7.0', '7.1', '7.2']
            if any(indicator in version_lower for indicator in vulnerable_indicators):
                return True
        
        # Проверяем скрипты nmap
        for script_name, script_output in host.scripts.items():
            if 'vulnerable' in script_output.lower() or 'vulnerability' in script_output.lower():
                return True
        
        return False
    
    def _assess_risk_level(self, host, port):
        """Оценивает уровень риска для сервиса"""
        risk = "LOW"
        
        # Повышаем риск для критических сервисов
        if self._is_critical_service(port):
            risk = "MEDIUM"
        
        # Повышаем риск для уязвимых версий
        if self._is_potentially_vulnerable(host, port):
            risk = "HIGH"
        
        # Проверяем скрипты nmap на высокорисковые индикаторы
        for script_name, script_output in host.scripts.items():
            script_lower = script_output.lower()
            if any(keyword in script_lower for keyword in ['exploit', 'cve', 'remote code', 'privilege escalation']):
                risk = "HIGH"
                break
        
        return risk
    
    def _match_regex(self, port, host, pattern):
        """Проверяет совпадение по регулярному выражению"""
        import re
        
        # Проверяем в версии сервиса
        if port.version and re.search(pattern, port.version, re.IGNORECASE):
            return True
        
        # Проверяем в скриптах nmap
        for script_name, script_output in host.scripts.items():
            if re.search(pattern, script_output, re.IGNORECASE):
                return True
        
        return False
    
    def _match_tags(self, host, port, tags_pattern):
        """Проверяет совпадение по тегам nmap скриптов"""
        # Это упрощенная реализация - в реальности нужно парсить теги скриптов
        tags = [tag.strip() for tag in tags_pattern.split(',')]
        
        for script_name in host.scripts.keys():
            script_lower = script_name.lower()
            for tag in tags:
                if tag in script_lower:
                    return True
        
        return False
    
    def _display_filtered_results(self, filtered_data):
        """Отображает отфильтрованные результаты"""
        self.filtered_results_table.setRowCount(len(filtered_data))
        
        for row, data in enumerate(filtered_data):
            host = data['host']
            port = data['port']
            
            self.filtered_results_table.setItem(row, 0, QTableWidgetItem(host.ip))
            self.filtered_results_table.setItem(row, 1, QTableWidgetItem(port.service))
            self.filtered_results_table.setItem(row, 2, QTableWidgetItem(str(port.port)))
            self.filtered_results_table.setItem(row, 3, QTableWidgetItem(port.version or "N/A"))
            
            # Уровень риска с цветовым кодированием
            risk_item = QTableWidgetItem(data['risk_level'])
            if data['risk_level'] == "HIGH":
                risk_item.setBackground(QColor(255, 200, 200))  # Красный
            elif data['risk_level'] == "MEDIUM":
                risk_item.setBackground(QColor(255, 255, 200))  # Желтый
            else:
                risk_item.setBackground(QColor(200, 255, 200))  # Зеленый
            self.filtered_results_table.setItem(row, 4, risk_item)
            
            self.filtered_results_table.setItem(row, 5, QTableWidgetItem("; ".join(data['match_reasons'])))
        
        self.filter_stats_label.setText(f"Found {len(filtered_data)} matches")
    
    def _show_message(self, message):
        """Показывает сообщение"""
        self.filter_stats_label.setText(message)
        self.filtered_results_table.setRowCount(0)
    
    @pyqtSlot(dict)
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results:
            self.current_results = results
            self.filter_stats_label.setText(f"Results loaded: {len(results.hosts)} hosts")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results:
            self.current_results = results
            self.filter_stats_label.setText(f"Scan completed: {len(results.hosts)} hosts")
