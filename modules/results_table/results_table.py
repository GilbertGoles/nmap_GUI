from PyQt6.QtWidgets import (QVBoxLayout, QGroupBox,
                             QLabel, QTableWidget, QTableWidgetItem,
                             QHeaderView, QTextEdit, QHBoxLayout, QPushButton, 
                             QMessageBox, QDialog)  # Добавляем QDialog
from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QColor
import re  # ДОБАВЛЯЕМ ИМПОРТ ДЛЯ РЕГУЛЯРНЫХ ВЫРАЖЕНИЙ
from modules.base_module import BaseTabModule
from core.event_bus import EventBus
from shared.models.scan_result import HostInfo, PortInfo

# Добавляем заглушку для CVE checker если его нет
class CVEChecker:
    """Заглушка для проверки CVE уязвимостей"""
    
    def __init__(self):
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        import logging
        return logging.getLogger(__name__)
    
    def check_service_cve(self, service: str, version: str) -> list:
        """
        Проверяет CVE уязвимости для сервиса
        В реальной реализации здесь будет обращение к CVE базе
        """
        cves = []
        
        try:
            # Простая заглушка для демонстрации
            # В реальной системе здесь будет обращение к CVE базе данных
            service_lower = service.lower()
            version_lower = version.lower()
            
            # Пример проверки для OpenSSH
            if 'ssh' in service_lower and '6.6.1' in version_lower:
                cves.append({
                    'id': 'CVE-2016-6210',
                    'risk': 'MEDIUM',
                    'description': 'OpenSSH 6.6.1 allows remote attackers to obtain sensitive information from process memory',
                    'cvss_score': 5.3,
                    'source': 'NVD'
                })
            
            # Пример проверки для Apache
            elif 'http' in service_lower and '2.4.7' in version_lower:
                cves.append({
                    'id': 'CVE-2017-3169',
                    'risk': 'HIGH',
                    'description': 'Apache HTTP Server mod_ssl vulnerability',
                    'cvss_score': 7.5,
                    'source': 'NVD'
                })
            
            # Добавляем общие CVE на основе версий
            if any(vuln_ver in version_lower for vuln_ver in ['2.4.49', '2.4.50']):
                cves.append({
                    'id': 'CVE-2021-41773',
                    'risk': 'CRITICAL',
                    'description': 'Apache HTTP Server path traversal vulnerability',
                    'cvss_score': 9.8,
                    'source': 'NVD'
                })
                
        except Exception as e:
            self.logger.debug(f"CVE check error for {service} {version}: {e}")
        
        return cves

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ResultsTableTab(event_bus, dependencies)

class VulnerabilityDetailsDialog(QDialog):
    """Диалог для отображения деталей уязвимостей"""
    
    def __init__(self, vulnerabilities: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Vulnerability Details")
        self.setGeometry(100, 100, 800, 600)
        
        layout = QVBoxLayout(self)
        
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        layout.addWidget(self.text_edit)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)
        
        self._display_vulnerabilities(vulnerabilities)
    
    def _display_vulnerabilities(self, vulnerabilities):
        """Отображает список уязвимостей"""
        if not vulnerabilities:
            self.text_edit.setText("No vulnerabilities found")
            return
        
        # Безопасное создание HTML
        html_parts = []
        html_parts.append("""
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .vuln { margin: 10px 0; padding: 10px; border-left: 4px solid #f44336; background: #ffeaea; }
            .critical { border-color: #d32f2f; background: #ffcdd2; }
            .high { border-color: #f44336; background: #ffeaea; }
            .medium { border-color: #ff9800; background: #fff3e0; }
            .low { border-color: #4caf50; background: #e8f5e8; }
            .risk { font-weight: bold; padding: 2px 8px; border-radius: 3px; }
            .risk-critical { background: #d32f2f; color: white; }
            .risk-high { background: #f44336; color: white; }
            .risk-medium { background: #ff9800; color: white; }
            .risk-low { background: #4caf50; color: white; }
            .cve { background: #e3f2fd; border-left: 4px solid #2196f3; }
            .cve-id { font-family: monospace; font-weight: bold; color: #1976d2; }
        </style>
    </head>
    <body>
    """)
        
        html_parts.append(f"<h2>Found Vulnerabilities: {len(vulnerabilities)}</h2>")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            risk = vuln.get('risk', 'low').lower()
            risk_class = f"risk-{risk}"
            vuln_class = risk
            
            if vuln.get('type') == 'CVE':
                vuln_class = 'cve'
            
            html_parts.append(f'<div class="vuln {vuln_class}">')
            html_parts.append('<h3>')
            
            if vuln.get('type') == 'CVE':
                html_parts.append(f'<span class="cve-id">{vuln.get("id", "Unknown CVE")}</span> - ')
            
            html_parts.append(f'Vulnerability #{i} <span class="risk {risk_class}">{vuln.get("risk", "UNKNOWN")}</span></h3>')
            html_parts.append(f'<p><strong>Service:</strong> {vuln.get("service", "Unknown")}</p>')
            html_parts.append(f'<p><strong>Port:</strong> {vuln.get("port", "Unknown")}</p>')
            html_parts.append(f'<p><strong>Version:</strong> {vuln.get("version", "Unknown")}</p>')
            
            if vuln.get('cvss_score'):
                html_parts.append(f'<p><strong>CVSS Score:</strong> {vuln.get("cvss_score")}</p>')
            
            html_parts.append(f'<p><strong>Issue:</strong> {vuln.get("issue", "No details")}</p>')
            html_parts.append(f'<p><strong>Recommendation:</strong> {vuln.get("recommendation", "No recommendation")}</p>')
            
            if vuln.get('source'):
                html_parts.append(f'<p><strong>Source:</strong> {vuln.get("source")}</p>')
            elif vuln.get('script'):
                html_parts.append(f'<p><strong>Script:</strong> {vuln.get("script", "N/A")}</p>')
            
            html_parts.append('</div>')
        
        html_parts.append('</body></html>')
        
        self.text_edit.setHtml(''.join(html_parts))

class ResultsTableTab(BaseTabModule):
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.cve_checker = CVEChecker()  # Инициализируем CVE checker
        self.current_results = None
        self.current_host = None
    
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
        
        # Кнопка для просмотра уязвимостей (будет добавляться динамически)
        self.vuln_btn = QPushButton("View Vulnerability Details")
        self.vuln_btn.clicked.connect(self._show_current_host_vulnerabilities)
        self.vuln_btn.setVisible(False)  # Скрыта по умолчанию
        details_layout.addWidget(self.vuln_btn)
        
        layout.addWidget(details_group)
        
        # Статус
        self.status_label = QLabel("No results available")
        layout.addWidget(self.status_label)
        
        # Инициализируем результаты
        self.current_results = None
        self.current_host = None  # Текущий выбранный хост
    
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
            
            # Добавляем информацию об уязвимостях в экспорт
            vulnerabilities = self._extract_vulnerabilities(host)
            if vulnerabilities:
                lines.append(f"Vulnerabilities: {len(vulnerabilities)} found")
                for i, vuln in enumerate(vulnerabilities, 1):
                    vuln_type = f"[{vuln.get('type', 'SCRIPT')}]" if vuln.get('type') else ""
                    lines.append(f"  {i}. {vuln_type} {vuln.get('service', 'Unknown')} (Port {vuln.get('port', 'Unknown')}) - Risk: {vuln.get('risk', 'Unknown')}")
        
        return '\n'.join(lines)
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        print(f"🔵 [ResultsTable] Scan completed: {scan_id}, has results: {results is not None}")
        
        if results:
            self.current_results = results
            self._display_results(results)
    
    @pyqtSlot(dict)
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        print(f"🔵 [ResultsTable] Results updated: {scan_id}, has results: {results is not None}")
        
        if results:
            self.current_results = results
            self._display_results(results)
    
    def _display_results(self, results):
        """Отображает результаты в таблице"""
        print(f"🔵 [ResultsTable] Displaying results: {len(results.hosts) if results and hasattr(results, 'hosts') else 0} hosts")
        
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
        vulnerabilities = self._extract_vulnerabilities(host)
        return len(vulnerabilities)
    
    def _show_host_details(self, host: HostInfo):
        """Показывает детальную информацию о хосте"""
        self.current_host = host
        
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
                details += f"  State: {port.state}\n\n"
        else:
            details += "No open ports found\n"
        
        # Добавляем информацию об уязвимостях
        vulnerabilities = self._extract_vulnerabilities(host)
        if vulnerabilities:
            details += f"\n⚠️  Potential Vulnerabilities Found: {len(vulnerabilities)}\n"
            
            # Считаем CVE и скриптовые уязвимости отдельно
            cve_count = sum(1 for v in vulnerabilities if v.get('type') == 'CVE')
            script_count = len(vulnerabilities) - cve_count
            
            if cve_count > 0:
                details += f"  - CVE Vulnerabilities: {cve_count}\n"
            if script_count > 0:
                details += f"  - Script Detections: {script_count}\n"
                
            details += "Click 'View Details' for more information.\n"
            self.vuln_btn.setVisible(True)
        else:
            self.vuln_btn.setVisible(False)
        
        self.details_text.setPlainText(details)
    
    def _show_current_host_vulnerabilities(self):
        """Показывает детали уязвимостей для текущего хоста"""
        if self.current_host:
            self._show_vulnerability_details(self.current_host)
    
    def _show_vulnerability_details(self, host: HostInfo):
        """Показывает детали уязвимостей для хоста"""
        vulnerabilities = self._extract_vulnerabilities(host)
        
        if vulnerabilities:
            dialog = VulnerabilityDetailsDialog(vulnerabilities, self)
            dialog.exec()
        else:
            QMessageBox.information(self, "No Vulnerabilities", "No vulnerabilities found for this host")
    
    def _extract_vulnerabilities(self, host: HostInfo) -> list:
        """Извлекает информацию об уязвимостях из скриптов nmap и CVE баз"""
        vulnerabilities = []
        
        # Анализируем скрипты nmap
        if hasattr(host, 'scripts') and host.scripts:
            for script_name, script_output in host.scripts.items():
                vuln_info = self._parse_vulnerability_from_script(script_name, script_output, host)
                if vuln_info:
                    vulnerabilities.append(vuln_info)
        
        # Проверяем CVE для сервисов
        for port in host.ports:
            if port.state == "open" and port.service and port.service != "unknown":
                # Проверяем CVE уязвимости
                cve_vulns = self._check_cve_vulnerabilities(port, host)
                vulnerabilities.extend(cve_vulns)
                
                # Проверяем уязвимости версий
                version_vulns = self._check_version_vulnerabilities(port, host)
                vulnerabilities.extend(version_vulns)
        
        return vulnerabilities
    
    def _check_cve_vulnerabilities(self, port: PortInfo, host: HostInfo) -> list:
        """Проверяет CVE уязвимости для сервиса"""
        vulnerabilities = []
        
        try:
            # Проверяем CVE для конкретного сервиса
            cves = self.cve_checker.check_service_cve(port.service, port.version)
            
            for cve in cves:
                vulnerabilities.append({
                    'type': 'CVE',
                    'id': cve['id'],
                    'service': port.service,
                    'port': str(port.port),
                    'version': port.version,
                    'risk': cve['risk'],
                    'issue': cve['description'],
                    'cvss_score': cve.get('cvss_score'),
                    'recommendation': f"Update {port.service} to latest version",
                    'source': cve.get('source', 'CVE Database')
                })
                
        except Exception as e:
            self.logger.debug(f"CVE check failed for {port.service}: {e}")
        
        return vulnerabilities
    
    def _check_version_vulnerabilities(self, port, host: HostInfo) -> list:
        """Проверяет версии сервисов на известные уязвимости"""
        vulnerabilities = []
        version_lower = port.version.lower()
        
        # Проверяем известные уязвимые версии
        if 'openssh' in version_lower:
            if any(vuln_ver in version_lower for vuln_ver in ['6.6.1', '7.1']):
                vulnerabilities.append({
                    'type': 'VERSION',
                    'script': 'version_detection',
                    'service': port.service,
                    'port': str(port.port),
                    'risk': 'MEDIUM',
                    'issue': f'Potential vulnerabilities in {port.version}',
                    'recommendation': 'Update to latest OpenSSH version',
                    'version': port.version
                })
        
        elif 'apache' in version_lower:
            if any(vuln_ver in version_lower for vuln_ver in ['2.4.49', '2.4.50']):
                vulnerabilities.append({
                    'type': 'VERSION',
                    'script': 'version_detection',
                    'service': port.service,
                    'port': str(port.port),
                    'risk': 'HIGH',
                    'issue': f'Known vulnerabilities in Apache {port.version}',
                    'recommendation': 'Update Apache to latest version',
                    'version': port.version
                })
        
        return vulnerabilities
    
    def _parse_vulnerability_from_script(self, script_name: str, script_output: str, host: HostInfo) -> dict:
        """Парсит информацию об уязвимости из вывода скрипта"""
        if not script_output or not script_name:
            return None
            
        script_lower = script_output.lower()
        
        # Пропускаем информационные скрипты без уязвимостей
        non_vulnerability_scripts = ['http-title', 'http-date', 'ssh-hostkey', 'banner', 'port-states']
        if any(non_vuln in script_name for non_vuln in non_vulnerability_scripts):
            return None
        
        # Определяем уровень риска по ключевым словам
        risk = "LOW"
        issue = script_output[:200] + "..." if len(script_output) > 200 else script_output
        
        if any(keyword in script_lower for keyword in ['exploit', 'remote code', 'privilege escalation', 'critical', 'cve']):
            risk = "HIGH"
        elif any(keyword in script_lower for keyword in ['vulnerable', 'vulnerability', 'risk', 'warning']):
            risk = "MEDIUM"
        elif any(keyword in script_lower for keyword in ['info', 'detected', 'found']):
            risk = "LOW"
        
        # Находим связанный порт
        port_num = "unknown"
        service = "unknown"
        
        # Пытаемся извлечь порт из имени скрипта
        port_match = re.search(r'port(\d+)_', script_name)
        if port_match:
            port_num = port_match.group(1)
        else:
            # Ищем порт в выводе
            port_in_output = re.search(r'port\s*(\d+)', script_lower)
            if port_in_output:
                port_num = port_in_output.group(1)
        
        # Находим сервис для порта
        if port_num != "unknown":
            for port in host.ports:
                if str(port.port) == port_num:
                    service = port.service
                    break
        
        return {
            'type': 'SCRIPT',
            'script': script_name,
            'service': service,
            'port': port_num,
            'risk': risk,
            'issue': issue,
            'recommendation': 'Investigate the script output for details'
        }
    
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
        self.current_host = None
        self.vuln_btn.setVisible(False)
