from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QPushButton, QComboBox, QTextEdit, QFileDialog,
                             QLabel, QCheckBox, QProgressBar, QTableWidget,
                             QTableWidgetItem, QHeaderView, QSplitter,
                             QMessageBox, QLineEdit, QFormLayout)
from PyQt6.QtCore import Qt, pyqtSlot
import os
import json
import csv
import html
from datetime import datetime
from typing import List, Dict

from modules.base_module import BaseTabModule
from core.event_bus import EventBus
from shared.models.scan_result import ScanResult, HostInfo, PortInfo

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ReportingTab(event_bus, dependencies)

class ReportingTab(BaseTabModule):
    TAB_NAME = "Reporting"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.current_results = None
        self.report_templates = {}
        
        # Загружаем шаблоны отчетов
        self._load_report_templates()
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.results_updated.connect(self._on_results_updated)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
    
    def _create_ui(self) -> QWidget:
        """Создает UI компонент отчетов"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Панель управления отчетами
        layout.addWidget(self._create_control_panel())
        
        # Сплиттер для предпросмотра и настроек
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая часть - настройки отчета
        splitter.addWidget(self._create_settings_widget())
        
        # Правая часть - предпросмотр отчета
        splitter.addWidget(self._create_preview_widget())
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        return widget
    
    def _create_control_panel(self) -> QGroupBox:
        """Создает панель управления отчетами"""
        group = QGroupBox("Report Control")
        layout = QHBoxLayout(group)
        
        # Выбор шаблона
        layout.addWidget(QLabel("Template:"))
        self.template_combo = QComboBox()
        self.template_combo.addItems(list(self.report_templates.keys()))
        self.template_combo.currentTextChanged.connect(self._on_template_changed)
        layout.addWidget(self.template_combo)
        
        # Формат экспорта
        layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "JSON", "CSV", "TXT", "XML"])
        layout.addWidget(self.format_combo)
        
        # Кнопки
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self._generate_report)
        layout.addWidget(self.generate_btn)
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self._export_report)
        layout.addWidget(self.export_btn)
        
        self.preview_btn = QPushButton("Refresh Preview")
        self.preview_btn.clicked.connect(self._refresh_preview)
        layout.addWidget(self.preview_btn)
        
        return group
    
    def _create_settings_widget(self) -> QGroupBox:
        """Создает виджет настроек отчета"""
        group = QGroupBox("Report Settings")
        layout = QVBoxLayout(group)
        
        # Основные настройки
        form_layout = QFormLayout()
        
        self.report_title = QLineEdit("Network Security Scan Report")
        form_layout.addRow("Report Title:", self.report_title)
        
        self.include_executive_summary = QCheckBox("Include Executive Summary")
        self.include_executive_summary.setChecked(True)
        form_layout.addRow(self.include_executive_summary)
        
        self.include_host_details = QCheckBox("Include Host Details")
        self.include_host_details.setChecked(True)
        form_layout.addRow(self.include_host_details)
        
        self.include_service_details = QCheckBox("Include Service Details")
        self.include_service_details.setChecked(True)
        form_layout.addRow(self.include_service_details)
        
        self.include_vulnerabilities = QCheckBox("Include Potential Vulnerabilities")
        self.include_vulnerabilities.setChecked(True)
        form_layout.addRow(self.include_vulnerabilities)
        
        self.include_recommendations = QCheckBox("Include Recommendations")
        self.include_recommendations.setChecked(True)
        form_layout.addRow(self.include_recommendations)
        
        self.include_scan_intensity = QCheckBox("Include Scan Methodology")
        self.include_scan_intensity.setChecked(True)
        form_layout.addRow(self.include_scan_intensity)
        
        layout.addLayout(form_layout)
        
        # Дополнительные опции
        layout.addWidget(QLabel("Custom Sections:"))
        self.custom_sections = QTextEdit()
        self.custom_sections.setMaximumHeight(100)
        self.custom_sections.setPlaceholderText("Add custom sections or notes for the report...")
        layout.addWidget(self.custom_sections)
        
        return group
    
    def _create_preview_widget(self) -> QGroupBox:
        """Создает виджет предпросмотра отчета"""
        group = QGroupBox("Report Preview")
        layout = QVBoxLayout(group)
        
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        layout.addWidget(self.preview_text)
        
        # Статус
        self.preview_status = QLabel("No report generated")
        layout.addWidget(self.preview_status)
        
        return group
    
    def _load_report_templates(self):
        """Загружает шаблоны отчетов"""
        self.report_templates = {
            "Executive Summary": {
                "description": "High-level summary for management",
                "sections": ["executive_summary", "statistics", "recommendations"]
            },
            "Technical Detailed": {
                "description": "Detailed technical report for engineers",
                "sections": ["executive_summary", "methodology", "statistics", 
                           "host_details", "service_details", "vulnerabilities"]
            },
            "Comprehensive": {
                "description": "Complete report with all details",
                "sections": ["executive_summary", "methodology", "statistics",
                           "host_details", "service_details", "vulnerabilities",
                           "recommendations", "appendix"]
            },
            "Quick Overview": {
                "description": "Brief overview of findings",
                "sections": ["statistics", "key_findings"]
            },
            "Penetration Test": {
                "description": "Report formatted for penetration testing",
                "sections": ["executive_summary", "methodology", "findings",
                           "risk_assessment", "recommendations"]
            }
        }
    
    def _on_template_changed(self, template_name):
        """Обрабатывает изменение шаблона отчета"""
        if template_name in self.report_templates:
            template = self.report_templates[template_name]
            self.preview_status.setText(f"Template: {template_name} - {template['description']}")
    
    def _generate_report(self):
        """Генерирует отчет"""
        if not self.current_results:
            QMessageBox.warning(self, "Warning", "No scan results available!")
            return
        
        try:
            report_content = self._create_report_content()
            self.preview_text.setHtml(report_content if self.format_combo.currentText() == "HTML" else report_content)
            self.preview_status.setText("Report generated successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report: {e}")
    
    def _export_report(self):
        """Экспортирует отчет в файл"""
        if not self.current_results:
            QMessageBox.warning(self, "Warning", "No report to export!")
            return
        
        file_format = self.format_combo.currentText().lower()
        default_name = f"nmap_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_format}"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            default_name,
            f"{file_format.upper()} Files (*.{file_format})"
        )
        
        if file_path:
            try:
                report_content = self._create_report_content()
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                QMessageBox.information(self, "Success", f"Report exported to {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {e}")
    
    def _refresh_preview(self):
        """Обновляет предпросмотр отчета"""
        self._generate_report()
    
    def _create_report_content(self) -> str:
        """Создает содержимое отчета"""
        format_type = self.format_combo.currentText()
        
        if format_type == "HTML":
            return self._generate_html_report()
        elif format_type == "JSON":
            return self._generate_json_report()
        elif format_type == "CSV":
            return self._generate_csv_report()
        elif format_type == "TXT":
            return self._generate_text_report()
        elif format_type == "XML":
            return self._generate_xml_report()
        else:
            return self._generate_html_report()
    
    def _generate_html_report(self) -> str:
        """Генерирует HTML отчет"""
        if not self.current_results:
            return "<h1>No scan results available</h1>"
        
        html_content = []
        
        # Заголовок и метаданные
        html_content.append(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{html.escape(self.report_title.text())}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .methodology {{ background: #e8f4f8; padding: 15px; border-radius: 5px; }}
                .host-table {{ width: 100%; border-collapse: collapse; }}
                .host-table th, .host-table td {{ border: 1px solid #ddd; padding: 8px; }}
                .host-table th {{ background: #4CAF50; color: white; }}
                .vulnerability {{ color: #d32f2f; font-weight: bold; }}
                .recommendation {{ background: #e8f5e8; padding: 10px; margin: 5px 0; }}
                .risk-high {{ color: #d32f2f; font-weight: bold; }}
                .risk-medium {{ color: #f57c00; }}
                .risk-low {{ color: #388e3c; }}
            </style>
        </head>
        <body>
            <h1>{html.escape(self.report_title.text())}</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        """)
        
        # Методология сканирования
        if self.include_scan_intensity.isChecked() and hasattr(self.current_results, 'config'):
            html_content.append(self._generate_methodology_html())
        
        # Executive Summary
        if self.include_executive_summary.isChecked():
            html_content.append(self._generate_executive_summary_html())
        
        # Статистика сканирования
        html_content.append(self._generate_statistics_html())
        
        # Детали хостов
        if self.include_host_details.isChecked():
            html_content.append(self._generate_host_details_html())
        
        # Детали сервисов
        if self.include_service_details.isChecked():
            html_content.append(self._generate_service_details_html())
        
        # Потенциальные уязвимости
        if self.include_vulnerabilities.isChecked():
            html_content.append(self._generate_vulnerabilities_html())
        
        # Рекомендации
        if self.include_recommendations.isChecked():
            html_content.append(self._generate_recommendations_html())
        
        # Пользовательские секции
        custom_text = self.custom_sections.toPlainText().strip()
        if custom_text:
            html_content.append(f"""
            <h2>Additional Notes</h2>
            <div class="custom-section">
                {html.escape(custom_text).replace('\n', '<br>')}
            </div>
            """)
        
        html_content.append("""
        </body>
        </html>
        """)
        
        return '\n'.join(html_content)
    
    def _generate_methodology_html(self) -> str:
        """Генерирует раздел методологии"""
        config = self.current_results.config
        intensity_map = {
            "safe": "SAFE - Basic security checks only",
            "normal": "NORMAL - Standard security assessment",
            "aggressive": "AGGRESSIVE - Advanced vulnerability detection", 
            "penetration": "PENETRATION - Full penetration testing"
        }
        
        intensity_text = intensity_map.get(config.scan_intensity.value, "Unknown")
        
        return f"""
        <div class="methodology">
            <h2>Scan Methodology</h2>
            <p><strong>Scan Type:</strong> {config.scan_type.value.upper()}</p>
            <p><strong>Intensity Level:</strong> {intensity_text}</p>
            <p><strong>Targets:</strong> {', '.join(config.targets)}</p>
            <p><strong>Port Range:</strong> {config.port_range or 'Default'}</p>
            <p><strong>Timing Template:</strong> {config.timing_template}</p>
            <p><strong>Additional Options:</strong> 
                { 'Service Detection' if config.service_version else ''}
                { 'OS Detection' if config.os_detection else ''}
                { 'Script Scanning' if config.script_scan else ''}
            </p>
        </div>
        """
    
    def _generate_executive_summary_html(self) -> str:
        """Генерирует executive summary"""
        stats = self._calculate_statistics()
        
        risk_level = "LOW"
        if stats['potential_vulnerabilities'] > 5:
            risk_level = "HIGH"
        elif stats['potential_vulnerabilities'] > 2:
            risk_level = "MEDIUM"
        
        return f"""
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>This report summarizes the results of the network security scan conducted on {datetime.now().strftime('%Y-%m-%d')}.</p>
            
            <h3>Key Findings</h3>
            <ul>
                <li><strong>Overall Risk Level:</strong> <span class="risk-{risk_level.lower()}">{risk_level}</span></li>
                <li><strong>Total Hosts Scanned:</strong> {stats['total_hosts']}</li>
                <li><strong>Active Hosts Found:</strong> {stats['active_hosts']}</li>
                <li><strong>Open Ports Discovered:</strong> {stats['open_ports']}</li>
                <li><strong>Unique Services:</strong> {stats['unique_services']}</li>
                <li><strong>Potential Vulnerabilities:</strong> {stats['potential_vulnerabilities']}</li>
            </ul>
            
            <p>The scan revealed {stats['active_hosts']} active hosts with {stats['open_ports']} open ports 
            running {stats['unique_services']} different services. {stats['potential_vulnerabilities']} potential 
            security vulnerabilities were identified during the assessment.</p>
        </div>
        """
    
    def _generate_statistics_html(self) -> str:
        """Генерирует статистику"""
        stats = self._calculate_statistics()
        
        # Топ сервисов
        top_services = self._get_top_services(10)
        
        html = f"""
        <h2>Scan Statistics</h2>
        <table class="host-table">
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Hosts</td><td>{stats['total_hosts']}</td></tr>
            <tr><td>Active Hosts</td><td>{stats['active_hosts']}</td></tr>
            <tr><td>Open Ports</td><td>{stats['open_ports']}</td></tr>
            <tr><td>Unique Services</td><td>{stats['unique_services']}</td></tr>
            <tr><td>OS Detected</td><td>{stats['os_detected']}</td></tr>
            <tr><td>Potential Vulnerabilities</td><td>{stats['potential_vulnerabilities']}</td></tr>
        </table>
        
        <h3>Top Services</h3>
        <table class="host-table">
            <tr><th>Service</th><th>Count</th><th>Common Ports</th></tr>
        """
        
        for service, count, common_ports in top_services:
            html += f"<tr><td>{service}</td><td>{count}</td><td>{', '.join(map(str, common_ports[:3]))}</td></tr>"
        
        html += "</table>"
        return html
    
    def _generate_host_details_html(self) -> str:
        """Генерирует детали хостов"""
        html = "<h2>Host Details</h2>"
        
        for host in self.current_results.hosts:
            if host.state == "up":
                vulnerability_count = self._count_vulnerabilities(host)
                risk_indicator = "🔴" if vulnerability_count > 0 else "🟢"
                
                html += f"""
                <h3>{risk_indicator} Host: {host.ip} {f'({host.hostname})' if host.hostname else ''}</h3>
                <table class="host-table">
                    <tr><th>Property</th><th>Value</th></tr>
                    <tr><td>Status</td><td>{host.state}</td></tr>
                    <tr><td>OS</td><td>{host.os_family or 'Unknown'} {host.os_details or ''}</td></tr>
                    <tr><td>Open Ports</td><td>{len([p for p in host.ports if p.state == 'open'])}</td></tr>
                    <tr><td>Potential Vulnerabilities</td><td>{vulnerability_count}</td></tr>
                </table>
                """
                
                # Порты хоста
                open_ports = [p for p in host.ports if p.state == 'open']
                if open_ports:
                    html += "<h4>Open Ports</h4><table class='host-table'><tr><th>Port</th><th>Service</th><th>Version</th></tr>"
                    for port in open_ports:
                        html += f"<tr><td>{port.port}/{port.protocol}</td><td>{port.service}</td><td>{port.version or 'N/A'}</td></tr>"
                    html += "</table>"
        
        return html
    
    def _generate_service_details_html(self) -> str:
        """Генерирует детали сервисов"""
        # Группируем сервисы по типу
        services = {}
        for host in self.current_results.hosts:
            for port in host.ports:
                if port.state == 'open' and port.service != 'unknown':
                    if port.service not in services:
                        services[port.service] = []
                    services[port.service].append((host, port))
        
        html = "<h2>Service Details</h2>"
        
        for service, hosts_ports in services.items():
            html += f"<h3>{service} ({len(hosts_ports)} instances)</h3><ul>"
            for host, port in hosts_ports[:10]:  # Ограничиваем для читаемости
                html += f"<li>{host.ip}:{port.port} - {port.version or 'Version unknown'}</li>"
            if len(hosts_ports) > 10:
                html += f"<li>... and {len(hosts_ports) - 10} more</li>"
            html += "</ul>"
        
        return html
    
    def _generate_vulnerabilities_html(self) -> str:
        """Генерирует раздел потенциальных уязвимостей"""
        vulnerabilities = self._find_potential_vulnerabilities()
        
        html = "<h2>Potential Vulnerabilities</h2>"
        
        if not vulnerabilities:
            html += "<p>No obvious vulnerabilities detected based on service versions and script output.</p>"
            return html
        
        # Группируем по уровню риска
        high_risk = [v for v in vulnerabilities if v['risk'] == 'HIGH']
        medium_risk = [v for v in vulnerabilities if v['risk'] == 'MEDIUM']
        low_risk = [v for v in vulnerabilities if v['risk'] == 'LOW']
        
        if high_risk:
            html += "<h3 class='risk-high'>High Risk Vulnerabilities</h3>"
            for vuln in high_risk:
                html += self._format_vulnerability_html(vuln)
        
        if medium_risk:
            html += "<h3 class='risk-medium'>Medium Risk Vulnerabilities</h3>"
            for vuln in medium_risk:
                html += self._format_vulnerability_html(vuln)
        
        if low_risk:
            html += "<h3 class='risk-low'>Low Risk Vulnerabilities</h3>"
            for vuln in low_risk:
                html += self._format_vulnerability_html(vuln)
        
        return html
    
    def _format_vulnerability_html(self, vuln: dict) -> str:
        """Форматирует информацию об уязвимости в HTML"""
        return f"""
        <div class="vulnerability">
            <h4>{vuln['service']} on {vuln['host']}:{vuln['port']} <span class="risk-{vuln['risk'].lower()}">[{vuln['risk']} RISK]</span></h4>
            <p><strong>Version:</strong> {vuln['version']}</p>
            <p><strong>Potential Issue:</strong> {vuln['issue']}</p>
            <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
        </div>
        """
    
    def _generate_recommendations_html(self) -> str:
        """Генерирует рекомендации"""
        stats = self._calculate_statistics()
        vulnerabilities = self._find_potential_vulnerabilities()
        
        html = "<h2>Security Recommendations</h2>"
        
        recommendations = []
        
        # Рекомендации based on findings
        if stats['open_ports'] > 50:
            recommendations.append(("HIGH", "Reduce the number of open ports to minimize attack surface"))
        
        if any('ftp' in port.service.lower() for host in self.current_results.hosts for port in host.ports if port.state == 'open'):
            recommendations.append(("HIGH", "Replace FTP with SFTP or FTPS for secure file transfer"))
        
        if any('telnet' in port.service.lower() for host in self.current_results.hosts for port in host.ports if port.state == 'open'):
            recommendations.append(("HIGH", "Replace Telnet with SSH for secure remote access"))
        
        if stats['potential_vulnerabilities'] > 0:
            recommendations.append(("HIGH", "Update vulnerable software versions to the latest stable releases"))
        
        # Общие рекомендации
        recommendations.extend([
            ("MEDIUM", "Implement regular security patching schedule"),
            ("MEDIUM", "Use firewall rules to restrict unnecessary network access"),
            ("MEDIUM", "Enable logging and monitoring for critical services"),
            ("LOW", "Conduct regular security assessments")
        ])
        
        # Группируем по приоритету
        for priority in ["HIGH", "MEDIUM", "LOW"]:
            priority_recs = [rec for rec in recommendations if rec[0] == priority]
            if priority_recs:
                html += f'<h3 class="risk-{priority.lower()}">{priority} Priority Recommendations</h3>'
                for _, rec in priority_recs:
                    html += f'<div class="recommendation">{rec}</div>'
        
        return html
    
    def _generate_json_report(self) -> str:
        """Генерирует JSON отчет"""
        report_data = {
            "metadata": {
                "title": self.report_title.text(),
                "generated": datetime.now().isoformat(),
                "scan_id": getattr(self.current_results, 'scan_id', 'unknown')
            },
            "statistics": self._calculate_statistics(),
            "vulnerabilities": self._find_potential_vulnerabilities(),
            "hosts": []
        }
        
        for host in self.current_results.hosts:
            host_data = {
                "ip": host.ip,
                "hostname": host.hostname,
                "status": host.state,
                "os": {
                    "family": host.os_family,
                    "details": host.os_details
                },
                "ports": [],
                "vulnerability_count": self._count_vulnerabilities(host)
            }
            
            for port in host.ports:
                if port.state == 'open':
                    host_data["ports"].append({
                        "port": port.port,
                        "protocol": port.protocol,
                        "service": port.service,
                        "version": port.version
                    })
            
            report_data["hosts"].append(host_data)
        
        return json.dumps(report_data, indent=2)
    
    def _generate_csv_report(self) -> str:
        """Генерирует CSV отчет"""
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Заголовок
        writer.writerow(["Host", "Hostname", "Status", "Port", "Protocol", "Service", "Version", "OS", "Vulnerabilities"])
        
        # Данные
        for host in self.current_results.hosts:
            for port in host.ports:
                if port.state == 'open':
                    writer.writerow([
                        host.ip,
                        host.hostname,
                        host.state,
                        port.port,
                        port.protocol,
                        port.service,
                        port.version or "",
                        f"{host.os_family or ''} {host.os_details or ''}".strip(),
                        self._count_vulnerabilities(host)
                    ])
        
        return output.getvalue()
    
    def _generate_text_report(self) -> str:
        """Генерирует текстовый отчет"""
        lines = []
        lines.append(f"Report: {self.report_title.text()}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 50)
        
        stats = self._calculate_statistics()
        lines.append(f"Total Hosts: {stats['total_hosts']}")
        lines.append(f"Active Hosts: {stats['active_hosts']}")
        lines.append(f"Open Ports: {stats['open_ports']}")
        lines.append(f"Potential Vulnerabilities: {stats['potential_vulnerabilities']}")
        lines.append("")
        
        for host in self.current_results.hosts:
            if host.state == 'up':
                vuln_count = self._count_vulnerabilities(host)
                lines.append(f"Host: {host.ip} ({host.hostname or 'no hostname'}) [Vulnerabilities: {vuln_count}]")
                lines.append(f"  OS: {host.os_family or 'Unknown'} {host.os_details or ''}")
                lines.append("  Open Ports:")
                for port in host.ports:
                    if port.state == 'open':
                        lines.append(f"    {port.port}/{port.protocol}: {port.service} {port.version or ''}")
                lines.append("")
        
        return '\n'.join(lines)
    
    def _generate_xml_report(self) -> str:
        """Генерирует XML отчет"""
        # Используем существующий XML от nmap, добавляем метаданные
        if hasattr(self.current_results, 'raw_xml') and self.current_results.raw_xml:
            return self.current_results.raw_xml
        else:
            return "<?xml version=\"1.0\"?>\n<report>No raw XML data available</report>"
    
    def _calculate_statistics(self) -> Dict:
        """Вычисляет статистику сканирования"""
        if not self.current_results:
            return {}
        
        stats = {
            "total_hosts": len(self.current_results.hosts),
            "active_hosts": len([h for h in self.current_results.hosts if h.state == "up"]),
            "open_ports": 0,
            "unique_services": set(),
            "os_detected": 0,
            "potential_vulnerabilities": 0
        }
        
        for host in self.current_results.hosts:
            if host.os_family:
                stats["os_detected"] += 1
            
            for port in host.ports:
                if port.state == "open":
                    stats["open_ports"] += 1
                    if port.service and port.service != "unknown":
                        stats["unique_services"].add(port.service)
        
        stats["unique_services"] = len(stats["unique_services"])
        stats["potential_vulnerabilities"] = len(self._find_potential_vulnerabilities())
        
        return stats
    
    def _get_top_services(self, limit: int = 10) -> List[tuple]:
        """Возвращает топ сервисов по количеству"""
        service_count = {}
        service_ports = {}
        
        for host in self.current_results.hosts:
            for port in host.ports:
                if port.state == "open" and port.service != "unknown":
                    service = port.service
                    if service not in service_count:
                        service_count[service] = 0
                        service_ports[service] = set()
                    
                    service_count[service] += 1
                    service_ports[service].add(port.port)
        
        # Сортируем по количеству
        sorted_services = sorted(service_count.items(), key=lambda x: x[1], reverse=True)
        
        result = []
        for service, count in sorted_services[:limit]:
            common_ports = sorted(service_ports[service])
            result.append((service, count, common_ports))
        
        return result
    
    def _find_potential_vulnerabilities(self) -> List[Dict]:
        """Находит потенциальные уязвимости based on service versions и скриптов"""
        vulnerabilities = []
        
        # Расширенный список уязвимых версий
        vulnerable_versions = {
            "apache": [("2.4.49", "HIGH", "CVE-2021-41773 - Path Traversal"),
                      ("2.4.50", "HIGH", "CVE-2021-42013 - Path Traversal")],
            "openssh": [("7.0", "MEDIUM", "Multiple vulnerabilities"), 
                       ("7.1", "MEDIUM", "Multiple vulnerabilities"),
                       ("7.2", "MEDIUM", "Multiple vulnerabilities")],
            "ftp": [("vsftpd 2.3.4", "HIGH", "Backdoor command execution")],
            "samba": [("3.0.0", "HIGH", "Multiple vulnerabilities"),
                     ("3.0.1", "HIGH", "Multiple vulnerabilities")],
            "tomcat": [("7.0.0", "MEDIUM", "Initial release - consider upgrading"),
                      ("8.0.0", "MEDIUM", "Initial release - consider upgrading")]
        }
        
        for host in self.current_results.hosts:
            for port in host.ports:
                if port.state == "open" and port.version:
                    version_lower = port.version.lower()
                    
                    # Проверяем версии сервисов
                    for service, vulnerable_list in vulnerable_versions.items():
                        if service in port.service.lower() or service in version_lower:
                            for vulnerable_version, risk, issue in vulnerable_list:
                                if vulnerable_version in port.version:
                                    vulnerabilities.append({
                                        "host": host.ip,
                                        "port": port.port,
                                        "service": port.service,
                                        "version": port.version,
                                        "risk": risk,
                                        "issue": issue,
                                        "recommendation": f"Update {service} to latest version"
                                    })
                                    break
                    
                    # Проверяем скрипты nmap на индикаторы уязвимостей
                    for script_name, script_output in host.scripts.items():
                        script_lower = script_output.lower()
                        if any(keyword in script_lower for keyword in ['vulnerable', 'vulnerability']):
                            vulnerabilities.append({
                                "host": host.ip,
                                "port": port.port,
                                "service": port.service,
                                "version": port.version or "Unknown",
                                "risk": "MEDIUM",
                                "issue": f"Potential vulnerability detected by {script_name}",
                                "recommendation": "Investigate the script output for details"
                            })
        
        return vulnerabilities
    
    def _count_vulnerabilities(self, host: HostInfo) -> int:
        """Считает количество уязвимостей для хоста"""
        count = 0
        
        # Проверяем скрипты nmap
        for script_name, script_output in host.scripts.items():
            script_lower = script_output.lower()
            if any(keyword in script_lower for keyword in ['vulnerable', 'vulnerability', 'cve']):
                count += 1
        
        # Проверяем версии сервисов
        for port in host.ports:
            if port.version:
                version_lower = port.version.lower()
                if any(vuln in version_lower for vuln in ['2.4.49', '2.4.50', 'vsftpd 2.3.4']):
                    count += 1
        
        return count
    
    @pyqtSlot(dict)
    def _on_results_updated(self, data):
        """Обрабатывает обновление результатов"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results:
            self.current_results = results
            self.preview_status.setText(f"Results loaded: {len(results.hosts)} hosts")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if results:
            self.current_results = results
            self.preview_status.setText(f"Scan completed: {len(results.hosts)} hosts")
