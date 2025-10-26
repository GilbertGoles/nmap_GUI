from PyQt6.QtWidgets import (QVBoxLayout, QGroupBox,
                             QTextEdit, QLabel, QTableWidget,
                             QTableWidgetItem, QHeaderView)
from PyQt6.QtCore import pyqtSlot
from datetime import datetime
from modules.base_module import BaseTabModule
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return MonitoringTab(event_bus, dependencies)

class MonitoringTab(BaseTabModule):
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_started.connect(self._on_scan_started)
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
    
    def _create_ui(self):
        """Создает UI компонент мониторинга"""
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("Scan Monitoring")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Таблица активных сканирований
        scans_group = QGroupBox("Active Scans")
        scans_layout = QVBoxLayout(scans_group)
        
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(4)
        self.scans_table.setHorizontalHeaderLabels([
            "Scan ID", "Targets", "Progress", "Status"
        ])
        
        # Настройка таблицы
        header = self.scans_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        scans_layout.addWidget(self.scans_table)
        layout.addWidget(scans_group)
        
        # Журнал событий
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout(log_group)
        
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setMaximumHeight(200)
        log_layout.addWidget(self.event_log)
        
        layout.addWidget(log_group)
        
        # Статус
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
    
    def _log_event(self, message: str, level: str = "INFO"):
        """Добавляет запись в журнал событий"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        self.event_log.append(formatted_message)
    
    @pyqtSlot(dict)
    def _on_scan_started(self, data):
        """Обрабатывает начало сканирования"""
        scan_id = data.get('scan_id')
        config = data.get('config')
        
        self._log_event(f"Scan started: {scan_id}")
        
        # Добавляем в таблицу
        row = self.scans_table.rowCount()
        self.scans_table.insertRow(row)
        
        self.scans_table.setItem(row, 0, QTableWidgetItem(scan_id[:8]))
        
        targets_text = ", ".join(config.targets[:3])
        if len(config.targets) > 3:
            targets_text += f" ... (+{len(config.targets) - 3})"
        self.scans_table.setItem(row, 1, QTableWidgetItem(targets_text))
        
        self.scans_table.setItem(row, 2, QTableWidgetItem("0%"))
        self.scans_table.setItem(row, 3, QTableWidgetItem("Running"))
    
    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса"""
        scan_id = data.get('scan_id')
        progress = data.get('progress', 0)
        
        # Обновляем прогресс в таблице
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 2).setText(f"{progress}%")
                break
        
        self._log_event(f"Scan {scan_id[:8]}: {progress}% complete")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        self._log_event(f"Scan completed: {scan_id}")
        
        # Обновляем статус в таблице
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 3).setText("Completed")
                break
