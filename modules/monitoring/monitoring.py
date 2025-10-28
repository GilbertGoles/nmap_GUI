from PyQt6.QtWidgets import (QVBoxLayout, QGroupBox,
                             QTextEdit, QLabel, QTableWidget,
                             QTableWidgetItem, QHeaderView, QHBoxLayout, QPushButton)
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
        self.event_bus.scan_stopped.connect(self._on_scan_stopped)
    
    def _create_ui(self):
        """Создает UI компонент мониторинга"""
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("Scan Monitoring")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Панель управления
        control_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear Log")
        self.clear_btn.clicked.connect(self._clear_log)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Таблица активных сканирований
        scans_group = QGroupBox("Active Scans")
        scans_layout = QVBoxLayout(scans_group)
        
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(6)  # Увеличили количество колонок
        self.scans_table.setHorizontalHeaderLabels([
            "Scan ID", "Targets", "Type", "Intensity", "Progress", "Status"
        ])
        
        # Настройка таблицы
        header = self.scans_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
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
        
        # Статистика
        self.status_label = QLabel("Ready - No active scans")
        layout.addWidget(self.status_label)
        
        # Хранилище данных
        self.active_scans = {}
    
    def _log_event(self, message: str, level: str = "INFO"):
        """Добавляет запись в журнал событий"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "black",
            "WARNING": "orange", 
            "ERROR": "red",
            "SUCCESS": "green"
        }
        color = color_map.get(level, "black")
        
        formatted_message = f'<font color="{color}">[{timestamp}] [{level}] {message}</font>'
        self.event_log.append(formatted_message)
        
        # Автопрокрутка вниз
        cursor = self.event_log.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.event_log.setTextCursor(cursor)
    
    def _clear_log(self):
        """Очищает журнал событий"""
        self.event_log.clear()
    
    @pyqtSlot(dict)
    def _on_scan_started(self, data):
        """Обрабатывает начало сканирования"""
        scan_id = data.get('scan_id')
        config = data.get('config')
        
        if not scan_id or not config:
            return
        
        self._log_event(f"🚀 Scan started: {scan_id}", "INFO")
        self._log_event(f"📋 Targets: {', '.join(config.targets)}", "INFO")
        self._log_event(f"🔧 Type: {config.scan_type.value}", "INFO")
        self._log_event(f"⚡ Intensity: {config.scan_intensity.value}", "INFO")
        
        # Добавляем в таблицу
        row = self.scans_table.rowCount()
        self.scans_table.insertRow(row)
        
        self.scans_table.setItem(row, 0, QTableWidgetItem(scan_id[:8]))
        
        targets_text = ", ".join(config.targets[:2])  # Показываем только 2 цели
        if len(config.targets) > 2:
            targets_text += f" ... (+{len(config.targets) - 2})"
        self.scans_table.setItem(row, 1, QTableWidgetItem(targets_text))
        
        self.scans_table.setItem(row, 2, QTableWidgetItem(config.scan_type.value))
        self.scans_table.setItem(row, 3, QTableWidgetItem(config.scan_intensity.value))
        self.scans_table.setItem(row, 4, QTableWidgetItem("0%"))
        self.scans_table.setItem(row, 5, QTableWidgetItem("Running"))
        
        # Сохраняем информацию о сканировании
        self.active_scans[scan_id] = {
            'row': row,
            'config': config,
            'progress': 0
        }
        
        self._update_status()
    
    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса"""
        scan_id = data.get('scan_id')
        progress = data.get('progress', 0)
        status = data.get('status', '')
        
        if scan_id not in self.active_scans:
            return
        
        # Обновляем прогресс в таблице
        scan_info = self.active_scans[scan_id]
        row = scan_info['row']
        
        self.scans_table.item(row, 4).setText(f"{progress}%")
        
        if status:
            self.scans_table.item(row, 5).setText(status[:30])  # Обрезаем длинный статус
        
        # Обновляем прогресс в хранилище
        self.active_scans[scan_id]['progress'] = progress
        
        # Логируем значительные изменения прогресса
        if progress % 20 == 0 or progress == 100:  # Каждые 20% или при завершении
            self._log_event(f"📊 Scan {scan_id[:8]}: {progress}% complete", "INFO")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if scan_id not in self.active_scans:
            return
        
        scan_info = self.active_scans[scan_id]
        row = scan_info['row']
        
        if results and results.status == "completed":
            host_count = len(results.hosts) if hasattr(results, 'hosts') else 0
            open_ports = sum(len([p for p in h.ports if p.state == 'open']) for h in results.hosts) if results.hosts else 0
            
            self.scans_table.item(row, 4).setText("100%")
            self.scans_table.item(row, 5).setText("Completed")
            
            self._log_event(f"✅ Scan {scan_id[:8]} completed successfully!", "SUCCESS")
            self._log_event(f"📊 Results: {host_count} hosts, {open_ports} open ports", "INFO")
        else:
            self.scans_table.item(row, 5).setText("Failed")
            self._log_event(f"❌ Scan {scan_id[:8]} failed", "ERROR")
        
        # Удаляем из активных сканирований
        del self.active_scans[scan_id]
        self._update_status()
    
    @pyqtSlot(dict)
    def _on_scan_stopped(self, data):
        """Обрабатывает остановку сканирования"""
        scan_id = data.get('scan_id')
        
        if scan_id in self.active_scans:
            scan_info = self.active_scans[scan_id]
            row = scan_info['row']
            
            self.scans_table.item(row, 5).setText("Stopped")
            self._log_event(f"⏹️ Scan {scan_id[:8]} stopped by user", "WARNING")
            
            del self.active_scans[scan_id]
            self._update_status()
    
    def _update_status(self):
        """Обновляет статусную строку"""
        active_count = len(self.active_scans)
        if active_count == 0:
            self.status_label.setText("Ready - No active scans")
        else:
            total_progress = sum(scan['progress'] for scan in self.active_scans.values())
            avg_progress = total_progress // active_count if active_count > 0 else 0
            self.status_label.setText(f"Monitoring {active_count} active scans - Average progress: {avg_progress}%")
