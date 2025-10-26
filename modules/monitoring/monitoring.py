from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QTextEdit, QLabel, QProgressBar, QTableWidget,
                             QTableWidgetItem, QHeaderView, QSplitter)
from PyQt6.QtCore import Qt, pyqtSlot
from datetime import datetime
from modules.base_module import BaseTabModule
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return MonitoringTab(event_bus, dependencies)

class MonitoringTab(BaseTabModule):
    TAB_NAME = "Monitoring"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.scan_history = []
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_started.connect(self._on_scan_started)
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
        self.event_bus.scan_paused.connect(self._on_scan_paused)
        self.event_bus.scan_resumed.connect(self._on_scan_resumed)
        self.event_bus.scan_stopped.connect(self._on_scan_stopped)
    
    def _create_ui(self) -> QWidget:
        """Создает UI компонент мониторинга"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Сплиттер для разделения областей
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Верхняя часть - активные сканирования
        splitter.addWidget(self._create_active_scans_widget())
        
        # Нижняя часть - журнал событий
        splitter.addWidget(self._create_event_log_widget())
        
        # Устанавливаем пропорции
        splitter.setSizes([300, 200])
        
        layout.addWidget(splitter)
        return widget
    
    def _create_active_scans_widget(self) -> QGroupBox:
        """Создает виджет активных сканирований"""
        group = QGroupBox("Active Scans")
        layout = QVBoxLayout(group)
        
        # Таблица активных сканирований
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(6)
        self.scans_table.setHorizontalHeaderLabels([
            "Scan ID", "Targets", "Progress", "Status", "Start Time", "Actions"
        ])
        
        # Настройка таблицы
        header = self.scans_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.scans_table)
        
        return group
    
    def _create_event_log_widget(self) -> QGroupBox:
        """Создает виджет журнала событий"""
        group = QGroupBox("Event Log")
        layout = QVBoxLayout(group)
        
        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setMaximumHeight(200)
        
        layout.addWidget(self.event_log)
        
        # Кнопка очистки журнала
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self.event_log.clear)
        layout.addWidget(clear_btn)
        
        return group
    
    def _log_event(self, message: str, level: str = "INFO"):
        """Добавляет запись в журнал событий"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        self.event_log.append(formatted_message)
        
        # Автопрокрутка к последнему сообщению
        scrollbar = self.event_log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    @pyqtSlot(dict)
    def _on_scan_started(self, data):
        """Обрабатывает начало сканирования"""
        scan_id = data.get('scan_id')
        config = data.get('config')
        
        self._log_event(f"Scan started: {scan_id} - Targets: {', '.join(config.targets)}")
        
        # Добавляем в таблицу активных сканирований
        row = self.scans_table.rowCount()
        self.scans_table.insertRow(row)
        
        # Scan ID
        self.scans_table.setItem(row, 0, QTableWidgetItem(scan_id[:8]))
        
        # Targets (первые 3 цели)
        targets_preview = ', '.join(config.targets[:3])
        if len(config.targets) > 3:
            targets_preview += f" ... (+{len(config.targets) - 3} more)"
        self.scans_table.setItem(row, 1, QTableWidgetItem(targets_preview))
        
        # Progress
        progress_item = QTableWidgetItem("0%")
        self.scans_table.setItem(row, 2, progress_item)
        
        # Status
        status_item = QTableWidgetItem("Running")
        self.scans_table.setItem(row, 3, status_item)
        
        # Start Time
        start_time = datetime.now().strftime("%H:%M:%S")
        self.scans_table.setItem(row, 4, QTableWidgetItem(start_time))
        
        # Actions (заглушка)
        self.scans_table.setItem(row, 5, QTableWidgetItem("Pause | Stop"))
    
    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса"""
        scan_id = data.get('scan_id')
        progress = data.get('progress', 0)
        status = data.get('status', '')
        
        # Обновляем прогресс в таблице
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 2).setText(f"{progress}%")
                self.scans_table.item(row, 3).setText(status)
                break
        
        self._log_event(f"Scan {scan_id[:8]}: {progress}% - {status}")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        
        self._log_event(f"Scan completed: {scan_id}")
        
        # Обновляем статус в таблице
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 3).setText("Completed")
                self.scans_table.item(row, 2).setText("100%")
                break
    
    @pyqtSlot(dict)
    def _on_scan_paused(self, data):
        """Обрабатывает приостановку сканирования"""
        scan_id = data.get('scan_id')
        self._log_event(f"Scan paused: {scan_id}")
        
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 3).setText("Paused")
                break
    
    @pyqtSlot(dict)
    def _on_scan_resumed(self, data):
        """Обрабатывает возобновление сканирования"""
        scan_id = data.get('scan_id')
        self._log_event(f"Scan resumed: {scan_id}")
        
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 3).setText("Running")
                break
    
    @pyqtSlot(dict)
    def _on_scan_stopped(self, data):
        """Обрабатывает остановку сканирования"""
        scan_id = data.get('scan_id')
        self._log_event(f"Scan stopped: {scan_id}")
        
        for row in range(self.scans_table.rowCount()):
            if self.scans_table.item(row, 0).text() == scan_id[:8]:
                self.scans_table.item(row, 3).setText("Stopped")
                break
