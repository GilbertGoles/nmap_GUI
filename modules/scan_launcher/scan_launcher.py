from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QLabel, QComboBox, QLineEdit, QSpinBox, 
                             QCheckBox, QPushButton, QTextEdit, QProgressBar,
                             QFormLayout, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSlot
from modules.base_module import BaseTabModule
from shared.models.scan_config import ScanConfig, ScanType
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ScanLauncherTab(event_bus, dependencies)

class ScanLauncherTab(BaseTabModule):
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
    
    def _create_ui(self):
        """Создает UI компонент запуска сканирований"""
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("NMAP Scan Launcher")
        title.setStyleSheet("font-size: 16pt; font-weight: bold;")
        layout.addWidget(title)
        
        # Группа настроек сканирования
        settings_group = QGroupBox("Scan Settings")
        settings_layout = QFormLayout(settings_group)
        
        # Цели сканирования
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("192.168.1.1, 10.0.0.0/24, scanme.nmap.org")
        settings_layout.addRow("Targets:", self.targets_input)
        
        # Тип сканирования
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Quick Scan", "Stealth Scan", "Comprehensive Scan"])
        settings_layout.addRow("Scan Type:", self.scan_type_combo)
        
        # Диапазон портов
        self.ports_input = QLineEdit("1-1000")
        settings_layout.addRow("Ports:", self.ports_input)
        
        # Опции
        self.service_version_check = QCheckBox("Service version detection")
        settings_layout.addRow(self.service_version_check)
        
        self.os_detection_check = QCheckBox("OS detection")
        settings_layout.addRow(self.os_detection_check)
        
        layout.addWidget(settings_group)
        
        # Панель управления
        control_group = QGroupBox("Scan Control")
        control_layout = QHBoxLayout(control_group)
        
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self._start_scan)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.progress_bar)
        control_layout.addStretch()
        
        layout.addWidget(control_group)
        
        # Предпросмотр команды
        command_group = QGroupBox("Command Preview")
        command_layout = QVBoxLayout(command_group)
        
        self.command_preview = QTextEdit()
        self.command_preview.setMaximumHeight(60)
        self.command_preview.setReadOnly(True)
        command_layout.addWidget(self.command_preview)
        
        layout.addWidget(command_group)
        
        # Обновляем предпросмотр команды
        self._update_command_preview()
        
        # Подключаем сигналы для обновления предпросмотра
        self.targets_input.textChanged.connect(self._update_command_preview)
        self.scan_type_combo.currentTextChanged.connect(self._update_command_preview)
        self.ports_input.textChanged.connect(self._update_command_preview)
    
    def _update_command_preview(self):
        """Обновляет предпросмотр команды nmap"""
        targets = self.targets_input.text().strip()
        scan_type = self.scan_type_combo.currentText()
        ports = self.ports_input.text().strip()
        
        if not targets:
            self.command_preview.setPlainText("Enter targets to see command preview")
            return
        
        # Строим базовую команду
        cmd_parts = ["nmap"]
        
        # Добавляем тип сканирования
        if scan_type == "Quick Scan":
            cmd_parts.append("-F")
        elif scan_type == "Stealth Scan":
            cmd_parts.append("-sS")
        elif scan_type == "Comprehensive Scan":
            cmd_parts.extend(["-sS", "-sV", "-O", "-A"])
        
        # Добавляем порты
        if ports:
            cmd_parts.append(f"-p {ports}")
        
        # Добавляем цели
        cmd_parts.append(targets)
        
        command = " ".join(cmd_parts)
        self.command_preview.setPlainText(command)
    
    def _start_scan(self):
        """Запускает сканирование"""
        targets_text = self.targets_input.text().strip()
        if not targets_text:
            self.command_preview.setPlainText("Error: No targets specified")
            return
        
        try:
            # Создаем конфигурацию сканирования
            import uuid
            config = ScanConfig(
                scan_id=str(uuid.uuid4()),
                targets=[target.strip() for target in targets_text.split(',')],
                scan_type=ScanType.CUSTOM,
                port_range=self.ports_input.text(),
                service_version=self.service_version_check.isChecked(),
                os_detection=self.os_detection_check.isChecked()
            )
            
            # Запускаем сканирование
            scan_manager = self.dependencies.get('scan_manager')
            if scan_manager:
                scan_id = scan_manager.submit_scan(config)
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(0)
                
        except Exception as e:
            self.command_preview.setPlainText(f"Error starting scan: {e}")
    
    def _stop_scan(self):
        """Останавливает сканирование"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
    
    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса сканирования"""
        progress = data.get('progress', 0)
        self.progress_bar.setValue(progress)
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        self._stop_scan()
        self.command_preview.setPlainText("Scan completed successfully!")
