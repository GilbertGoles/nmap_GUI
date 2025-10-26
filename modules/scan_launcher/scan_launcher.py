from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QLabel, QComboBox, QLineEdit, QSpinBox, 
                             QCheckBox, QPushButton, QTextEdit, QProgressBar,
                             QFormLayout)
from PyQt6.QtCore import pyqtSlot
from modules.base_module import BaseTabModule
from shared.models.scan_config import ScanConfig, ScanType
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ScanLauncherTab(event_bus, dependencies)

class ScanLauncherTab(BaseTabModule):
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.current_scan_id = None
        
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
        self.event_bus.scan_paused.connect(self._on_scan_paused)
        self.event_bus.scan_resumed.connect(self._on_scan_resumed)
        self.event_bus.scan_stopped.connect(self._on_scan_stopped)
    
    def _create_ui(self):
        """Создает UI компонент запуска сканирований"""
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("NMAP Scan Launcher")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Статус сканирования
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-weight: bold; color: green;")
        layout.addWidget(self.status_label)
        
        # Группа настроек сканирования
        settings_group = QGroupBox("Scan Settings")
        settings_layout = QFormLayout(settings_group)
        
        # Цели сканирования
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("192.168.1.1, 10.0.0.0/24, scanme.nmap.org")
        settings_layout.addRow("Targets:", self.targets_input)
        
        # Тип сканирования
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Quick Scan", "Stealth Scan", "Comprehensive Scan", "Custom"])
        settings_layout.addRow("Scan Type:", self.scan_type_combo)
        
        # Диапазон портов
        self.ports_input = QLineEdit("1-1000")
        settings_layout.addRow("Ports:", self.ports_input)
        
        # Потоки
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 16)
        self.threads_spinbox.setValue(4)
        settings_layout.addRow("Threads:", self.threads_spinbox)
        
        # Опции
        self.service_version_check = QCheckBox("Service version detection")
        settings_layout.addRow(self.service_version_check)
        
        self.os_detection_check = QCheckBox("OS detection")
        settings_layout.addRow(self.os_detection_check)
        
        # Добавляем чекбокс для script scanning
        self.script_scan_check = QCheckBox("Script scanning (NSE)")
        settings_layout.addRow(self.script_scan_check)
        
        layout.addWidget(settings_group)
        
        # Панель управления
        control_group = QGroupBox("Scan Control")
        control_layout = QHBoxLayout(control_group)
        
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self._start_scan)
        
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self._pause_scan)
        self.pause_btn.setEnabled(False)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.pause_btn)
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
        self.service_version_check.stateChanged.connect(self._update_command_preview)
        self.os_detection_check.stateChanged.connect(self._update_command_preview)
        self.script_scan_check.stateChanged.connect(self._update_command_preview)
    
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
            cmd_parts.extend(["-sS", "-sV", "-O", "-A", "--script=default"])
        # Для Custom типа добавляем опции на основе чекбоксов
        elif scan_type == "Custom":
            if self.service_version_check.isChecked():
                cmd_parts.append("-sV")
            if self.os_detection_check.isChecked():
                cmd_parts.append("-O")
            if self.script_scan_check.isChecked():
                cmd_parts.append("--script=default")
        
        # Добавляем потоки
        cmd_parts.append(f"--min-parallelism {self.threads_spinbox.value()}")
        
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
            self.status_label.setText("Error: No targets specified")
            return
        
        try:
            # Парсим цели (убираем порты из IP адресов)
            targets = []
            for target in targets_text.split(','):
                target = target.strip()
                # Если указан IP:PORT, убираем порт
                if ':' in target and not target.startswith(('http', 'https')):
                    ip_part = target.split(':')[0]
                    if self._is_valid_ip(ip_part):
                        targets.append(ip_part)
                        self.status_label.setText(f"Note: Using {ip_part} instead of {target}")
                    else:
                        targets.append(target)
                else:
                    targets.append(target)
            
            # Создаем конфигурацию сканирования
            import uuid
            config = ScanConfig(
                scan_id=str(uuid.uuid4()),
                targets=targets,
                scan_type=ScanType.CUSTOM,
                port_range=self.ports_input.text(),
                threads=self.threads_spinbox.value(),
                service_version=self.service_version_check.isChecked(),
                os_detection=self.os_detection_check.isChecked(),
                script_scan=self.script_scan_check.isChecked()
            )
            
            # Запускаем сканирование
            scan_manager = self.dependencies.get('scan_manager')
            if scan_manager:
                self.current_scan_id = scan_manager.submit_scan(config)
                self.start_btn.setEnabled(False)
                self.pause_btn.setEnabled(True)
                self.stop_btn.setEnabled(True)
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(0)
                self.status_label.setText(f"Scan started: {self.current_scan_id[:8]}")
                
        except Exception as e:
            self.status_label.setText(f"Error starting scan: {e}")
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Проверяет валидность IP адреса"""
        import ipaddress
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def _pause_scan(self):
        """Приостанавливает сканирование"""
        if self.current_scan_id:
            self.event_bus.scan_paused.emit({'scan_id': self.current_scan_id})
            self.status_label.setText("Scan paused")
            self.status_label.setStyleSheet("font-weight: bold; color: orange;")
            self.pause_btn.setText("Resume")
            self.pause_btn.clicked.disconnect()
            self.pause_btn.clicked.connect(self._resume_scan)
    
    def _resume_scan(self):
        """Возобновляет сканирование"""
        if self.current_scan_id:
            self.event_bus.scan_resumed.emit({'scan_id': self.current_scan_id})
            self.status_label.setText("Scan resumed")
            self.status_label.setStyleSheet("font-weight: bold; color: blue;")
            self.pause_btn.setText("Pause")
            self.pause_btn.clicked.disconnect()
            self.pause_btn.clicked.connect(self._pause_scan)
    
    def _stop_scan(self):
        """Останавливает сканирование"""
        if self.current_scan_id:
            self.event_bus.scan_stopped.emit({'scan_id': self.current_scan_id})
            self._reset_scan_controls()
            self.status_label.setText("Scan stopped")
            self.status_label.setStyleSheet("font-weight: bold; color: red;")
    
    def _reset_scan_controls(self):
        """Сбрасывает элементы управления сканированием"""
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
        self.current_scan_id = None
        
        # Восстанавливаем кнопку паузы
        self.pause_btn.setText("Pause")
        self.pause_btn.clicked.disconnect()
        self.pause_btn.clicked.connect(self._pause_scan)
    
    def _set_scan_running_state(self, running: bool):
        """Устанавливает состояние элементов управления при запуске/остановке сканирования"""
        self.start_btn.setEnabled(not running)
        self.pause_btn.setEnabled(running)
        self.stop_btn.setEnabled(running)

    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса сканирования"""
        scan_id = data.get('scan_id')
        progress = data.get('progress', 0)
        status = data.get('status', '')
        
        if scan_id == self.current_scan_id:
            self.progress_bar.setValue(progress)
            if status:
                self.status_label.setText(f"Scanning... {progress}% - {status[:50]}")
            else:
                self.status_label.setText(f"Scanning... {progress}%")

    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if scan_id == self.current_scan_id:
            self._reset_scan_controls()
            if results and hasattr(results, 'hosts'):
                host_count = len(results.hosts)
                port_count = sum(len([p for p in h.ports if p.state == 'open']) for h in results.hosts)
                self.status_label.setText(f"Scan completed! Found {host_count} hosts with {port_count} open ports")
            else:
                self.status_label.setText("Scan completed (no results)")
    
    @pyqtSlot(dict)
    def _on_scan_paused(self, data):
        """Обрабатывает событие паузы сканирования"""
        if data.get('scan_id') == self.current_scan_id:
            self.status_label.setText("Scan paused")
            self.status_label.setStyleSheet("font-weight: bold; color: orange;")
    
    @pyqtSlot(dict)
    def _on_scan_resumed(self, data):
        """Обрабатывает событие возобновления сканирования"""
        if data.get('scan_id') == self.current_scan_id:
            self.status_label.setText("Scan resumed")
            self.status_label.setStyleSheet("font-weight: bold; color: blue;")
    
    @pyqtSlot(dict)
    def _on_scan_stopped(self, data):
        """Обрабатывает событие остановки сканирования"""
        if data.get('scan_id') == self.current_scan_id:
            self._reset_scan_controls()
            self.status_label.setText("Scan stopped")
            self.status_label.setStyleSheet("font-weight: bold; color: red;")
