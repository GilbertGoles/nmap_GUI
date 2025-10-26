from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QLabel, QComboBox, QLineEdit, QSpinBox, 
                             QCheckBox, QPushButton, QTextEdit, QProgressBar,
                             QFormLayout, QTabWidget, QScrollArea)
from PyQt6.QtCore import Qt, pyqtSlot
from modules.base_module import BaseTabModule
from shared.models.scan_config import ScanConfig, ScanType
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return ScanLauncherTab(event_bus, dependencies)

class ScanLauncherTab(BaseTabModule):
    TAB_NAME = "Scan Launcher"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.current_scan_id = None
        self.scan_manager = dependencies.get('scan_manager') if dependencies else None
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
        self.event_bus.scan_stopped.connect(self._on_scan_stopped)
        self.event_bus.targets_updated.connect(self._on_targets_updated)
    
    def _create_ui(self) -> QWidget:
        """Создает UI компонент запуска сканирований"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Основные вкладки
        tab_widget = QTabWidget()
        
        # Вкладка быстрого запуска
        tab_widget.addTab(self._create_quick_scan_tab(), "Quick Scan")
        
        # Вкладка расширенных настроек
        tab_widget.addTab(self._create_advanced_tab(), "Advanced")
        
        # Вкладка командной строки
        tab_widget.addTab(self._create_command_line_tab(), "Command Line")
        
        layout.addWidget(tab_widget)
        
        # Панель управления
        layout.addWidget(self._create_control_panel())
        
        # Командная строка
        layout.addWidget(self._create_command_preview())
        
        return widget
    
    def _create_quick_scan_tab(self) -> QWidget:
        """Создает вкладку быстрого запуска"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        # Выбор типа сканирования
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Quick", "Stealth", "Comprehensive", "Custom"])
        self.scan_type_combo.currentTextChanged.connect(self._on_scan_type_changed)
        layout.addRow("Scan Type:", self.scan_type_combo)
        
        # Поле целей
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("Enter targets (one per line or comma separated)\nExamples: 192.168.1.1, 10.0.0.0/24, scanme.nmap.org")
        self.targets_input.setMaximumHeight(80)
        layout.addRow("Targets:", self.targets_input)
        
        # Диапазон портов
        self.ports_input = QLineEdit("1-1000")
        self.ports_input.setPlaceholderText("1-1000, 80,443, 21-25")
        layout.addRow("Ports:", self.ports_input)
        
        return widget
    
    def _create_advanced_tab(self) -> QWidget:
        """Создает вкладку расширенных настроек"""
        scroll = QScrollArea()
        widget = QWidget()
        layout = QFormLayout(widget)
        
        # Настройки производительности
        layout.addRow(QLabel("<b>Performance Settings</b>"))
        
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 64)
        self.threads_spinbox.setValue(4)
        layout.addRow("Threads:", self.threads_spinbox)
        
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", 
                                   "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        self.timing_combo.setCurrentIndex(3)
        layout.addRow("Timing Template:", self.timing_combo)
        
        # Дополнительные опции
        layout.addRow(QLabel("<b>Scan Options</b>"))
        
        self.service_version_check = QCheckBox("Service version detection (-sV)")
        self.os_detection_check = QCheckBox("OS detection (-O)")
        self.script_scan_check = QCheckBox("Script scan (-sC)")
        self.aggressive_check = QCheckBox("Aggressive scan (-A)")
        
        layout.addRow(self.service_version_check)
        layout.addRow(self.os_detection_check)
        layout.addRow(self.script_scan_check)
        layout.addRow(self.aggressive_check)
        
        # Опции вывода
        layout.addRow(QLabel("<b>Output Options</b>"))
        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems(["XML", "Normal", "Grepable"])
        layout.addRow("Output Format:", self.output_format_combo)
        
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        return scroll
    
    def _create_command_line_tab(self) -> QWidget:
        """Создает вкладку командной строки"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        layout.addWidget(QLabel("Custom Nmap Command:"))
        
        self.custom_command_input = QTextEdit()
        self.custom_command_input.setPlaceholderText("Enter custom nmap command...")
        layout.addWidget(self.custom_command_input)
        
        # Кнопка применения настроек из команды
        self.parse_command_btn = QPushButton("Parse Command")
        self.parse_command_btn.clicked.connect(self._parse_custom_command)
        layout.addWidget(self.parse_command_btn)
        
        return widget
    
    def _create_control_panel(self) -> QGroupBox:
        """Создает панель управления сканированием"""
        group = QGroupBox("Scan Control")
        layout = QHBoxLayout(group)
        
        # Кнопки управления
        self.start_btn = QPushButton("Start Scan")
        self.pause_btn = QPushButton("Pause")
        self.stop_btn = QPushButton("Stop")
        
        self.start_btn.clicked.connect(self._start_scan)
        self.pause_btn.clicked.connect(self._pause_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        
        # Прогресс бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Статус
        self.status_label = QLabel("Ready")
        
        layout.addWidget(self.start_btn)
        layout.addWidget(self.pause_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        
        self._update_control_buttons(False)
        
        return group
    
    def _create_command_preview(self) -> QGroupBox:
        """Создает предпросмотр командной строки"""
        group = QGroupBox("Command Preview")
        layout = QVBoxLayout(group)
        
        self.command_preview = QTextEdit()
        self.command_preview.setMaximumHeight(60)
        self.command_preview.setReadOnly(True)
        layout.addWidget(self.command_preview)
        
        # Обновляем предпросмотр при изменении настроек
        self.scan_type_combo.currentTextChanged.connect(self._update_command_preview)
        self.targets_input.textChanged.connect(self._update_command_preview)
        self.ports_input.textChanged.connect(self._update_command_preview)
        self.service_version_check.toggled.connect(self._update_command_preview)
        self.os_detection_check.toggled.connect(self._update_command_preview)
        self.script_scan_check.toggled.connect(self._update_command_preview)
        
        self._update_command_preview()
        
        return group
    
    def _update_command_preview(self):
        """Обновляет предпросмотр команды nmap"""
        try:
            config = self._get_scan_config()
            command = config.to_nmap_command()
            self.command_preview.setPlainText(command)
            self.event_bus.command_updated.emit(command)
        except Exception as e:
            self.command_preview.setPlainText(f"Error generating command: {e}")
    
    def _get_scan_config(self) -> ScanConfig:
        """Создает конфигурацию сканирования из UI"""
        import uuid
        
        # Получаем цели
        targets_text = self.targets_input.toPlainText().strip()
        if not targets_text:
            targets = []
        else:
            # Разделяем по запятым или переносам строк
            targets = [target.strip() for target in targets_text.replace('\n', ',').split(',') if target.strip()]
        
        # Определяем тип сканирования
        scan_type_map = {
            "Quick": ScanType.QUICK,
            "Stealth": ScanType.STEALTH, 
            "Comprehensive": ScanType.COMPREHENSIVE,
            "Custom": ScanType.CUSTOM
        }
        
        config = ScanConfig(
            scan_id=str(uuid.uuid4()),
            targets=targets,
            scan_type=scan_type_map[self.scan_type_combo.currentText()],
            custom_command=self.custom_command_input.toPlainText(),
            threads=self.threads_spinbox.value(),
            timing_template=self.timing_combo.currentText()[1:2],  # "T4" -> "4"
            port_range=self.ports_input.text(),
            service_version=self.service_version_check.isChecked(),
            os_detection=self.os_detection_check.isChecked(),
            script_scan=self.script_scan_check.isChecked()
        )
        
        return config
    
    def _start_scan(self):
        """Запускает сканирование"""
        try:
            config = self._get_scan_config()
            
            if not config.targets:
                self.status_label.setText("Error: No targets specified")
                return
            
            if self.scan_manager:
                self.current_scan_id = self.scan_manager.submit_scan(config)
                self._update_control_buttons(True)
                self.progress_bar.setVisible(True)
                self.status_label.setText("Scan started...")
            else:
                self.status_label.setText("Error: Scan manager not available")
                
        except Exception as e:
            self.status_label.setText(f"Error starting scan: {e}")
    
    def _pause_scan(self):
        """Приостанавливает сканирование"""
        if self.current_scan_id:
            self.event_bus.scan_paused.emit({'scan_id': self.current_scan_id})
            self.status_label.setText("Scan paused")
    
    def _stop_scan(self):
        """Останавливает сканирование"""
        if self.current_scan_id:
            self.event_bus.scan_stopped.emit({'scan_id': self.current_scan_id})
            self._update_control_buttons(False)
            self.progress_bar.setVisible(False)
            self.status_label.setText("Scan stopped")
    
    def _parse_custom_command(self):
        """Парсит пользовательскую команду и применяет настройки"""
        # TODO: Реализовать парсинг nmap команд
        command = self.custom_command_input.toPlainText()
        self.status_label.setText("Custom command parsing not yet implemented")
    
    def _update_control_buttons(self, scanning: bool):
        """Обновляет состояние кнопок управления"""
        self.start_btn.setEnabled(not scanning)
        self.pause_btn.setEnabled(scanning)
        self.stop_btn.setEnabled(scanning)
    
    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает обновление прогресса сканирования"""
        if data.get('scan_id') == self.current_scan_id:
            progress = data.get('progress', 0)
            status = data.get('status', '')
            
            self.progress_bar.setValue(progress)
            self.status_label.setText(f"Scanning... {progress}% - {status}")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        if data.get('scan_id') == self.current_scan_id:
            self._update_control_buttons(False)
            self.progress_bar.setVisible(False)
            self.status_label.setText("Scan completed")
    
    @pyqtSlot(dict)
    def _on_scan_stopped(self, data):
        """Обрабатывает остановку сканирования"""
        if data.get('scan_id') == self.current_scan_id:
            self._update_control_buttons(False)
            self.progress_bar.setVisible(False)
            self.status_label.setText("Scan stopped")
    
    @pyqtSlot(list)
    def _on_targets_updated(self, targets):
        """Обновляет цели из других модулей"""
        if targets:
            self.targets_input.setPlainText('\n'.join(targets))
    
    def _on_scan_type_changed(self, scan_type):
        """Обновляет UI при изменении типа сканирования"""
        if scan_type == "Quick":
            self.ports_input.setText("1-1000")
            self.service_version_check.setChecked(False)
            self.os_detection_check.setChecked(False)
        elif scan_type == "Stealth":
            self.ports_input.setText("1-1000")
            self.service_version_check.setChecked(False)
            self.os_detection_check.setChecked(False)
        elif scan_type == "Comprehensive":
            self.ports_input.setText("1-1000")
            self.service_version_check.setChecked(True)
            self.os_detection_check.setChecked(True)
            self.script_scan_check.setChecked(True)
        
        self._update_command_preview()
