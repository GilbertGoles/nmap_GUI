from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                             QLabel, QComboBox, QLineEdit, QSpinBox, 
                             QCheckBox, QPushButton, QTextEdit, QProgressBar,
                             QFormLayout, QTabWidget)
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
        
        # Создаем вкладки для разных типов сканирования
        self.tab_widget = QTabWidget()
        
        # Вкладка быстрого сканирования
        quick_tab = self._create_quick_tab()
        self.tab_widget.addTab(quick_tab, "Quick Scan")
        
        # Вкладка расширенного сканирования
        advanced_tab = self._create_advanced_tab()
        self.tab_widget.addTab(advanced_tab, "Advanced")
        
        layout.addWidget(self.tab_widget)
        
        # Статус сканирования
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-weight: bold; color: green;")
        layout.addWidget(self.status_label)
        
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
        
        # Обновляем предпросмотр команды при изменении вкладки
        self.tab_widget.currentChanged.connect(self._update_command_preview)
        self._update_command_preview()

    def _create_quick_tab(self):
        """Создает вкладку быстрого сканирования"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        # Цели сканирования с примерами
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText(
            "Examples:\n"
            "• scanme.nmap.org (single host)\n"
            "• 192.168.1.1 (single IP)\n" 
            "• 192.168.1.0/24 (entire network)\n"
            "• 192.168.1.1-100 (IP range)\n"
            "• 192.168.1.1,192.168.1.5,192.168.1.10 (multiple IPs)"
        )
        self.targets_input.textChanged.connect(self._update_command_preview)
        layout.addRow("Targets:", self.targets_input)
        
        # Быстрый выбор сетей
        network_layout = QHBoxLayout()
        self.common_networks_combo = QComboBox()
        self.common_networks_combo.addItems([
            "Common Networks...",
            "192.168.1.0/24",
            "192.168.0.0/24", 
            "10.0.0.0/24",
            "172.16.0.0/24"
        ])
        self.add_network_btn = QPushButton("Add Network")
        self.add_network_btn.clicked.connect(self._add_common_network)
        
        network_layout.addWidget(self.common_networks_combo)
        network_layout.addWidget(self.add_network_btn)
        layout.addRow("Quick Networks:", network_layout)
        
        # Тип сканирования
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Quick Scan", "Stealth Scan", "Comprehensive Scan", "Network Discovery"])
        self.scan_type_combo.currentTextChanged.connect(self._update_command_preview)
        layout.addRow("Scan Type:", self.scan_type_combo)
        
        # Диапазон портов
        self.ports_input = QLineEdit("1-1000")
        self.ports_input.textChanged.connect(self._update_command_preview)
        layout.addRow("Ports:", self.ports_input)
        
        return widget

    def _create_advanced_tab(self):
        """Создает вкладку расширенного сканирования"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        # Цели сканирования
        self.advanced_targets_input = QLineEdit()
        self.advanced_targets_input.setPlaceholderText("192.168.1.1, 10.0.0.0/24, scanme.nmap.org")
        self.advanced_targets_input.textChanged.connect(self._update_command_preview)
        layout.addRow("Targets:", self.advanced_targets_input)
        
        # Тип сканирования
        self.advanced_scan_type_combo = QComboBox()
        self.advanced_scan_type_combo.addItems(["Quick Scan", "Stealth Scan", "Comprehensive Scan", "Custom"])
        self.advanced_scan_type_combo.currentTextChanged.connect(self._update_command_preview)
        layout.addRow("Scan Type:", self.advanced_scan_type_combo)
        
        # Диапазон портов
        self.advanced_ports_input = QLineEdit("1-1000")
        self.advanced_ports_input.textChanged.connect(self._update_command_preview)
        layout.addRow("Ports:", self.advanced_ports_input)
        
        # Потоки
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 16)
        self.threads_spinbox.setValue(4)
        self.threads_spinbox.valueChanged.connect(self._update_command_preview)
        layout.addRow("Threads:", self.threads_spinbox)
        
        # Тайминг шаблон - ИСПРАВЛЕННАЯ ВЕРСИЯ
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        self.timing_combo.setCurrentIndex(3)  # T3 Normal по умолчанию
        self.timing_combo.currentTextChanged.connect(self._update_command_preview)
        layout.addRow("Timing:", self.timing_combo)
        
        # Опции
        self.service_version_check = QCheckBox("Service version detection")
        self.service_version_check.toggled.connect(self._update_command_preview)
        layout.addRow(self.service_version_check)
        
        self.os_detection_check = QCheckBox("OS detection")
        self.os_detection_check.toggled.connect(self._update_command_preview)
        layout.addRow(self.os_detection_check)
        
        self.script_scan_check = QCheckBox("Script scanning (NSE)")
        self.script_scan_check.toggled.connect(self._update_command_preview)
        layout.addRow(self.script_scan_check)
        
        return widget

    def _add_common_network(self):
        """Добавляет common network в цели"""
        network = self.common_networks_combo.currentText()
        if network != "Common Networks...":
            current_targets = self.targets_input.text().strip()
            if current_targets:
                new_targets = current_targets + "," + network
            else:
                new_targets = network
            self.targets_input.setText(new_targets)

    def _update_command_preview(self):
        """Обновляет предпросмотр команды nmap"""
        # Определяем активную вкладку и используем соответствующие элементы
        current_tab_index = self.tab_widget.currentIndex()
        
        if current_tab_index == 0:  # Quick Scan tab
            targets = self.targets_input.text().strip()
            scan_type = self.scan_type_combo.currentText()
            ports = self.ports_input.text().strip()
        else:  # Advanced tab
            targets = self.advanced_targets_input.text().strip()
            scan_type = self.advanced_scan_type_combo.currentText()
            ports = self.advanced_ports_input.text().strip()
        
        if not targets:
            self.command_preview.setPlainText("Enter targets to see command preview")
            return
        
        # Строим базовую команду
        cmd_parts = ["nmap"]
        
        # Добавляем тайминг шаблон (только в advanced tab)
        if current_tab_index == 1:
            timing_text = self.timing_combo.currentText()
            if "T0" in timing_text:
                cmd_parts.append("-T0")
            elif "T1" in timing_text:
                cmd_parts.append("-T1")
            elif "T2" in timing_text:
                cmd_parts.append("-T2")
            elif "T3" in timing_text:
                cmd_parts.append("-T3")
            elif "T4" in timing_text:
                cmd_parts.append("-T4")
            elif "T5" in timing_text:
                cmd_parts.append("-T5")
        
        # Добавляем тип сканирования - ИСПРАВЛЕННАЯ ВЕРСИЯ!
        if scan_type == "Quick Scan":
            cmd_parts.append("-F")
            # НЕ добавляем -p при использовании -F (они конфликтуют)
        elif scan_type == "Stealth Scan":
            cmd_parts.append("-sS")
            # Добавляем порты для stealth сканирования
            if ports and scan_type != "Network Discovery":
                cmd_parts.append(f"-p {ports}")
        elif scan_type == "Comprehensive Scan":
            cmd_parts.extend(["-sS", "-sV", "-O", "-A"])
            # Добавляем порты для comprehensive сканирования
            if ports and scan_type != "Network Discovery":
                cmd_parts.append(f"-p {ports}")
        elif scan_type == "Network Discovery":
            cmd_parts.extend(["-sn"])  # Только обнаружение хостов, без сканирования портов
            # НЕ добавляем порты для discovery сканирования
        elif scan_type == "Custom":
            if current_tab_index == 1:  # Only in advanced tab
                # Для custom сканирования добавляем порты если указаны
                if ports and scan_type != "Network Discovery":
                    cmd_parts.append(f"-p {ports}")
                if self.service_version_check.isChecked():
                    cmd_parts.append("-sV")
                if self.os_detection_check.isChecked():
                    cmd_parts.append("-O")
                if self.script_scan_check.isChecked():
                    cmd_parts.append("-sC")
        
        # Дополнительные опции (только для не-quick сканирований в advanced tab)
        if current_tab_index == 1 and scan_type != "Quick Scan" and scan_type != "Custom":
            if self.service_version_check.isChecked():
                cmd_parts.append("-sV")
            if self.os_detection_check.isChecked():
                cmd_parts.append("-O")
            if self.script_scan_check.isChecked():
                cmd_parts.append("-sC")
        
        # Добавляем потоки (только в advanced tab)
        if current_tab_index == 1:
            cmd_parts.append(f"--min-parallelism {self.threads_spinbox.value()}")
        
        # Добавляем цели
        cmd_parts.append(targets)
        
        # ВАЖНО: добавляем вывод в XML (обязательно для работы парсера)
        cmd_parts.append("-oX -")
        
        command = " ".join(cmd_parts)
        self.command_preview.setPlainText(command)

    def _start_scan(self):
        """Запускает сканирование"""
        # Определяем активную вкладку
        current_tab_index = self.tab_widget.currentIndex()
        
        if current_tab_index == 0:  # Quick Scan tab
            targets_text = self.targets_input.text().strip()
            scan_type_text = self.scan_type_combo.currentText()
            ports = self.ports_input.text().strip()
        else:  # Advanced tab
            targets_text = self.advanced_targets_input.text().strip()
            scan_type_text = self.advanced_scan_type_combo.currentText()
            ports = self.advanced_ports_input.text().strip()
        
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
            
            # Определяем тип сканирования для ScanConfig
            if scan_type_text == "Quick Scan":
                scan_type_enum = ScanType.QUICK
            elif scan_type_text == "Stealth Scan":
                scan_type_enum = ScanType.STEALTH
            elif scan_type_text == "Comprehensive Scan":
                scan_type_enum = ScanType.COMPREHENSIVE
            elif scan_type_text == "Network Discovery":
                scan_type_enum = ScanType.DISCOVERY
            else:
                scan_type_enum = ScanType.CUSTOM
            
            # Определяем тайминг шаблон - ИСПРАВЛЕННАЯ ВЕРСИЯ
            timing_template = "T3"  # по умолчанию
            if current_tab_index == 1:
                timing_text = self.timing_combo.currentText()
                if "T0" in timing_text:
                    timing_template = "T0"
                elif "T1" in timing_text:
                    timing_template = "T1"
                elif "T2" in timing_text:
                    timing_template = "T2"
                elif "T3" in timing_text:
                    timing_template = "T3"
                elif "T4" in timing_text:
                    timing_template = "T4"
                elif "T5" in timing_text:
                    timing_template = "T5"
            
            # Для quick scan и discovery scan игнорируем указанные порты
            port_range = ""
            if scan_type_text not in ["Quick Scan", "Network Discovery"]:
                port_range = ports
            
            # Определяем дополнительные опции (игнорируем для quick scan)
            service_version = False
            os_detection = False
            script_scan = False
            
            if current_tab_index == 1:  # Advanced tab
                if scan_type_text != "Quick Scan":
                    service_version = self.service_version_check.isChecked()
                    os_detection = self.os_detection_check.isChecked()
                    script_scan = self.script_scan_check.isChecked()
            
            # Создаем конфигурацию сканирования
            import uuid
            config = ScanConfig(
                scan_id=str(uuid.uuid4()),
                targets=targets,
                scan_type=scan_type_enum,
                port_range=port_range,  # ИСПРАВЛЕНО!
                threads=self.threads_spinbox.value() if current_tab_index == 1 else 4,
                timing_template=timing_template,
                service_version=service_version,
                os_detection=os_detection,
                script_scan=script_scan
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
