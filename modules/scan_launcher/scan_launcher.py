from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, 
                             QTextEdit, QHBoxLayout, QGroupBox, QComboBox,
                             QLineEdit, QCheckBox, QProgressBar, QGridLayout,
                             QMessageBox)
from PyQt6.QtCore import Qt, pyqtSlot
import logging

from core.event_bus import EventBus
from shared.models.scan_config import ScanConfig, ScanType

class ScanLauncherTab(QWidget):
    """Вкладка для запуска сканирований"""
    
    def __init__(self, event_bus: EventBus, core_modules):
        super().__init__()
        self.event_bus = event_bus
        self.scan_manager = core_modules['scan_manager']
        self.logger = logging.getLogger(__name__)
        self.current_scan_id = None
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Настраивает интерфейс"""
        main_layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("NMAP Scan Launcher")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        main_layout.addWidget(title)
        
        # Конфигурация сканирования
        config_group = QGroupBox("Scan Configuration")
        config_layout = QGridLayout(config_group)
        
        # Цели сканирования
        config_layout.addWidget(QLabel("Targets:"), 0, 0)
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("e.g., 192.168.1.0/24, scanme.nmap.org, 10.0.0.1-100")
        self.targets_input.setText("scanme.nmap.org")
        config_layout.addWidget(self.targets_input, 0, 1)
        
        # Тип сканирования
        config_layout.addWidget(QLabel("Scan Type:"), 1, 0)
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Quick", "Stealth", "Comprehensive", "Discovery", "Custom"])
        config_layout.addWidget(self.scan_type_combo, 1, 1)
        
        # Диапазон портов
        config_layout.addWidget(QLabel("Port Range:"), 2, 0)
        self.port_range_input = QLineEdit()
        self.port_range_input.setPlaceholderText("e.g., 1-1000, 80,443,22,21")
        self.port_range_input.setText("1-1000")
        config_layout.addWidget(self.port_range_input, 2, 1)
        
        # Timing template
        config_layout.addWidget(QLabel("Timing:"), 3, 0)
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        self.timing_combo.setCurrentIndex(3)  # T3 Normal
        config_layout.addWidget(self.timing_combo, 3, 1)
        
        # Дополнительные опции
        config_layout.addWidget(QLabel("Options:"), 4, 0)
        options_layout = QHBoxLayout()
        self.service_version_check = QCheckBox("Service Version")
        self.os_detection_check = QCheckBox("OS Detection")
        self.script_scan_check = QCheckBox("Script Scan")
        options_layout.addWidget(self.service_version_check)
        options_layout.addWidget(self.os_detection_check)
        options_layout.addWidget(self.script_scan_check)
        config_layout.addLayout(options_layout, 4, 1)
        
        # Пользовательская команда
        config_layout.addWidget(QLabel("Custom Command:"), 5, 0)
        self.custom_command_input = QLineEdit()
        self.custom_command_input.setPlaceholderText("Custom nmap flags (for custom scan type)")
        config_layout.addWidget(self.custom_command_input, 5, 1)
        
        main_layout.addWidget(config_group)
        
        # Кнопки управления
        buttons_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setStyleSheet("padding: 8px; font-size: 14px; background-color: #4CAF50; color: white;")
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setStyleSheet("padding: 8px; font-size: 14px; background-color: #f44336; color: white;")
        self.stop_btn.setEnabled(False)
        
        buttons_layout.addWidget(self.start_btn)
        buttons_layout.addWidget(self.stop_btn)
        buttons_layout.addStretch()
        
        main_layout.addLayout(buttons_layout)
        
        # Прогресс бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Область для вывода логов
        log_group = QGroupBox("Scan Output")
        log_layout = QVBoxLayout(log_group)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Scan logs will appear here...")
        log_layout.addWidget(self.log_output)
        
        main_layout.addWidget(log_group)
    
    def _connect_signals(self):
        """Подключает сигналы"""
        self.start_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        
        # Подписываемся на события сканирования
        self.event_bus.scan_progress.connect(self._on_scan_progress)
        self.event_bus.scan_completed.connect(self._on_scan_completed)
        self.event_bus.scan_started.connect(self._on_scan_started)
        
        # Обновляем видимость опций при изменении типа сканирования
        self.scan_type_combo.currentTextChanged.connect(self._update_ui_for_scan_type)
        
        # Инициализируем UI для текущего типа сканирования
        self._update_ui_for_scan_type(self.scan_type_combo.currentText())
    
    def _update_ui_for_scan_type(self, scan_type):
        """Обновляет UI в зависимости от типа сканирования"""
        
        # 1. Сброс состояния для всех, кроме 'Custom'
        is_custom = (scan_type == "Custom")
        is_quick_or_discovery = (scan_type in ["Quick", "Discovery"])
        
        checks = [self.service_version_check, self.os_detection_check, self.script_scan_check]

        # Устанавливаем доступность
        self.port_range_input.setEnabled(not is_quick_or_discovery)
        self.custom_command_input.setEnabled(is_custom)
        
        for check in checks:
            check.setEnabled(is_custom or (scan_type not in ["Quick", "Discovery", "Comprehensive"]))

        # 2. Устанавливаем checked-состояние в зависимости от типа
        if scan_type == "Comprehensive":
            # Для Comprehensive включаем Service Version, OS Detection и Script Scan
            for check in checks:
                check.setChecked(True)
                check.setEnabled(False) # Делаем неактивным, чтобы пользователь не убрал
        elif is_quick_or_discovery:
            # Для Quick и Discovery отключаем все продвинутые опции
            for check in checks:
                check.setChecked(False)
                check.setEnabled(False)
        else:
            # Для Custom и Stealth (по умолчанию) даем пользователю контроль
            pass
    
    def _start_scan(self):
        """Запускает сканирование"""
        try:
            # Получаем параметры из UI
            targets_text = self.targets_input.text().strip()
            if not targets_text:
                QMessageBox.warning(self, "Error", "Please enter scan targets")
                return
            
            targets = [target.strip() for target in targets_text.split(',')]
            
            # Создаем конфигурацию сканирования
            scan_type_map = {
                "Quick": ScanType.QUICK,
                "Stealth": ScanType.STEALTH,
                "Comprehensive": ScanType.COMPREHENSIVE,
                "Discovery": ScanType.DISCOVERY,
                "Custom": ScanType.CUSTOM
            }
            
            config = ScanConfig(
                # === ИСПРАВЛЕНИЕ: УДАЛЯЕМ присвоение временного ID ===
                # ScanManager сам сгенерирует уникальный UUID через ScanJob
                targets=targets,
                scan_type=scan_type_map[self.scan_type_combo.currentText()],
                timing_template=f"T{self.timing_combo.currentIndex()}",
                port_range=self.port_range_input.text().strip() or None,
                service_version=self.service_version_check.isChecked(),
                os_detection=self.os_detection_check.isChecked(),
                script_scan=self.script_scan_check.isChecked(),
                custom_command=self.custom_command_input.text().strip() or None
            )
            
            # Запускаем сканирование
            self.current_scan_id = self.scan_manager.submit_scan(config) # ScanManager сгенерирует ID
            self.log_output.append(f"🚀 Started scan: {self.current_scan_id}")
            self.log_output.append(f"📋 Targets: {', '.join(targets)}")
            self.log_output.append(f"🔧 Type: {self.scan_type_combo.currentText()}\n")
            
            # Обновляем UI
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
        except Exception as e:
            self.log_output.append(f"❌ Error starting scan: {e}\n")
            QMessageBox.critical(self, "Error", f"Failed to start scan: {e}")
    
    def _stop_scan(self):
        """Останавливает текущее сканирование"""
        if self.current_scan_id:
            self.scan_manager.stop_scan(self.current_scan_id)
            self.log_output.append(f"⏹️ Stopped scan: {self.current_scan_id}\n")
            self._reset_ui()
    
    def _reset_ui(self):
        """Сбрасывает UI после завершения сканирования"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.current_scan_id = None
    
    @pyqtSlot(dict)
    def _on_scan_started(self, data):
        """Обрабатывает начало сканирования"""
        scan_id = data.get('scan_id')
        if scan_id == self.current_scan_id:
            self.log_output.append(f"⚡ Scan {scan_id} initialized...\n")
    
    @pyqtSlot(dict)
    def _on_scan_progress(self, data):
        """Обрабатывает прогресс сканирования"""
        scan_id = data.get('scan_id')
        progress = data.get('progress', 0)
        status = data.get('status', '')
        
        if scan_id == self.current_scan_id:
            if progress >= 0:
                self.progress_bar.setValue(progress)
                if status and progress < 100:
                    self.log_output.append(f"📊 Progress: {progress}% - {status}")
            else:
                self.log_output.append(f"⚠️ Error: {status}")
    
    @pyqtSlot(dict)
    def _on_scan_completed(self, data):
        """Обрабатывает завершение сканирования"""
        scan_id = data.get('scan_id')
        results = data.get('results')
        
        if scan_id == self.current_scan_id:
            if results and results.status == "completed":
                self.log_output.append(f"✅ Scan {scan_id} completed successfully!")
                self.log_output.append(f"📊 Found {len(results.hosts)} host(s)")
                
                for host in results.hosts:
                    open_ports = [port for port in host.ports if port.state == 'open']
                    hostname = host.hostname if host.hostname else "N/A"
                    
                    self.log_output.append(f"  • Host: {host.ip} ({hostname}) - State: {host.state}")

                    # --- ВЫВОД ОС ---
                    # Используем правильные атрибуты из модели данных
                    if hasattr(host, 'os_family') and host.os_family and host.os_family != "unknown":
                        self.log_output.append(f"    OS: {host.os_family}")
                    elif hasattr(host, 'os') and host.os and host.os != "unknown":
                        self.log_output.append(f"    OS: {host.os}")
                        
                    # --- ВЫВОД ПОРТОВ И СЕРВИСОВ ---
                    if open_ports:
                        self.log_output.append(f"    {len(open_ports)} Open Port(s):")
                        for port in open_ports:
                            # Используем правильные атрибуты из модели PortInfo
                            service_info = f"{port.version}" if hasattr(port, 'version') and port.version else "N/A"
                            service_name = f"{port.service}" if hasattr(port, 'service') and port.service else "unknown"
                            
                            self.log_output.append(
                                f"      - {port.port}/{port.protocol} | Service: {service_name} | Version: {service_info}"
                            )
                    
                    # --- ВЫВОД СКРИПТОВ ---
                    if hasattr(host, 'scripts') and host.scripts:
                        self.log_output.append(f"    📝 Scripts found: {len(host.scripts)}")
                        for script_id, script_output in host.scripts.items():
                            short_output = script_output[:100] + "..." if len(script_output) > 100 else script_output
                            self.log_output.append(f"      - {script_id}: {short_output}")
                    
                    # Разделитель между хостами
                    self.log_output.append("")
                    
            else:
                # Этот блок срабатывает, если статус не "completed" (т.е. stopped, error и т.д.)
                self.log_output.append(f"❌ Scan {scan_id} failed or was terminated.")
                if results and results.status:
                    self.log_output.append(f"    Final Status: {results.status}")
                elif results is None:
                    # Если results == None, значит, сканирование было остановлено _on_scan_stopped
                    pass 
         
            self.log_output.append("")  # Пустая строка для разделения
            self._reset_ui()


def create_tab(event_bus: EventBus, core_modules) -> QWidget:
    """
    Функция для создания вкладки сканирования
    """
    try:
        return ScanLauncherTab(event_bus, core_modules)
    except Exception as e:
        logging.error(f"Error creating Scan Launcher tab: {e}")
        # Возвращаем заглушку в случае ошибки
        error_widget = QWidget()
        layout = QVBoxLayout(error_widget)
        error_label = QLabel(f"Error loading Scan Launcher: {str(e)}")
        error_label.setWordWrap(True)
        layout.addWidget(error_label)
        return error_widget
