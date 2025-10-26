from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QTextEdit, QLineEdit, QPushButton, QComboBox,
                             QLabel, QCheckBox, QScrollArea, QSplitter,
                             QMessageBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QToolButton, QMenu)
from PyQt6.QtCore import Qt, pyqtSlot, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QAction
import re
import shlex
from typing import Dict, List, Optional

from shared.models.scan_config import ScanConfig, ScanType

class CommandLineWidget(QWidget):
    """Виджет командной строки для продвинутых пользователей"""
    
    command_updated = pyqtSignal(str)  # Сигнал при изменении команды
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_command = ""
        self.command_history = []
        self.history_index = -1
        self.nmap_options = self._load_nmap_options()
        self._init_ui()
    
    def _init_ui(self):
        """Инициализирует UI"""
        layout = QVBoxLayout(self)
        
        # Сплиттер для командной строки и справки
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Верхняя часть - командная строка
        splitter.addWidget(self._create_command_section())
        
        # Нижняя часть - справка и примеры
        splitter.addWidget(self._create_help_section())
        
        splitter.setSizes([300, 200])
        layout.addWidget(splitter)
    
    def _create_command_section(self) -> QGroupBox:
        """Создает секцию командной строки"""
        group = QGroupBox("Nmap Command Line")
        layout = QVBoxLayout(group)
        
        # История команд
        self.history_combo = QComboBox()
        self.history_combo.setEditable(False)
        self.history_combo.currentTextChanged.connect(self._on_history_selected)
        layout.addWidget(QLabel("Command History:"))
        layout.addWidget(self.history_combo)
        
        # Поле ввода команды
        self.command_input = QTextEdit()
        self.command_input.setMaximumHeight(80)
        self.command_input.setPlaceholderText(
            "Enter nmap command or use the options below to build one...\n"
            "Examples:\n"
            "nmap -sS -sV -O 192.168.1.0/24\n"
            "nmap -p 80,443,22 --script http-title scanme.nmap.org\n"
            "nmap -A -T4 10.0.0.1-100"
        )
        self.command_input.textChanged.connect(self._on_command_changed)
        layout.addWidget(QLabel("Nmap Command:"))
        layout.addWidget(self.command_input)
        
        # Кнопки управления
        button_layout = QHBoxLayout()
        
        self.parse_btn = QPushButton("Parse Command")
        self.parse_btn.clicked.connect(self._parse_command)
        button_layout.addWidget(self.parse_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self._clear_command)
        button_layout.addWidget(self.clear_btn)
        
        self.save_btn = QPushButton("Save to History")
        self.save_btn.clicked.connect(self._save_to_history)
        button_layout.addWidget(self.save_btn)
        
        self.validate_btn = QPushButton("Validate")
        self.validate_btn.clicked.connect(self._validate_command)
        button_layout.addWidget(self.validate_btn)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
    
    def _create_help_section(self) -> QWidget:
        """Создает секцию справки"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Табы для разных типов справки
        tab_widget = QTabWidget()
        
        # Вкладка быстрых опций
        tab_widget.addTab(self._create_quick_options_tab(), "Quick Options")
        
        # Вкладка справки по опциям
        tab_widget.addTab(self._create_options_reference_tab(), "Options Reference")
        
        # Вкладка примеров
        tab_widget.addTab(self._create_examples_tab(), "Examples")
        
        layout.addWidget(tab_widget)
        
        return widget
    
    def _create_quick_options_tab(self) -> QWidget:
        """Создает вкладку быстрых опций"""
        scroll = QScrollArea()
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Группы опций
        layout.addWidget(self._create_scan_type_group())
        layout.addWidget(self._create_target_specification_group())
        layout.addWidget(self._create_host_discovery_group())
        layout.addWidget(self._create_scan_techniques_group())
        layout.addWidget(self._create_port_specification_group())
        layout.addWidget(self._create_service_version_group())
        layout.addWidget(self._create_os_detection_group())
        layout.addWidget(self._create_timing_options_group())
        
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        return scroll
    
    def _create_scan_type_group(self) -> QGroupBox:
        """Создает группу типов сканирования"""
        group = QGroupBox("Scan Types")
        layout = QHBoxLayout(group)
        
        scan_buttons = [
            ("-sS (SYN)", "TCP SYN scan"),
            ("-sT (Connect)", "TCP connect scan"),
            ("-sU (UDP)", "UDP scan"),
            ("-sN (Null)", "Null scan"),
            ("-sF (FIN)", "FIN scan"),
            ("-sX (Xmas)", "Xmas scan")
        ]
        
        for option, description in scan_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            btn.setStyleSheet("QToolButton { padding: 5px; }")
            layout.addWidget(btn)
        
        return group
    
    def _create_target_specification_group(self) -> QGroupBox:
        """Создает группу спецификации целей"""
        group = QGroupBox("Target Specification")
        layout = QHBoxLayout(group)
        
        target_buttons = [
            ("-iL <file>", "Input from list"),
            ("-iR <num>", "Random targets"),
            ("--exclude <hosts>", "Exclude hosts"),
            ("--excludefile <file>", "Exclude from file")
        ]
        
        for option, description in target_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_host_discovery_group(self) -> QGroupBox:
        """Создает группу обнаружения хостов"""
        group = QGroupBox("Host Discovery")
        layout = QHBoxLayout(group)
        
        discovery_buttons = [
            ("-sL (List)", "List scan"),
            ("-sn (No port)", "No port scan"),
            ("-Pn (No ping)", "No host discovery"),
            ("-PS (SYN)", "TCP SYN discovery"),
            ("-PA (ACK)", "TCP ACK discovery"),
            ("-PU (UDP)", "UDP discovery")
        ]
        
        for option, description in discovery_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_scan_techniques_group(self) -> QGroupBox:
        """Создает группу техник сканирования"""
        group = QGroupBox("Scan Techniques")
        layout = QHBoxLayout(group)
        
        technique_buttons = [
            ("-sS (Stealth)", "SYN stealth"),
            ("-sT (Connect)", "TCP connect"),
            ("-sU (UDP)", "UDP ports"),
            ("-sN (Null)", "Null flags"),
            ("-sF (FIN)", "FIN flag"),
            ("-sX (Xmas)", "FIN, PSH, URG")
        ]
        
        for option, description in technique_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_port_specification_group(self) -> QGroupBox:
        """Создает группу спецификации портов"""
        group = QGroupBox("Port Specification")
        layout = QHBoxLayout(group)
        
        port_buttons = [
            ("-p 80", "Single port"),
            ("-p 80,443", "Multiple ports"),
            ("-p 1-1000", "Port range"),
            ("-p-", "All ports"),
            ("-F (Fast)", "Fast mode"),
            ("--top-ports 100", "Top ports")
        ]
        
        for option, description in port_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_service_version_group(self) -> QGroupBox:
        """Создает группу определения версий сервисов"""
        group = QGroupBox("Service/Version Detection")
        layout = QHBoxLayout(group)
        
        service_buttons = [
            ("-sV", "Version detection"),
            ("-sV --version-all", "All version probes"),
            ("-A", "Aggressive scan"),
            ("--script banner", "Banner grabbing")
        ]
        
        for option, description in service_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_os_detection_group(self) -> QGroupBox:
        """Создает группу определения ОС"""
        group = QGroupBox("OS Detection")
        layout = QHBoxLayout(group)
        
        os_buttons = [
            ("-O", "OS detection"),
            ("-O --osscan-limit", "Limit to promising targets"),
            ("-O --osscan-guess", "Guess OS aggressively")
        ]
        
        for option, description in os_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_timing_options_group(self) -> QGroupBox:
        """Создает группу опций тайминга"""
        group = QGroupBox("Timing Options")
        layout = QHBoxLayout(group)
        
        timing_buttons = [
            ("-T0 (Paranoid)", "Very slow"),
            ("-T1 (Sneaky)", "Quite slow"),
            ("-T2 (Polite)", "Slow"),
            ("-T3 (Normal)", "Normal"),
            ("-T4 (Aggressive)", "Fast"),
            ("-T5 (Insane)", "Very fast")
        ]
        
        for option, description in timing_buttons:
            btn = QToolButton()
            btn.setText(option)
            btn.setToolTip(description)
            btn.clicked.connect(lambda checked, opt=option: self._add_option(opt))
            layout.addWidget(btn)
        
        return group
    
    def _create_options_reference_tab(self) -> QWidget:
        """Создает вкладку справки по опциям"""
        scroll = QScrollArea()
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Таблица опций nmap
        self.options_table = QTableWidget()
        self.options_table.setColumnCount(3)
        self.options_table.setHorizontalHeaderLabels(["Option", "Description", "Example"])
        
        # Заполняем таблицу опциями
        self._populate_options_table()
        
        # Настройка таблицы
        header = self.options_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        self.options_table.itemDoubleClicked.connect(self._on_option_double_clicked)
        
        layout.addWidget(self.options_table)
        
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        return scroll
    
    def _create_examples_tab(self) -> QWidget:
        """Создает вкладку примеров"""
        scroll = QScrollArea()
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        examples = [
            {
                "name": "Quick Scan",
                "command": "nmap -F 192.168.1.0/24",
                "description": "Fast scan of common ports on a network"
            },
            {
                "name": "Stealth Scan", 
                "command": "nmap -sS -sV -O 10.0.0.1-50",
                "description": "Stealth SYN scan with version and OS detection"
            },
            {
                "name": "Comprehensive Scan",
                "command": "nmap -A -T4 scanme.nmap.org",
                "description": "Aggressive scan with all features enabled"
            },
            {
                "name": "UDP Scan",
                "command": "nmap -sU -p 53,67,68,69,123 192.168.1.1",
                "description": "UDP scan of common UDP ports"
            },
            {
                "name": "Vulnerability Scan",
                "command": "nmap -sV --script vuln 10.0.0.0/24", 
                "description": "Version detection with vulnerability scripts"
            },
            {
                "name": "Service Detection",
                "command": "nmap -sC -sV -p- 192.168.1.100",
                "description": "Full port scan with default scripts and version detection"
            }
        ]
        
        for example in examples:
            example_group = QGroupBox(example["name"])
            example_layout = QVBoxLayout(example_group)
            
            # Команда
            cmd_label = QLabel(f"<b>Command:</b> {example['command']}")
            cmd_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            example_layout.addWidget(cmd_label)
            
            # Описание
            desc_label = QLabel(f"<b>Description:</b> {example['description']}")
            example_layout.addWidget(desc_label)
            
            # Кнопка использования
            use_btn = QPushButton("Use This Command")
            use_btn.clicked.connect(lambda checked, cmd=example['command']: self._use_example_command(cmd))
            example_layout.addWidget(use_btn)
            
            layout.addWidget(example_group)
        
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)
        return scroll
    
    def _load_nmap_options(self) -> Dict:
        """Загружает опции nmap для справки"""
        return {
            "Scan Techniques": {
                "-sS": "TCP SYN scan",
                "-sT": "TCP connect scan", 
                "-sU": "UDP scan",
                "-sN": "TCP Null scan",
                "-sF": "TCP FIN scan",
                "-sX": "TCP Xmas scan"
            },
            "Host Discovery": {
                "-sL": "List Scan - simply list targets to scan",
                "-sn": "Ping Scan - disable port scan",
                "-Pn": "Treat all hosts as online -- skip host discovery",
                "-PS": "TCP SYN discovery on port(s)",
                "-PA": "TCP ACK discovery on port(s)",
                "-PU": "UDP discovery on port(s)"
            },
            "Port Specification": {
                "-p": "Only scan specified ports",
                "--top-ports": "Scan <number> most common ports", 
                "-p-": "Scan all ports",
                "-F": "Fast mode - Scan fewer ports than the default scan"
            },
            "Service/Version Detection": {
                "-sV": "Probe open ports to determine service/version info",
                "-A": "Enable OS detection, version detection, script scanning, and traceroute"
            },
            "OS Detection": {
                "-O": "Enable OS detection",
                "--osscan-limit": "Limit OS detection to promising targets",
                "--osscan-guess": "Guess OS more aggressively"
            },
            "Timing and Performance": {
                "-T0": "Paranoid (0) timing",
                "-T1": "Sneaky (1) timing", 
                "-T2": "Polite (2) timing",
                "-T3": "Normal (3) timing",
                "-T4": "Aggressive (4) timing",
                "-T5": "Insane (5) timing"
            }
        }
    
    def _populate_options_table(self):
        """Заполняет таблицу опциями nmap"""
        row = 0
        for category, options in self.nmap_options.items():
            # Добавляем заголовок категории
            self.options_table.insertRow(row)
            category_item = QTableWidgetItem(category)
            category_item.setBackground(Qt.GlobalColor.lightGray)
            self.options_table.setItem(row, 0, category_item)
            row += 1
            
            # Добавляем опции категории
            for option, description in options.items():
                self.options_table.insertRow(row)
                self.options_table.setItem(row, 0, QTableWidgetItem(option))
                self.options_table.setItem(row, 1, QTableWidgetItem(description))
                
                # Пример использования
                example = self._get_option_example(option)
                self.options_table.setItem(row, 2, QTableWidgetItem(example))
                row += 1
    
    def _get_option_example(self, option: str) -> str:
        """Возвращает пример использования опции"""
        examples = {
            "-sS": "nmap -sS 192.168.1.1",
            "-sV": "nmap -sV 192.168.1.1", 
            "-O": "nmap -O 192.168.1.1",
            "-p": "nmap -p 80,443 192.168.1.1",
            "-A": "nmap -A 192.168.1.1",
            "-T4": "nmap -T4 192.168.1.0/24"
        }
        return examples.get(option, "nmap [OPTION] target")
    
    def _add_option(self, option: str):
        """Добавляет опцию в командную строку"""
        current_text = self.command_input.toPlainText().strip()
        
        if current_text and not current_text.startswith("nmap"):
            current_text = f"nmap {current_text}"
        elif not current_text:
            current_text = "nmap"
        
        # Добавляем опцию
        if option not in current_text:
            current_text += f" {option}"
        
        self.command_input.setPlainText(current_text)
        self._on_command_changed()
    
    def _on_command_changed(self):
        """Обрабатывает изменение команды"""
        self.current_command = self.command_input.toPlainText().strip()
        self.command_updated.emit(self.current_command)
    
    def _parse_command(self):
        """Парсит команду и извлекает параметры"""
        command = self.current_command.strip()
        if not command:
            QMessageBox.information(self, "Info", "No command to parse")
            return
        
        try:
            # Убираем 'nmap' из начала если есть
            if command.startswith("nmap"):
                command = command[4:].strip()
            
            # Парсим аргументы
            args = shlex.split(command)
            
            # Анализируем опции
            options = {}
            targets = []
            i = 0
            
            while i < len(args):
                arg = args[i]
                
                if arg.startswith('-'):
                    # Это опция
                    if '=' in arg:
                        key, value = arg.split('=', 1)
                        options[key] = value
                    elif i + 1 < len(args) and not args[i + 1].startswith('-'):
                        # Опция со значением
                        options[arg] = args[i + 1]
                        i += 1
                    else:
                        # Флаг (опция без значения)
                        options[arg] = True
                else:
                    # Это цель
                    targets.append(arg)
                
                i += 1
            
            # Показываем результат парсинга
            result = f"Parsed Command: {command}\n\n"
            result += f"Targets: {', '.join(targets) if targets else 'None'}\n"
            result += "Options:\n"
            for key, value in options.items():
                result += f"  {key}: {value}\n"
            
            QMessageBox.information(self, "Command Parsed", result)
            
        except Exception as e:
            QMessageBox.critical(self, "Parse Error", f"Failed to parse command: {e}")
    
    def _clear_command(self):
        """Очищает командную строку"""
        self.command_input.clear()
        self._on_command_changed()
    
    def _save_to_history(self):
        """Сохраняет команду в историю"""
        command = self.current_command.strip()
        if not command:
            QMessageBox.warning(self, "Warning", "No command to save")
            return
        
        if command not in self.command_history:
            self.command_history.append(command)
            self.history_combo.addItem(command)
            QMessageBox.information(self, "Saved", "Command saved to history")
        else:
            QMessageBox.information(self, "Info", "Command already in history")
    
    def _validate_command(self):
        """Проверяет команду на валидность"""
        command = self.current_command.strip()
        if not command:
            QMessageBox.warning(self, "Warning", "No command to validate")
            return
        
        # Базовая валидация
        warnings = []
        
        if not command.startswith("nmap"):
            warnings.append("Command should start with 'nmap'")
        
        # Проверяем наличие целей
        if not re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?:-\d{1,3})?\b', command):
            if "scanme.nmap.org" not in command and "localhost" not in command:
                warnings.append("No valid target specified")
        
        # Проверяем конфликтующие опции
        if "-sS" in command and "-sT" in command:
            warnings.append("Conflicting scan types: -sS and -sT")
        
        if warnings:
            QMessageBox.warning(self, "Validation Warnings", "\n".join(warnings))
        else:
            QMessageBox.information(self, "Validation", "Command appears valid")
    
    def _on_history_selected(self, command):
        """Обрабатывает выбор команды из истории"""
        if command:
            self.command_input.setPlainText(command)
            self._on_command_changed()
    
    def _on_option_double_clicked(self, item):
        """Обрабатывает двойной клик по опции в таблице"""
        if item.column() == 0:  # Колонка с опциями
            option = item.text()
            if option and not option.startswith("Scan") and not option.startswith("Host"):
                self._add_option(option)
    
    def _use_example_command(self, command):
        """Использует пример команды"""
        self.command_input.setPlainText(command)
        self._on_command_changed()
    
    def get_command(self) -> str:
        """Возвращает текущую команду"""
        return self.current_command
    
    def set_command(self, command: str):
        """Устанавливает команду"""
        self.command_input.setPlainText(command)
        self._on_command_changed()
    
    def get_scan_config_from_command(self) -> Optional[ScanConfig]:
        """Создает ScanConfig из команды (упрощенная версия)"""
        # Это упрощенная реализация - в реальном приложении нужен более сложный парсер
        command = self.current_command.strip()
        if not command or not command.startswith("nmap"):
            return None
        
        try:
            import uuid
            config = ScanConfig(
                scan_id=str(uuid.uuid4()),
                targets=[],
                scan_type=ScanType.CUSTOM,
                custom_command=command
            )
            
            # Базовая экстракция целей
            targets = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?:-\d{1,3})?\b', command)
            if targets:
                config.targets = targets
            
            # Определяем тип сканирования
            if "-sS" in command:
                config.scan_type = ScanType.STEALTH
            elif "-F" in command:
                config.scan_type = ScanType.QUICK
            elif "-A" in command or ("-sV" in command and "-O" in command):
                config.scan_type = ScanType.COMPREHENSIVE
            
            # Извлекаем порты
            port_match = re.search(r'-p\s+([\d,\-]+)', command)
            if port_match:
                config.port_range = port_match.group(1)
            
            # Дополнительные опции
            config.service_version = "-sV" in command
            config.os_detection = "-O" in command
            config.script_scan = "-sC" in command or "--script" in command
            
            return config
            
        except Exception:
            return None
