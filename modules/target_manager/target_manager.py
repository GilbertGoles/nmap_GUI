from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QTextEdit, QLabel, QPushButton, QListWidget,
                             QListWidgetItem, QFileDialog, QMessageBox,
                             QSplitter, QLineEdit, QComboBox, QCheckBox,
                             QFormLayout, QProgressBar)
from PyQt6.QtCore import Qt, pyqtSlot
import os
import ipaddress
from modules.base_module import BaseTabModule
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return TargetManagerTab(event_bus, dependencies)

class TargetManagerTab(BaseTabModule):
    TAB_NAME = "Target Manager"
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.target_groups = {}
        self.current_group = "default"
        
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        # Этот модуль в основном публикует события, а не подписывается
        pass
    
    def _create_ui(self) -> QWidget:
        """Создает UI компонент управления целями"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Сплиттер для разделения областей
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Левая часть - управление группами и импорт
        splitter.addWidget(self._create_management_widget())
        
        # Правая часть - просмотр и редактирование целей
        splitter.addWidget(self._create_editor_widget())
        
        # Устанавливаем пропорции
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Инициализируем группу по умолчанию
        self._initialize_default_group()
        
        return widget
    
    def _create_management_widget(self) -> QGroupBox:
        """Создает виджет управления группами"""
        group = QGroupBox("Target Groups")
        layout = QVBoxLayout(group)
        
        # Управление группами
        group_management_layout = QHBoxLayout()
        self.group_combo = QComboBox()
        self.group_combo.currentTextChanged.connect(self._on_group_changed)
        
        self.new_group_btn = QPushButton("New")
        self.new_group_btn.clicked.connect(self._create_new_group)
        
        self.delete_group_btn = QPushButton("Delete")
        self.delete_group_btn.clicked.connect(self._delete_current_group)
        
        group_management_layout.addWidget(QLabel("Group:"))
        group_management_layout.addWidget(self.group_combo, 1)
        group_management_layout.addWidget(self.new_group_btn)
        group_management_layout.addWidget(self.delete_group_btn)
        
        layout.addLayout(group_management_layout)
        
        # Список целей в группе
        layout.addWidget(QLabel("Targets in Group:"))
        self.targets_list = QListWidget()
        self.targets_list.itemSelectionChanged.connect(self._on_target_selection_changed)
        layout.addWidget(self.targets_list, 1)
        
        # Статистика группы
        self.group_stats_label = QLabel("Total: 0 targets")
        layout.addWidget(self.group_stats_label)
        
        # Панель действий с целями
        actions_layout = QHBoxLayout()
        self.remove_target_btn = QPushButton("Remove Selected")
        self.remove_target_btn.clicked.connect(self._remove_selected_targets)
        self.clear_group_btn = QPushButton("Clear Group")
        self.clear_group_btn.clicked.connect(self._clear_current_group)
        
        actions_layout.addWidget(self.remove_target_btn)
        actions_layout.addWidget(self.clear_group_btn)
        
        layout.addLayout(actions_layout)
        
        return group
    
    def _create_editor_widget(self) -> QWidget:
        """Создает виджет редактирования целей"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Импорт целей
        layout.addWidget(self._create_import_widget())
        
        # Ручной ввод целей
        layout.addWidget(self._create_manual_input_widget())
        
        # Быстрые действия
        layout.addWidget(self._create_quick_actions_widget())
        
        return widget
    
    def _create_import_widget(self) -> QGroupBox:
        """Создает виджет импорта целей"""
        group = QGroupBox("Import Targets")
        layout = QVBoxLayout(group)
        
        # Импорт из файла
        file_import_layout = QHBoxLayout()
        self.import_file_btn = QPushButton("Import from File")
        self.import_file_btn.clicked.connect(self._import_from_file)
        
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("color: gray; font-style: italic;")
        
        file_import_layout.addWidget(self.import_file_btn)
        file_import_layout.addWidget(self.file_path_label, 1)
        
        layout.addLayout(file_import_layout)
        
        # Опции импорта
        options_layout = QFormLayout()
        self.remove_duplicates_check = QCheckBox("Remove duplicates")
        self.remove_duplicates_check.setChecked(True)
        self.validate_targets_check = QCheckBox("Validate targets")
        self.validate_targets_check.setChecked(True)
        
        options_layout.addRow(self.remove_duplicates_check)
        options_layout.addRow(self.validate_targets_check)
        
        layout.addLayout(options_layout)
        
        return group
    
    def _create_manual_input_widget(self) -> QGroupBox:
        """Создает виджет ручного ввода целей"""
        group = QGroupBox("Manual Target Input")
        layout = QVBoxLayout(group)
        
        layout.addWidget(QLabel("Enter targets (one per line or comma separated):"))
        
        self.targets_editor = QTextEdit()
        self.targets_editor.setPlaceholderText(
            "Examples:\n"
            "192.168.1.1\n"
            "10.0.0.0/24\n"
            "scanme.nmap.org\n"
            "192.168.1.1-100\n"
            "192.168.1.1,192.168.1.2,192.168.1.3"
        )
        self.targets_editor.setMaximumHeight(150)
        layout.addWidget(self.targets_editor)
        
        # Кнопки управления вводом
        editor_buttons_layout = QHBoxLayout()
        self.add_to_group_btn = QPushButton("Add to Current Group")
        self.add_to_group_btn.clicked.connect(self._add_manual_targets)
        
        self.validate_btn = QPushButton("Validate Targets")
        self.validate_btn.clicked.connect(self._validate_manual_targets)
        
        self.clear_editor_btn = QPushButton("Clear Editor")
        self.clear_editor_btn.clicked.connect(self.targets_editor.clear)
        
        editor_buttons_layout.addWidget(self.add_to_group_btn)
        editor_buttons_layout.addWidget(self.validate_btn)
        editor_buttons_layout.addWidget(self.clear_editor_btn)
        
        layout.addLayout(editor_buttons_layout)
        
        return group
    
    def _create_quick_actions_widget(self) -> QGroupBox:
        """Создает виджет быстрых действий"""
        group = QGroupBox("Quick Actions")
        layout = QVBoxLayout(group)
        
        # Кнопка отправки в сканирование
        self.send_to_scan_btn = QPushButton("Send to Scan Launcher")
        self.send_to_scan_btn.clicked.connect(self._send_to_scan_launcher)
        self.send_to_scan_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }")
        
        # Генерация диапазонов
        range_layout = QHBoxLayout()
        self.range_start_input = QLineEdit()
        self.range_start_input.setPlaceholderText("Start IP")
        self.range_end_input = QLineEdit()
        self.range_end_input.setPlaceholderText("End IP")
        self.generate_range_btn = QPushButton("Generate Range")
        self.generate_range_btn.clicked.connect(self._generate_ip_range)
        
        range_layout.addWidget(self.range_start_input)
        range_layout.addWidget(self.range_end_input)
        range_layout.addWidget(self.generate_range_btn)
        
        # Common networks
        common_networks_layout = QHBoxLayout()
        self.common_networks_combo = QComboBox()
        self.common_networks_combo.addItems([
            "Common Networks",
            "192.168.0.0/24",
            "192.168.1.0/24", 
            "10.0.0.0/24",
            "172.16.0.0/24"
        ])
        self.add_common_network_btn = QPushButton("Add Network")
        self.add_common_network_btn.clicked.connect(self._add_common_network)
        
        common_networks_layout.addWidget(self.common_networks_combo, 1)
        common_networks_layout.addWidget(self.add_common_network_btn)
        
        layout.addWidget(self.send_to_scan_btn)
        layout.addLayout(range_layout)
        layout.addLayout(common_networks_layout)
        
        return group
    
    def _initialize_default_group(self):
        """Инициализирует группу по умолчанию"""
        self.target_groups["default"] = []
        self.group_combo.addItem("default")
        self._update_group_stats()
    
    def _update_group_stats(self):
        """Обновляет статистику текущей группы"""
        if self.current_group in self.target_groups:
            count = len(self.target_groups[self.current_group])
            self.group_stats_label.setText(f"Total: {count} targets")
    
    def _update_targets_list(self):
        """Обновляет список целей в UI"""
        self.targets_list.clear()
        if self.current_group in self.target_groups:
            for target in self.target_groups[self.current_group]:
                item = QListWidgetItem(target)
                self.targets_list.addItem(item)
        
        self._update_group_stats()
    
    def _validate_target(self, target: str) -> bool:
        """Валидирует цель"""
        target = target.strip()
        if not target:
            return False
        
        try:
            # Пробуем как IP адрес
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                # Пробуем как сеть
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                # Пробуем как диапазон
                if '-' in target:
                    parts = target.split('-')
                    if len(parts) == 2:
                        try:
                            ipaddress.ip_address(parts[0].strip())
                            # Вторая часть может быть IP или числом
                            try:
                                ipaddress.ip_address(parts[1].strip())
                                return True
                            except ValueError:
                                # Это числовой диапазон
                                int(parts[1].strip())
                                return True
                        except (ValueError, AttributeError):
                            pass
                
                # Это может быть доменное имя
                if '.' in target and len(target) > 3:
                    return True
        
        return False
    
    def _parse_targets_text(self, text: str) -> list:
        """Парсит текст с целями в список"""
        targets = []
        
        # Разделяем по запятым и переносам строк
        raw_targets = text.replace('\n', ',').split(',')
        
        for target in raw_targets:
            target = target.strip()
            if target and self._validate_target(target):
                targets.append(target)
        
        return targets
    
    def _on_group_changed(self, group_name: str):
        """Обрабатывает смену группы"""
        if group_name and group_name in self.target_groups:
            self.current_group = group_name
            self._update_targets_list()
    
    def _create_new_group(self):
        """Создает новую группу"""
        group_name, ok = QInputDialog.getText(self.get_ui(), "New Group", "Enter group name:")
        if ok and group_name:
            if group_name not in self.target_groups:
                self.target_groups[group_name] = []
                self.group_combo.addItem(group_name)
                self.group_combo.setCurrentText(group_name)
            else:
                QMessageBox.warning(self.get_ui(), "Error", f"Group '{group_name}' already exists!")
    
    def _delete_current_group(self):
        """Удаляет текущую группу"""
        if self.current_group == "default":
            QMessageBox.warning(self.get_ui(), "Error", "Cannot delete default group!")
            return
        
        reply = QMessageBox.question(
            self.get_ui(), 
            "Confirm Delete", 
            f"Delete group '{self.current_group}' with {len(self.target_groups[self.current_group])} targets?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            del self.target_groups[self.current_group]
            self.group_combo.removeItem(self.group_combo.currentIndex())
            self.current_group = "default"
            self.group_combo.setCurrentText("default")
    
    def _remove_selected_targets(self):
        """Удаляет выбранные цели из группы"""
        selected_items = self.targets_list.selectedItems()
        if not selected_items:
            return
        
        for item in selected_items:
            target = item.text()
            if target in self.target_groups[self.current_group]:
                self.target_groups[self.current_group].remove(target)
        
        self._update_targets_list()
    
    def _clear_current_group(self):
        """Очищает текущую группу"""
        if not self.target_groups[self.current_group]:
            return
        
        reply = QMessageBox.question(
            self.get_ui(),
            "Confirm Clear",
            f"Clear all targets from group '{self.current_group}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.target_groups[self.current_group].clear()
            self._update_targets_list()
    
    def _import_from_file(self):
        """Импортирует цели из файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self.get_ui(),
            "Select targets file",
            "",
            "Text files (*.txt);;All files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                
                self.file_path_label.setText(os.path.basename(file_path))
                targets = self._parse_targets_text(content)
                
                if self.remove_duplicates_check.isChecked():
                    targets = list(set(targets))
                
                # Добавляем цели в текущую группу
                self.target_groups[self.current_group].extend(targets)
                
                if self.remove_duplicates_check.isChecked():
                    self.target_groups[self.current_group] = list(set(self.target_groups[self.current_group]))
                
                self._update_targets_list()
                
                QMessageBox.information(
                    self.get_ui(),
                    "Import Successful",
                    f"Imported {len(targets)} targets from {os.path.basename(file_path)}"
                )
                
            except Exception as e:
                QMessageBox.critical(
                    self.get_ui(),
                    "Import Error",
                    f"Failed to import targets: {str(e)}"
                )
    
    def _add_manual_targets(self):
        """Добавляет цели из редактора в текущую группу"""
        text = self.targets_editor.toPlainText().strip()
        if not text:
            QMessageBox.warning(self.get_ui(), "Warning", "No targets to add!")
            return
        
        targets = self._parse_targets_text(text)
        
        if not targets:
            QMessageBox.warning(self.get_ui(), "Warning", "No valid targets found!")
            return
        
        # Добавляем цели
        current_targets = set(self.target_groups[self.current_group])
        new_targets = set(targets)
        
        if self.remove_duplicates_check.isChecked():
            # Добавляем только новые цели
            added_targets = new_targets - current_targets
            self.target_groups[self.current_group].extend(added_targets)
            added_count = len(added_targets)
        else:
            # Добавляем все цели
            self.target_groups[self.current_group].extend(targets)
            added_count = len(targets)
        
        self._update_targets_list()
        
        QMessageBox.information(
            self.get_ui(),
            "Targets Added",
            f"Added {added_count} targets to group '{self.current_group}'"
        )
    
    def _validate_manual_targets(self):
        """Валидирует цели в редакторе"""
        text = self.targets_editor.toPlainText().strip()
        if not text:
            QMessageBox.information(self.get_ui(), "Validation", "No targets to validate!")
            return
        
        raw_targets = text.replace('\n', ',').split(',')
        valid_targets = []
        invalid_targets = []
        
        for target in raw_targets:
            target = target.strip()
            if target:
                if self._validate_target(target):
                    valid_targets.append(target)
                else:
                    invalid_targets.append(target)
        
        message = f"Valid targets: {len(valid_targets)}\nInvalid targets: {len(invalid_targets)}"
        if invalid_targets:
            message += f"\n\nInvalid targets:\n" + "\n".join(invalid_targets[:10])
            if len(invalid_targets) > 10:
                message += f"\n... and {len(invalid_targets) - 10} more"
        
        QMessageBox.information(self.get_ui(), "Validation Results", message)
    
    def _send_to_scan_launcher(self):
        """Отправляет цели текущей группы в модуль сканирования"""
        if not self.target_groups[self.current_group]:
            QMessageBox.warning(self.get_ui(), "Warning", "No targets in current group!")
            return
        
        # Публикуем событие с целями
        self.event_bus.targets_updated.emit(self.target_groups[self.current_group])
        
        QMessageBox.information(
            self.get_ui(),
            "Targets Sent",
            f"Sent {len(self.target_groups[self.current_group])} targets to Scan Launcher"
        )
    
    def _generate_ip_range(self):
        """Генерирует диапазон IP адресов"""
        start_ip = self.range_start_input.text().strip()
        end_ip = self.range_end_input.text().strip()
        
        if not start_ip or not end_ip:
            QMessageBox.warning(self.get_ui(), "Warning", "Please enter both start and end IP addresses!")
            return
        
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            if start > end:
                QMessageBox.warning(self.get_ui(), "Warning", "Start IP must be less than or equal to End IP!")
                return
            
            # Генерируем диапазон
            targets = []
            current = start
            while current <= end:
                targets.append(str(current))
                current += 1
            
            # Добавляем в редактор
            self.targets_editor.setPlainText('\n'.join(targets))
            
            QMessageBox.information(
                self.get_ui(),
                "Range Generated",
                f"Generated {len(targets)} IP addresses from {start_ip} to {end_ip}"
            )
            
        except ValueError as e:
            QMessageBox.critical(self.get_ui(), "Error", f"Invalid IP address: {str(e)}")
    
    def _add_common_network(self):
        """Добавляет common network в текущую группу"""
        network = self.common_networks_combo.currentText()
        if network == "Common Networks":
            QMessageBox.warning(self.get_ui(), "Warning", "Please select a network from the list!")
            return
        
        if self._validate_target(network):
            self.target_groups[self.current_group].append(network)
            self._update_targets_list()
            
            QMessageBox.information(
                self.get_ui(),
                "Network Added",
                f"Added network {network} to group '{self.current_group}'"
            )
    
    def _on_target_selection_changed(self):
        """Обрабатывает изменение выбора целей"""
        has_selection = len(self.targets_list.selectedItems()) > 0
        self.remove_target_btn.setEnabled(has_selection)

# Для QInputDialog нужно добавить импорт
from PyQt6.QtWidgets import QInputDialog
