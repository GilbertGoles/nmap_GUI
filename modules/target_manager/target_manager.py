from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGroupBox,
                             QTextEdit, QLabel, QPushButton, QListWidget,
                             QListWidgetItem, QFileDialog, QMessageBox)
from PyQt6.QtCore import pyqtSlot
from modules.base_module import BaseTabModule
from core.event_bus import EventBus

def create_tab(event_bus: EventBus, dependencies: dict = None):
    return TargetManagerTab(event_bus, dependencies)

class TargetManagerTab(BaseTabModule):
    
    def _setup_event_handlers(self):
        """Настройка обработчиков событий"""
        pass
    
    def _create_ui(self):
        """Создает UI компонент управления целями"""
        layout = QVBoxLayout(self)
        
        # Заголовок
        title = QLabel("Target Manager")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Группа ввода целей
        input_group = QGroupBox("Target Input")
        input_layout = QVBoxLayout(input_group)
        
        self.targets_editor = QTextEdit()
        self.targets_editor.setPlaceholderText(
            "Enter targets (one per line or comma separated):\n"
            "192.168.1.1\n"
            "10.0.0.0/24\n" 
            "scanme.nmap.org\n"
            "192.168.1.1-100"
        )
        self.targets_editor.setMaximumHeight(150)
        input_layout.addWidget(self.targets_editor)
        
        # Кнопки управления вводом
        button_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Targets")
        self.add_btn.clicked.connect(self._add_targets)
        
        self.clear_btn = QPushButton("Clear Editor")
        self.clear_btn.clicked.connect(self.targets_editor.clear)
        
        self.import_btn = QPushButton("Import from File")
        self.import_btn.clicked.connect(self._import_from_file)
        
        button_layout.addWidget(self.add_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addWidget(self.import_btn)
        
        input_layout.addLayout(button_layout)
        layout.addWidget(input_group)
        
        # Группа списка целей
        list_group = QGroupBox("Target List")
        list_layout = QVBoxLayout(list_group)
        
        self.targets_list = QListWidget()
        list_layout.addWidget(self.targets_list)
        
        # Кнопки управления списком
        list_buttons_layout = QHBoxLayout()
        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.clicked.connect(self._remove_selected)
        
        self.clear_list_btn = QPushButton("Clear All")
        self.clear_list_btn.clicked.connect(self._clear_all)
        
        self.send_btn = QPushButton("Send to Scanner")
        self.send_btn.clicked.connect(self._send_to_scanner)
        self.send_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        
        list_buttons_layout.addWidget(self.remove_btn)
        list_buttons_layout.addWidget(self.clear_list_btn)
        list_buttons_layout.addWidget(self.send_btn)
        
        list_layout.addLayout(list_buttons_layout)
        layout.addWidget(list_group)
        
        # Статистика
        self.stats_label = QLabel("Total targets: 0")
        layout.addWidget(self.stats_label)
        
        # Инициализируем список целей
        self.targets = []
    
    def _add_targets(self):
        """Добавляет цели из редактора в список"""
        text = self.targets_editor.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "No targets to add!")
            return
        
        # Разделяем цели
        targets = []
        for line in text.split('\n'):
            for target in line.split(','):
                target = target.strip()
                if target and target not in self.targets:
                    targets.append(target)
        
        # Добавляем в список
        self.targets.extend(targets)
        self._update_targets_list()
        
        QMessageBox.information(self, "Success", f"Added {len(targets)} targets")
    
    def _import_from_file(self):
        """Импортирует цели из файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select targets file", "", "Text files (*.txt);;All files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                
                self.targets_editor.setPlainText(content)
                QMessageBox.information(self, "Success", "File loaded into editor")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read file: {e}")
    
    def _remove_selected(self):
        """Удаляет выбранные цели"""
        selected_items = self.targets_list.selectedItems()
        if not selected_items:
            return
        
        for item in selected_items:
            target = item.text()
            if target in self.targets:
                self.targets.remove(target)
        
        self._update_targets_list()
    
    def _clear_all(self):
        """Очищает все цели"""
        if not self.targets:
            return
        
        reply = QMessageBox.question(
            self, "Confirm", "Clear all targets?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.targets.clear()
            self._update_targets_list()
    
    def _send_to_scanner(self):
        """Отправляет цели в модуль сканирования"""
        if not self.targets:
            QMessageBox.warning(self, "Warning", "No targets to send!")
            return
        
        self.event_bus.targets_updated.emit(self.targets)
        QMessageBox.information(self, "Success", f"Sent {len(self.targets)} targets to scanner")
    
    def _update_targets_list(self):
        """Обновляет список целей"""
        self.targets_list.clear()
        for target in self.targets:
            self.targets_list.addItem(target)
        
        self.stats_label.setText(f"Total targets: {len(self.targets)}")
