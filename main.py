#!/usr/bin/env python3
import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from core.app_loader import ApplicationLoader

def main():
    # Добавляем пути к модулям
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(script_dir, 'core'))
    sys.path.insert(0, os.path.join(script_dir, 'shared'))
    sys.path.insert(0, os.path.join(script_dir, 'modules'))
    
    app = QApplication(sys.argv)
    app.setApplicationName("NMAP GUI Scanner")
    app.setApplicationVersion("1.0.0")
    
    # Загружаем приложение
    loader = ApplicationLoader()
    main_window = loader.load_application()
    
    if main_window:
        main_window.show()
        sys.exit(app.exec())
    else:
        print("Failed to load application")
        sys.exit(1)

if __name__ == '__main__':
    main()
