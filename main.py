#!/usr/bin/env python3
import sys
import os
import logging
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import QTimer
from core.app_loader import ApplicationLoader

def setup_logging():
    """Настройка логирования"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('nmap_gui.log'),
            logging.StreamHandler()
        ]
    )

def check_dependencies():
    """Проверяет зависимости приложения"""
    try:
        # Проверяем наличие nmap
        import subprocess
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            logging.warning("Nmap might not be properly installed")
            return False
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        logging.error("Nmap not found in system PATH")
        return False

def main():
    """Основная функция приложения"""
    # Настройка логирования
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Добавляем пути к модулям
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(script_dir, 'core'))
    sys.path.insert(0, os.path.join(script_dir, 'shared'))
    sys.path.insert(0, os.path.join(script_dir, 'modules'))
    sys.path.insert(0, os.path.join(script_dir, 'gui'))
    
    # Проверяем зависимости
    if not check_dependencies():
        app = QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Dependency Error",
            "Nmap not found in system PATH.\n\n"
            "Please install nmap to use this application.\n"
            "Windows: Download from https://nmap.org/download.html\n"
            "Linux: sudo apt-get install nmap\n"
            "macOS: brew install nmap"
        )
        sys.exit(1)
    
    # Создаем приложение
    app = QApplication(sys.argv)
    app.setApplicationName("NMAP GUI Scanner")
    app.setApplicationVersion("1.0.0")
    app.setStyle('Fusion')  # Кроссплатформенный стиль
    
    # Загружаем приложение
    try:
        loader = ApplicationLoader()
        main_window = loader.load_application()
        
        if main_window:
            main_window.show()
            logger.info("Application started successfully")
            sys.exit(app.exec())
        else:
            logger.error("Failed to load application main window")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Application error: {e}")
        QMessageBox.critical(
            None,
            "Application Error",
            f"Failed to start application:\n{str(e)}"
        )
        sys.exit(1)

if __name__ == '__main__':
    main()
