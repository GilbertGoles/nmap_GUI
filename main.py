#!/usr/bin/env python3
import sys
import os
import logging
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont

def setup_logging():
    """Настройка системы логирования"""
    # Создаем директорию для логов если её нет
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Форматирование
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Файловый обработчик
    log_file = os.path.join(log_dir, f"nmap_gui_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    
    # Консольный обработчик
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Настраиваем корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Логируем запуск
    logging.info("=" * 60)
    logging.info("🚀 NMAP GUI Scanner Application Starting")
    logging.info("=" * 60)

def check_dependencies():
    """Проверяет зависимости приложения"""
    try:
        import subprocess
        # Проверяем наличие nmap
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"✅ Nmap found: {result.stdout.splitlines()[0] if result.stdout else 'Unknown version'}")
            return True
        else:
            logging.warning("⚠️ Nmap might not be properly installed")
            return False
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logging.error(f"❌ Nmap not found in system PATH: {e}")
        return False

def check_python_dependencies():
    """Проверяет Python зависимости"""
    try:
        from PyQt6 import QtCore, QtWidgets, QtGui
        logging.info(f"✅ PyQt6 version: {QtCore.PYQT_VERSION_STR}")
        
        import psutil
        logging.info(f"✅ psutil version: {psutil.__version__}")
        
        return True
    except ImportError as e:
        logging.error(f"❌ Missing Python dependency: {e}")
        return False

def setup_application_paths():
    """Настраивает пути для импорта модулей"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Добавляем пути к модулям в PYTHONPATH
    modules_to_add = [
        script_dir,
        os.path.join(script_dir, 'core'),
        os.path.join(script_dir, 'shared'),
        os.path.join(script_dir, 'modules'),
        os.path.join(script_dir, 'gui')
    ]
    
    for path in modules_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)
            logging.debug(f"📁 Added to path: {path}")

def handle_exception(exc_type, exc_value, exc_traceback):
    """Глобальный обработчик исключений"""
    if issubclass(exc_type, KeyboardInterrupt):
        # Не логируем KeyboardInterrupt
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logging.critical(
        "💥 Uncaught exception",
        exc_info=(exc_type, exc_value, exc_traceback)
    )
    
    # Показываем сообщение об ошибке пользователю
    try:
        app = QApplication.instance()
        if app:
            error_msg = f"Critical error occurred:\n\n{str(exc_value)}\n\nCheck logs for details."
            QMessageBox.critical(None, "Application Error", error_msg)
    except:
        pass  # Если QApplication не доступен

def main():
    """Основная функция приложения"""
    # Настройка глобального обработчика исключений
    sys.excepthook = handle_exception
    
    # Настройка логирования
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Настройка путей
    setup_application_paths()
    
    # Проверяем зависимости
    logger.info("🔍 Checking dependencies...")
    
    if not check_dependencies():
        app = QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Dependency Error",
            "Nmap not found in system PATH.\n\n"
            "Please install nmap to use this application:\n"
            "• Windows: Download from https://nmap.org/download.html\n"
            "• Linux: sudo apt-get install nmap\n"
            "• macOS: brew install nmap"
        )
        return 1
    
    if not check_python_dependencies():
        app = QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Dependency Error", 
            "Missing Python dependencies.\n\n"
            "Please install required packages:\n"
            "pip install PyQt6 psutil"
        )
        return 1
    
    logger.info("✅ All dependencies satisfied")
    
    # Создаем приложение
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("NMAP GUI Scanner")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("NMAP GUI Project")
        
        # Настраиваем стиль приложения
        app.setStyle('Fusion')
        
        # Настраиваем шрифт по умолчанию для лучшей читаемости
        default_font = QFont("Segoe UI", 10)
        app.setFont(default_font)
        
        logger.info("🖥️ QApplication created successfully")
        
    except Exception as e:
        logger.critical(f"❌ Failed to create QApplication: {e}")
        return 1
    
    # Загружаем основное приложение
    try:
        logger.info("📦 Loading application modules...")
        
        from core.app_loader import ApplicationLoader
        
        loader = ApplicationLoader()
        main_window = loader.load_application()
        
        if main_window:
            logger.info("✅ Application loaded successfully")
            
            # Показываем главное окно
            main_window.show()
            logger.info("👀 Main window displayed")
            
            # Запускаем главный цикл
            logger.info("🔄 Starting main event loop...")
            return_code = app.exec()
            
            logger.info(f"🔚 Application finished with exit code: {return_code}")
            return return_code
            
        else:
            logger.error("❌ Failed to load application main window")
            QMessageBox.critical(
                None,
                "Application Error",
                "Failed to load application interface.\n\n"
                "Please check the log file for details."
            )
            return 1
            
    except ImportError as e:
        logger.critical(f"❌ Import error: {e}")
        QMessageBox.critical(
            None,
            "Import Error",
            f"Failed to import application modules:\n\n{str(e)}\n\n"
            "Please ensure all files are in the correct locations."
        )
        return 1
        
    except Exception as e:
        logger.critical(f"💥 Application crashed: {e}", exc_info=True)
        QMessageBox.critical(
            None,
            "Application Error",
            f"Application encountered a critical error:\n\n{str(e)}\n\n"
            "Please check the log file for details."
        )
        return 1

if __name__ == '__main__':
    exit_code = main()
    logging.info(f"🔚 Application exit with code: {exit_code}")
    sys.exit(exit_code)
