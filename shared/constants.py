"""
Константы приложения NMAP GUI Scanner
"""

# Версия приложения
APP_VERSION = "1.0.0"
APP_NAME = "NMAP GUI Scanner"
APP_DESCRIPTION = "Graphical User Interface for Nmap with advanced features"

# Настройки по умолчанию
DEFAULT_SCAN_THREADS = 4
DEFAULT_TIMING_TEMPLATE = "T4"
DEFAULT_PORT_RANGE = "1-1000"
DEFAULT_OUTPUT_FORMAT = "xml"

# Цвета для UI
COLORS = {
    'primary': '#2E86AB',
    'secondary': '#A23B72', 
    'success': '#4CAF50',
    'warning': '#FF9800',
    'error': '#F44336',
    'background': '#F5F5F5',
    'text': '#212121',
    'border': '#BDBDBD'
}

# Настройки визуализации
GRAPH_SETTINGS = {
    'node_size_host': 50,
    'node_size_network': 60,
    'node_size_service': 40,
    'node_size_port': 30,
    'edge_width': 2,
    'layout_iterations': 100
}

# Критические сервисы для фильтрации
CRITICAL_SERVICES = {
    'ssh', 'telnet', 'ftp', 'smtp', 'domain', 'http', 'https',
    'microsoft-ds', 'netbios-ssn', 'rpcbind', 'nfs', 'mysql',
    'postgresql', 'mongodb', 'redis', 'vnc', 'rdp', 'snmp'
}

# Шаблоны уязвимых версий (для демонстрации)
VULNERABLE_VERSIONS = {
    'apache': ['2.4.49', '2.4.50'],
    'openssh': ['7.0', '7.1', '7.2', '8.0'],
    'ftp': ['vsftpd 2.3.4'],
    'samba': ['3.0.0', '3.0.1', '3.0.2', '4.0.0'],
    'tomcat': ['7.0.0', '7.0.1', '8.0.0'],
    'iis': ['6.0', '7.0', '7.5']
}

# Поддерживаемые форматы экспорта
EXPORT_FORMATS = ['html', 'json', 'csv', 'txt', 'xml']

# Максимальные значения
MAX_THREADS = 64
MAX_PORT = 65535
MAX_TARGETS = 10000

# Сообщения об ошибках
ERROR_MESSAGES = {
    'nmap_not_found': 'Nmap not found in system PATH. Please install nmap.',
    'invalid_target': 'Invalid target format',
    'scan_failed': 'Scan failed to execute',
    'parse_error': 'Failed to parse scan results',
    'file_not_found': 'File not found',
    'permission_denied': 'Permission denied'
}

# Регулярные выражения для валидации
REGEX_PATTERNS = {
    'ip_address': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
    'network_cidr': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',
    'ip_range': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$',
    'port': r'^\d{1,5}$',
    'port_range': r'^\d{1,5}-\d{1,5}$',
    'port_list': r'^\d{1,5}(,\d{1,5})*$'
}
