import ipaddress
import re
from typing import List, Tuple

def validate_ip(ip_str: str) -> bool:
    """
    Валидирует IP адрес
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_network(network_str: str) -> bool:
    """
    Валидирует сеть в формате CIDR
    """
    try:
        ipaddress.ip_network(network_str, strict=False)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    """
    Валидирует доменное имя
    """
    if not domain or len(domain) > 253:
        return False
    
    # Простая проверка доменного имени
    domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_regex, domain))

def validate_ip_range(range_str: str) -> bool:
    """
    Валидирует диапазон IP адресов
    """
    try:
        if '-' in range_str:
            parts = range_str.split('-')
            if len(parts) == 2:
                start_ip = parts[0].strip()
                end_ip = parts[1].strip()
                
                # Проверяем start IP
                if not validate_ip(start_ip):
                    return False
                
                # end_ip может быть IP или числом
                if validate_ip(end_ip):
                    return ipaddress.ip_address(start_ip) <= ipaddress.ip_address(end_ip)
                else:
                    # Это числовой диапазон
                    start = ipaddress.ip_address(start_ip)
                    end_num = int(end_ip)
                    return end_num >= int(start.packed[-1])
    except (ValueError, AttributeError):
        pass
    
    return False

def parse_targets(targets_text: str) -> Tuple[List[str], List[str]]:
    """
    Парсит текст с целями и возвращает валидные и невалидные цели
    """
    valid_targets = []
    invalid_targets = []
    
    # Разделяем по запятым и переносам строк
    raw_targets = re.split(r'[,\n]', targets_text)
    
    for target in raw_targets:
        target = target.strip()
        if not target:
            continue
            
        # Проверяем разные форматы
        if (validate_ip(target) or 
            validate_network(target) or 
            validate_domain(target) or 
            validate_ip_range(target)):
            valid_targets.append(target)
        else:
            invalid_targets.append(target)
    
    return valid_targets, invalid_targets

def normalize_targets(targets: List[str]) -> List[str]:
    """
    Нормализует список целей (удаляет дубликаты, сортирует)
    """
    # Удаляем дубликаты
    unique_targets = list(set(targets))
    
    # Сортируем: сначала IP, потом сети, потом домены
    ip_targets = []
    network_targets = []
    domain_targets = []
    range_targets = []
    
    for target in unique_targets:
        if validate_ip(target):
            ip_targets.append(target)
        elif validate_network(target):
            network_targets.append(target)
        elif validate_ip_range(target):
            range_targets.append(target)
        else:
            domain_targets.append(target)
    
    # Сортируем IP адреса
    ip_targets.sort(key=lambda x: ipaddress.ip_address(x))
    
    # Сортируем сети
    network_targets.sort(key=lambda x: ipaddress.ip_network(x, strict=False))
    
    # Сортируем диапазоны (простая сортировка)
    range_targets.sort()
    
    # Сортируем домены
    domain_targets.sort()
    
    return ip_targets + network_targets + range_targets + domain_targets
