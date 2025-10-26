import json
import csv
import html
from typing import List, Dict, Any
from datetime import datetime
from ..models.scan_result import ScanResult, HostInfo, PortInfo

class ExportManager:
    """Менеджер экспорта результатов сканирования"""
    
    @staticmethod
    def export_to_json(scan_result: ScanResult, include_raw_xml: bool = False) -> str:
        """
        Экспортирует результаты в JSON формат
        
        Args:
            scan_result: Результаты сканирования
            include_raw_xml: Включать ли raw XML
            
        Returns:
            str: JSON строка
        """
        export_data = {
            "metadata": {
                "scan_id": scan_result.scan_id,
                "scan_type": scan_result.config.scan_type.value if scan_result.config else "unknown",
                "start_time": scan_result.start_time.isoformat() if scan_result.start_time else None,
                "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
                "export_time": datetime.now().isoformat(),
                "total_hosts": len(scan_result.hosts)
            },
            "hosts": []
        }
        
        for host in scan_result.hosts:
            host_data = {
                "ip": host.ip,
                "hostname": host.hostname,
                "status": host.state,
                "os": {
                    "family": host.os_family,
                    "details": host.os_details
                },
                "ports": [],
                "scripts": host.scripts
            }
            
            for port in host.ports:
                port_data = {
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service,
                    "version": port.version,
                    "reason": port.reason
                }
                host_data["ports"].append(port_data)
            
            export_data["hosts"].append(host_data)
        
        if include_raw_xml and scan_result.raw_xml:
            export_data["raw_xml"] = scan_result.raw_xml
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    @staticmethod
    def export_to_csv(scan_result: ScanResult) -> str:
        """
        Экспортирует результаты в CSV формат
        
        Returns:
            str: CSV строка
        """
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Заголовок
        writer.writerow([
            "Host", "Hostname", "Status", "OS Family", "OS Details",
            "Port", "Protocol", "State", "Service", "Version", "Reason"
        ])
        
        # Данные
        for host in scan_result.hosts:
            if host.ports:
                for port in host.ports:
                    writer.writerow([
                        host.ip,
                        host.hostname,
                        host.state,
                        host.os_family or "",
                        host.os_details or "",
                        port.port,
                        port.protocol,
                        port.state,
                        port.service,
                        port.version or "",
                        port.reason or ""
                    ])
            else:
                # Хост без портов
                writer.writerow([
                    host.ip,
                    host.hostname,
                    host.state,
                    host.os_family or "",
                    host.os_details or "",
                    "", "", "", "", "", ""
                ])
        
        return output.getvalue()
    
    @staticmethod
    def export_to_html(scan_result: ScanResult, title: str = "Nmap Scan Report") -> str:
        """
        Экспортирует результаты в HTML формат
        
        Returns:
            str: HTML строка
        """
        stats = ExportManager._calculate_statistics(scan_result)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{html.escape(title)}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .host-section {{ margin: 20px 0; }}
                .up-host {{ color: green; }}
                .down-host {{ color: red; }}
                .open-port {{ background-color: #d4edda; }}
            </style>
        </head>
        <body>
            <h1>{html.escape(title)}</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Hosts:</strong> {stats['total_hosts']}</p>
                <p><strong>Active Hosts:</strong> {stats['active_hosts']}</p>
                <p><strong>Open Ports:</strong> {stats['open_ports']}</p>
                <p><strong>Unique Services:</strong> {stats['unique_services']}</p>
            </div>
        """
        
        # Детали по хостам
        html_content += "<h2>Host Details</h2>"
        
        for host in scan_result.hosts:
            status_class = "up-host" if host.state == "up" else "down-host"
            
            html_content += f"""
            <div class="host-section">
                <h3 class="{status_class}">Host: {html.escape(host.ip)} 
                    {f'({html.escape(host.hostname)})' if host.hostname else ''}
                    - {host.state.upper()}
                </h3>
                <p><strong>OS:</strong> {html.escape(host.os_family or 'Unknown')} 
                   {html.escape(host.os_details or '')}</p>
            """
            
            if host.ports:
                html_content += """
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                """
                
                for port in host.ports:
                    row_class = "open-port" if port.state == "open" else ""
                    html_content += f"""
                    <tr class="{row_class}">
                        <td>{port.port}</td>
                        <td>{port.protocol}</td>
                        <td>{port.state}</td>
                        <td>{html.escape(port.service)}</td>
                        <td>{html.escape(port.version or '')}</td>
                    </tr>
                    """
                
                html_content += "</table>"
            
            html_content += "</div>"
        
        html_content += """
        </body>
        </html>
        """
        
        return html_content
    
    @staticmethod
    def export_to_text(scan_result: ScanResult) -> str:
        """
        Экспортирует результаты в текстовый формат
        
        Returns:
            str: Текстовая строка
        """
        lines = []
        lines.append("NMAP SCAN REPORT")
        lines.append("=" * 50)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Scan ID: {scan_result.scan_id}")
        lines.append("")
        
        stats = ExportManager._calculate_statistics(scan_result)
        lines.append("SUMMARY:")
        lines.append(f"  Total Hosts: {stats['total_hosts']}")
        lines.append(f"  Active Hosts: {stats['active_hosts']}")
        lines.append(f"  Open Ports: {stats['open_ports']}")
        lines.append(f"  Unique Services: {stats['unique_services']}")
        lines.append("")
        
        for host in scan_result.hosts:
            lines.append(f"HOST: {host.ip}")
            lines.append(f"  Hostname: {host.hostname or 'N/A'}")
            lines.append(f"  Status: {host.state}")
            lines.append(f"  OS: {host.os_family or 'Unknown'} {host.os_details or ''}")
            
            if host.ports:
                lines.append("  PORTS:")
                for port in host.ports:
                    if port.state == "open":
                        lines.append(f"    {port.port}/{port.protocol} - {port.service} - {port.version or 'N/A'}")
            
            lines.append("")
        
        return '\n'.join(lines)
    
    @staticmethod
    def _calculate_statistics(scan_result: ScanResult) -> Dict[str, Any]:
        """Вычисляет статистику сканирования"""
        stats = {
            "total_hosts": len(scan_result.hosts),
            "active_hosts": len([h for h in scan_result.hosts if h.state == "up"]),
            "open_ports": 0,
            "unique_services": set()
        }
        
        for host in scan_result.hosts:
            for port in host.ports:
                if port.state == "open":
                    stats["open_ports"] += 1
                    if port.service and port.service != "unknown":
                        stats["unique_services"].add(port.service)
        
        stats["unique_services"] = len(stats["unique_services"])
        return stats
    
    @staticmethod
    def export_to_xml(scan_result: ScanResult) -> str:
        """
        Экспортирует результаты в XML формат
        
        Returns:
            str: XML строка
        """
        if scan_result.raw_xml:
            return scan_result.raw_xml
        else:
            # Генерируем базовый XML если raw_xml недоступен
            return ExportManager._generate_basic_xml(scan_result)
    
    @staticmethod
    def _generate_basic_xml(scan_result: ScanResult) -> str:
        """Генерирует базовый XML если оригинальный недоступен"""
        xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_parts.append('<nmaprun scanner="nmap" args="" start="" version="">')
        
        for host in scan_result.hosts:
            xml_parts.append(f'<host>')
            xml_parts.append(f'<address addr="{host.ip}" addrtype="ipv4"/>')
            
            if host.hostname:
                xml_parts.append('<hostnames>')
                xml_parts.append(f'<hostname name="{host.hostname}" type="user"/>')
                xml_parts.append('</hostnames>')
            
            xml_parts.append(f'<status state="{host.state}" reason=""/>')
            
            if host.ports:
                xml_parts.append('<ports>')
                for port in host.ports:
                    xml_parts.append(f'<port protocol="{port.protocol}" portid="{port.port}">')
                    xml_parts.append(f'<state state="{port.state}" reason=""/>')
                    xml_parts.append(f'<service name="{port.service}" product="{port.version or ""}"/>')
                    xml_parts.append('</port>')
                xml_parts.append('</ports>')
            
            xml_parts.append('</host>')
        
        xml_parts.append('</nmaprun>')
        return '\n'.join(xml_parts)
                    xml_parts.append(f'<status state="{host.state}" reason=""/>')
            
            if host.ports:
                xml_parts.append('<ports>')
                for port in host.ports:
                    xml_parts.append(f'<port protocol="{port.protocol}" portid="{port.port}">')
                    xml_parts.append(f'<state state="{port.state}" reason=""/>')
                    if port.service or port.version:
                        service_attrs = f'name="{port.service}"' if port.service else ''
                        if port.version:
                            service_attrs += f' product="{port.version}"'
                        xml_parts.append(f'<service {service_attrs}/>')
                    xml_parts.append('</port>')
                xml_parts.append('</ports>')
            
            # Информация об ОС
            if host.os_family:
                xml_parts.append('<os>')
                xml_parts.append(f'<osmatch name="{host.os_family}" accuracy="100">')
                if host.os_details:
                    xml_parts.append(f'<osclass type="{host.os_details}" vendor="" osfamily="{host.os_family}" osgen="" accuracy="100"/>')
                xml_parts.append('</osmatch>')
                xml_parts.append('</os>')
            
            xml_parts.append('</host>')
        
        # Добавляем время завершения
        end_time = scan_result.end_time or datetime.now()
        xml_parts.append(f'<runstats>')
        xml_parts.append(f'<finished time="{int(end_time.timestamp())}" timestr="{end_time.isoformat()}"/>')
        xml_parts.append('</runstats>')
        
        xml_parts.append('</nmaprun>')
        return '\n'.join(xml_parts)
      
