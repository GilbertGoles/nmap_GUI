class ResultsTableTab(BaseTabModule):
    
    def __init__(self, event_bus: EventBus, dependencies: dict = None):
        super().__init__(event_bus, dependencies)
        self.cve_checker = CVEChecker()  # Инициализируем CVE checker
        self.current_results = None
    
    def _extract_vulnerabilities(self, host: HostInfo) -> list:
        """Извлекает информацию об уязвимостях из скриптов nmap и CVE баз"""
        vulnerabilities = []
        
        # Анализируем скрипты nmap
        for script_name, script_output in host.scripts.items():
            vuln_info = self._parse_vulnerability_from_script(script_name, script_output, host)
            if vuln_info:
                vulnerabilities.append(vuln_info)
        
        # Проверяем CVE для сервисов
        for port in host.ports:
            if port.state == "open" and port.service and port.version:
                cve_vulns = self._check_cve_vulnerabilities(port, host)
                vulnerabilities.extend(cve_vulns)
        
        return vulnerabilities
    
    def _check_cve_vulnerabilities(self, port: PortInfo, host: HostInfo) -> list:
        """Проверяет CVE уязвимости для сервиса"""
        vulnerabilities = []
        
        try:
            # Проверяем CVE для конкретного сервиса
            cves = self.cve_checker.check_service_cve(port.service, port.version)
            
            for cve in cves:
                vulnerabilities.append({
                    'type': 'CVE',
                    'id': cve['id'],
                    'service': port.service,
                    'port': port.port,
                    'version': port.version,
                    'risk': cve['risk'],
                    'issue': cve['description'],
                    'cvss_score': cve['cvss_score'],
                    'recommendation': f"Update {port.service} to latest version",
                    'source': cve['source']
                })
                
        except Exception as e:
            self.logger.debug(f"CVE check failed for {port.service}: {e}")
        
        return vulnerabilities
