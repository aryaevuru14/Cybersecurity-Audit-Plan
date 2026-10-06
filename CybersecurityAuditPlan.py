import socket
import ssl
import json
import urllib.request
from datetime import datetime, timezone

class CybersecurityAuditor:
    def __init__(self, target_host: str):
        self.target_host = target_host
        self.audit_results = {
            "target": target_host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "port_scan": {},
            "http_headers": {},
            "ssl_info": {}
        }

    def scan_ports(self, ports=[21, 22, 80, 443, 3389, 8080]):
        """Scans standard network ports to identify open services."""
        print(f"[*] Starting Port Audit for {self.target_host}...")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((self.target_host, port))
                status = "OPEN" if result == 0 else "CLOSED/FILTERED"
                self.audit_results["port_scan"][port] = status
                sock.close()
            except Exception as e:
                self.audit_results["port_scan"][port] = f"ERROR: {str(e)}"

    def audit_http_headers(self):
        """Audits target HTTP headers for essential security controls."""
        url = f"https://{self.target_host}"
        print(f"[*] Checking HTTP Security Headers for {url}...")
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 AuditScanner/1.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                headers = dict(response.headers)
                for header in security_headers:
                    if header in headers:
                        self.audit_results["http_headers"][header] = {
                            "status": "PASS",
                            "value": headers[header]
                        }
                    else:
                        self.audit_results["http_headers"][header] = {
                            "status": "FAIL - MISSING",
                            "value": None
                        }
        except Exception as e:
            self.audit_results["http_headers"]["error"] = str(e)

    def check_ssl_certificate(self):
        """Inspects target SSL/TLS configuration and expiration."""
        print(f"[*] Inspecting SSL/TLS Certificate for {self.target_host}...")
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.target_host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert = ssock.getpeercert()
                    self.audit_results["ssl_info"]["subject"] = dict(x[0] for x in cert.get('subject', []))
                    self.audit_results["ssl_info"]["issuer"] = dict(x[0] for x in cert.get('issuer', []))
                    self.audit_results["ssl_info"]["notAfter"] = cert.get('notAfter')
        except Exception as e:
            self.audit_results["ssl_info"]["error"] = str(e)

    def export_report(self, filename="audit_report.json"):
        """Exports audit results to JSON format."""
        with open(filename, "w") as f:
            json.dump(self.audit_results, f, indent=4)
        print(f"[+] Audit complete! Detailed log written to {filename}")


if __name__ == "__main__":
    TARGET = "example.com"
    
    auditor = CybersecurityAuditor(TARGET)
    auditor.scan_ports()
    auditor.audit_http_headers()
    auditor.check_ssl_certificate()
    auditor.export_report()