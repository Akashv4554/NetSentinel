from app.scanner.tcp import TCPScanner

scanner = TCPScanner(timeout=2)

targets = [
    ("scanme.nmap.org", 22),
    ("scanme.nmap.org", 80),
    ("scanme.nmap.org", 443),
    ("scanme.nmap.org", 9999),
    ("google.com", 443),
    ("127.0.0.1", 80),
]

for host, port in targets:
    result = scanner.scan_port(host, port)
    print(result)