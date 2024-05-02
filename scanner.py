import requests
from bs4 import BeautifulSoup

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def check_security_headers(self):
        response = self.session.get(self.target_url)
        headers = response.headers

        missing_headers = []

        # Check for Content-Security-Policy header
        if 'Content-Security-Policy' not in headers:
            missing_headers.append('Content-Security-Policy')

        # Check for X-Frame-Options header
        if 'X-Frame-Options' not in headers:
            missing_headers.append('X-Frame-Options')

        # Check for X-Content-Type-Options header
        if 'X-Content-Type-Options' not in headers:
            missing_headers.append('X-Content-Type-Options')

        # Check for Referrer-Policy header
        if 'Referrer-Policy' not in headers:
            missing_headers.append('Referrer-Policy')

        # Check for Permissions-Policy header
        if 'Permissions-Policy' not in headers:
            missing_headers.append('Permissions-Policy')

        return missing_headers

    def run_scan(self):
        missing_headers = self.check_security_headers()

        if missing_headers:
            print(f"Missing security headers for {self.target_url}: {', '.join(missing_headers)}")
        else:
            print(f"All security headers are present for {self.target_url}")

if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    scanner = SecurityScanner(url)
    scanner.run_scan()
