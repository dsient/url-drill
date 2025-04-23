# url-drill

```
≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡  A website vulnerability scanner, designed for CTF use.
║   ┌┬┬┬┬┬┬┬┐        ║  Scans a link against a modifed version of the gobuster link traveral list; Scans for scripts, forms, emails,
║   URL-DRILL        ║  basic vulnerabilities, etc.
║ ▄▄┼┼≡≡≡≡≡┼┼▄▄      ║  - Uses a security disclosure header
║ █▓▓▓▓▓■▓▓▓▓▓█      ║  - WAF/IPS Evasion
║  █▒▒▒▓▓▓▒▒▒█       ║  
║ . ≡\▒▒▒▒▒/≡        ║  
║  ·  \░░░/ ` .      ║  
║ . ` `\░/ `°·@DSiENT║  Made for Linux (Windows, Mac untested as of 4/22/2025)
≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡  url-drill complies with GDPR/CCPA logging requirements.

URL-DRILL Features ::

1. Target Acquisition
   - Fetches target URL
   - Parses HTML with BeautifulSoup

2. Link Discovery
   - Extracts all anchor (<a>) links

3. Form Detection
   - Identifies forms and input fields
   - Logs method, action, and field types

4. Script Discovery
   - Logs all external <script src=""> links

5. Vulnerability Scanning (OWASP Top 10 Coverage)
   A. Sensitive Endpoints
      - /admin, /.env, /.git/config, etc.
   B. SQL Injection
      - Error-based and time-based payloads
   C. XSS (Cross-Site Scripting)
      - Reflected and stored XSS in forms
   D. Command Injection
      - Executes shell-style payloads
   E. Path Traversal
      - ../../etc/passwd, URL-encoded patterns
   F. XXE (XML External Entity)
      - Posts malicious XML and checks response
   G. Insecure Deserialization
      - Tests with Java and Python payloads

6. Security Headers Check
   - Verifies presence of key HTTP headers:
     - Content-Security-Policy
     - X-Frame-Options
     - X-Content-Type-Options
     - Strict-Transport-Security

7. Hidden Elements Discovery
   - Finds hidden inputs and elements with CSS or HTML tags

8. CORS Policy Inspection
   - Checks Access-Control-Allow-Origin header

9. Multithreaded Path Traversal
   - Uses the gobuster wordlist to test common paths
   - Logs status, size, response time, final URL
   - Threaded with connection pooling

10. Log Analysis
    - Extracts non-404 results from scan logs
    - Saves to 'non404.txt'

Bonus Features:
- CLI banner/logo from ASCII art
- Thread-safe logging
- Graceful handling of keyboard interrupts

```
