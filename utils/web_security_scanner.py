"""
Web Security Scanner Module

Performs additional low-level security checks for common web vulnerabilities
beyond basic header analysis.
"""

import requests
import re
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def scan_web_security_vulnerabilities(url, timeout=15):
    """
    Scan for common web security vulnerabilities

    Args:
        url (str): The URL to scan
        timeout (int): Request timeout in seconds

    Returns:
        dict: Analysis results including vulnerability findings
    """
    findings = []
    suspicious_count = 0
    vulnerabilities = {}

    try:
        # Make initial request
        response = requests.get(url, timeout=timeout, verify=False)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')

        # 1. Check for SQL Injection vulnerabilities (basic pattern detection)
        sql_patterns = [
            r"SELECT.*FROM.*WHERE",
            r"INSERT.*INTO.*VALUES",
            r"UPDATE.*SET.*WHERE",
            r"DELETE.*FROM.*WHERE"
        ]

        sql_indicators = []
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                sql_indicators.append(pattern)

        if sql_indicators:
            vulnerabilities['potential_sql_injection'] = {
                'severity': 'High',
                'description': 'Potential SQL injection patterns detected in page content',
                'patterns_found': sql_indicators
            }
            findings.append("Potential SQL injection vulnerabilities detected")
            suspicious_count += 3

        # 2. Check for XSS vulnerabilities (basic detection)
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"eval\s*\(",
            r"document\.write\s*\("
        ]

        xss_indicators = []
        for pattern in xss_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                xss_indicators.extend(matches[:3])  # Limit to first 3 matches

        if xss_indicators:
            vulnerabilities['potential_xss'] = {
                'severity': 'High',
                'description': 'Potential Cross-Site Scripting (XSS) patterns detected',
                'patterns_found': xss_indicators[:5]  # Limit output
            }
            findings.append("Potential XSS vulnerabilities detected")
            suspicious_count += 3

        # 3. Check for directory listing vulnerability
        directory_indicators = [
            "Index of /",
            "Parent Directory",
            "[DIR]",
            "Directory Listing"
        ]

        for indicator in directory_indicators:
            if indicator.lower() in content.lower():
                vulnerabilities['directory_listing'] = {
                    'severity': 'Medium',
                    'description': 'Directory listing appears to be enabled'
                }
                findings.append("Directory listing vulnerability detected")
                suspicious_count += 2
                break

        # 4. Check for exposed sensitive files
        sensitive_files = [
            '/.git/',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/web.config',
            '/.htaccess',
            '/admin/',
            '/backup/',
            '/db.sql',
            '/phpinfo.php'
        ]

        exposed_files = []
        for file_path in sensitive_files:
            try:
                test_url = urljoin(url, file_path)
                file_response = requests.head(test_url, timeout=5, verify=False)
                if file_response.status_code == 200:
                    exposed_files.append(file_path)
            except:
                continue

        if exposed_files:
            vulnerabilities['exposed_sensitive_files'] = {
                'severity': 'Critical',
                'description': 'Sensitive files are publicly accessible',
                'files': exposed_files
            }
            findings.append(f"Exposed sensitive files detected: {', '.join(exposed_files)}")
            suspicious_count += 4

        # 5. Check for insecure form submissions
        forms = soup.find_all('form')
        insecure_forms = []

        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()

            # Check if form submits to HTTP
            if action.startswith('http://'):
                insecure_forms.append('HTTP form submission')
            elif not action.startswith('https://') and url.startswith('https://'):
                # Relative URL on HTTPS site - check if it would be insecure
                full_action = urljoin(url, action)
                if not full_action.startswith('https://'):
                    insecure_forms.append('Potentially insecure form action')

            # Check for autocomplete enabled on sensitive forms
            inputs = form.find_all('input')
            for input_field in inputs:
                input_type = input_field.get('type', '').lower()
                if input_type in ['password', 'email'] and input_field.get('autocomplete') != 'off':
                    insecure_forms.append('Sensitive form fields allow autocomplete')

        if insecure_forms:
            vulnerabilities['insecure_forms'] = {
                'severity': 'Medium',
                'description': 'Forms have security weaknesses',
                'issues': list(set(insecure_forms))  # Remove duplicates
            }
            findings.append("Insecure form configurations detected")
            suspicious_count += 2

        # 6. Check for outdated software versions in meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            content_attr = meta.get('content', '')
            if 'wordpress' in content_attr.lower() or 'generator' in meta.get('name', '').lower():
                if re.search(r'version[\s=]+[\d.]+', content_attr, re.IGNORECASE):
                    vulnerabilities['version_disclosure'] = {
                        'severity': 'Low',
                        'description': 'Software version information is disclosed in meta tags'
                    }
                    findings.append("Software version disclosure detected")
                    suspicious_count += 1
                    break

        # 7. Check for missing security.txt file
        try:
            security_url = urljoin(url, '/.well-known/security.txt')
            security_response = requests.get(security_url, timeout=5, verify=False)
            if security_response.status_code != 200:
                vulnerabilities['missing_security_txt'] = {
                    'severity': 'Low',
                    'description': 'security.txt file is missing (RFC 9116)'
                }
                findings.append("Missing security.txt file")
                suspicious_count += 1
        except:
            pass

        # 8. Check for robots.txt exposure
        try:
            robots_url = urljoin(url, '/robots.txt')
            robots_response = requests.get(robots_url, timeout=5, verify=False)
            if robots_response.status_code == 200:
                robots_content = robots_response.text.lower()
                # Check if robots.txt reveals sensitive paths
                sensitive_paths = ['/admin', '/config', '/backup', '/private']
                revealed_paths = []
                for path in sensitive_paths:
                    if path in robots_content:
                        revealed_paths.append(path)

                if revealed_paths:
                    vulnerabilities['robots_txt_reveals_sensitive'] = {
                        'severity': 'Low',
                        'description': 'robots.txt reveals potentially sensitive paths',
                        'paths': revealed_paths
                    }
                    findings.append("robots.txt reveals sensitive paths")
                    suspicious_count += 1
        except:
            pass

        # 9. Check for HTTP methods
        allowed_methods = check_http_methods(url)
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
        enabled_dangerous_methods = [method for method in dangerous_methods if method in allowed_methods]

        if enabled_dangerous_methods:
            vulnerabilities['dangerous_http_methods'] = {
                'severity': 'Medium',
                'description': 'Dangerous HTTP methods are enabled',
                'methods': enabled_dangerous_methods
            }
            findings.append(f"Dangerous HTTP methods enabled: {', '.join(enabled_dangerous_methods)}")
            suspicious_count += 2

        # 10. Check for mixed content (HTTP resources on HTTPS pages)
        if url.startswith('https://'):
            mixed_content = []

            # Check for HTTP links in HTML
            http_links = soup.find_all(['a', 'link', 'script', 'img'], href=True)
            for link in http_links:
                href = link['href']
                if href.startswith('http://'):
                    mixed_content.append(href)

            # Check for HTTP sources in scripts and styles
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                if script['src'].startswith('http://'):
                    mixed_content.append(script['src'])

            styles = soup.find_all('link', rel='stylesheet', href=True)
            for style in styles:
                if style['href'].startswith('http://'):
                    mixed_content.append(style['href'])

            if mixed_content:
                vulnerabilities['mixed_content'] = {
                    'severity': 'Medium',
                    'description': 'HTTPS page loads resources over HTTP (mixed content)',
                    'resources': mixed_content[:5]  # Limit to first 5
                }
                findings.append("Mixed content vulnerability detected")
                suspicious_count += 2

    except requests.exceptions.RequestException as e:
        findings.append(f"Could not perform web security scan: {str(e)}")
        suspicious_count += 1
        vulnerabilities = {"error": "Failed to scan web security"}

    # Calculate overall risk level
    if suspicious_count >= 6:
        risk_level = "Critical"
    elif suspicious_count >= 4:
        risk_level = "High"
    elif suspicious_count >= 2:
        risk_level = "Medium"
    elif suspicious_count >= 1:
        risk_level = "Low"
    else:
        risk_level = "Safe"

    # If no vulnerabilities found
    if not findings:
        findings.append("No web security vulnerabilities detected")

    return {
        "url": url,
        "risk_level": risk_level,
        "suspicious_count": suspicious_count,
        "findings": findings,
        "vulnerabilities": vulnerabilities
    }


def check_http_methods(url, timeout=10):
    """
    Check which HTTP methods are allowed on the server

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        list: List of allowed HTTP methods
    """
    methods_to_check = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH']
    allowed_methods = []

    try:
        for method in methods_to_check:
            try:
                response = requests.request(method, url, timeout=timeout, verify=False)
                if response.status_code < 400:  # Method is allowed
                    allowed_methods.append(method)
            except:
                continue
    except:
        pass

    return allowed_methods
