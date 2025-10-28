"""
Security Headers Checker Module

Analyzes HTTP security headers to identify missing or misconfigured security measures
that could leave web applications vulnerable to various attacks.
"""

import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Important security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HTTP Strict Transport Security (HSTS)',
        'importance': 'Critical',
        'recommendation': 'Should be set to at least "max-age=31536000; includeSubDomains"'
    },
    'Content-Security-Policy': {
        'description': 'Content Security Policy',
        'importance': 'High',
        'recommendation': 'Should define allowed sources for content'
    },
    'X-Frame-Options': {
        'description': 'Clickjacking Protection',
        'importance': 'High',
        'recommendation': 'Should be set to "DENY" or "SAMEORIGIN"'
    },
    'X-Content-Type-Options': {
        'description': 'MIME Type Sniffing Protection',
        'importance': 'Medium',
        'recommendation': 'Should be set to "nosniff"'
    },
    'Referrer-Policy': {
        'description': 'Referrer Information Control',
        'importance': 'Medium',
        'recommendation': 'Should be set to "strict-origin-when-cross-origin" or similar'
    },
    'Permissions-Policy': {
        'description': 'Feature Policy',
        'importance': 'Medium',
        'recommendation': 'Should restrict access to sensitive browser features'
    },
    'X-XSS-Protection': {
        'description': 'Cross-Site Scripting Protection',
        'importance': 'Low',
        'recommendation': 'Should be set to "1; mode=block"'
    },
    'Server': {
        'description': 'Server Information Disclosure',
        'importance': 'Low',
        'recommendation': 'Should not reveal server software version'
    }
}


def check_security_headers(url, timeout=10):
    """
    Check security headers for a given URL

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        dict: Analysis results including header findings and risk assessment
    """
    findings = []
    suspicious_count = 0
    header_analysis = {}

    try:
        # Make request to get headers
        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        headers = response.headers

        # Check each security header
        for header_name, header_info in SECURITY_HEADERS.items():
            header_value = headers.get(header_name, '').strip()
            header_analysis[header_name] = {
                'present': bool(header_value),
                'value': header_value,
                'description': header_info['description'],
                'importance': header_info['importance'],
                'recommendation': header_info['recommendation']
            }

            # Analyze header presence and configuration
            if not header_value:
                # Header is missing
                if header_info['importance'] == 'Critical':
                    findings.append(f"Critical security header missing: {header_info['description']}")
                    suspicious_count += 3
                elif header_info['importance'] == 'High':
                    findings.append(f"Important security header missing: {header_info['description']}")
                    suspicious_count += 2
                elif header_info['importance'] == 'Medium':
                    findings.append(f"Recommended security header missing: {header_info['description']}")
                    suspicious_count += 1
                else:
                    findings.append(f"Optional security header missing: {header_info['description']}")
            else:
                # Header is present, check configuration
                if header_name == 'Strict-Transport-Security':
                    if 'max-age=' not in header_value or 'max-age=0' in header_value:
                        findings.append("HSTS header is misconfigured or disabled")
                        suspicious_count += 2
                    elif 'includeSubDomains' not in header_value:
                        findings.append("HSTS header should include subdomains")
                        suspicious_count += 1

                elif header_name == 'X-Frame-Options':
                    if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        findings.append("X-Frame-Options header has weak configuration")
                        suspicious_count += 2

                elif header_name == 'Content-Security-Policy':
                    if len(header_value) < 10:  # Very basic CSP
                        findings.append("Content Security Policy appears to be too permissive")
                        suspicious_count += 1

                elif header_name == 'X-Content-Type-Options':
                    if header_value.lower() != 'nosniff':
                        findings.append("X-Content-Type-Options should be set to 'nosniff'")
                        suspicious_count += 1

                elif header_name == 'Server':
                    # Check if server reveals version information
                    if any(char.isdigit() for char in header_value) and ('/' in header_value or ' ' in header_value):
                        findings.append("Server header reveals software version information")
                        suspicious_count += 1

        # Check for additional security issues
        # Check if site redirects to HTTP (should use HTTPS)
        if url.startswith('http://') and response.url.startswith('https://'):
            findings.append("Site redirects from HTTP to HTTPS (good practice)")
        elif url.startswith('https://') and response.url.startswith('http://'):
            findings.append("HTTPS site redirects to HTTP (security risk)")
            suspicious_count += 2

        # Check for insecure cookies
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie and 'secure' not in set_cookie.lower():
            findings.append("Cookies are not marked as secure (should use HTTPS)")
            suspicious_count += 1

        # Check for missing HTTPS
        if not url.startswith('https://'):
            findings.append("Site does not use HTTPS encryption")
            suspicious_count += 2

    except requests.exceptions.RequestException as e:
        findings.append(f"Could not analyze security headers: {str(e)}")
        suspicious_count += 1
        header_analysis = {"error": "Failed to retrieve headers"}

    # Calculate risk level based on findings
    if suspicious_count >= 5:
        risk_level = "Critical"
    elif suspicious_count >= 3:
        risk_level = "High"
    elif suspicious_count >= 2:
        risk_level = "Medium"
    elif suspicious_count >= 1:
        risk_level = "Low"
    else:
        risk_level = "Safe"

    # If no issues found
    if not findings:
        findings.append("No security header vulnerabilities detected")

    return {
        "url": url,
        "risk_level": risk_level,
        "suspicious_count": suspicious_count,
        "findings": findings,
        "header_analysis": header_analysis,
        "response_code": response.status_code if 'response' in locals() else None
    }
