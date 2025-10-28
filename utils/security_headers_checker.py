"""
Security Headers Checker Module

Analyzes HTTP security headers to identify missing or misconfigured security measures
that could leave web applications vulnerable to various attacks.
"""

import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Security Headers Checklist based on best practices
SECURITY_HEADERS = {
    'X-Frame-Options': {
        'purpose': 'Prevents Clickjacking',
        'what_to_check': 'Should be set to DENY or SAMEORIGIN',
        'example': 'X-Frame-Options: SAMEORIGIN',
        'importance': 'High'
    },
    'Content-Security-Policy': {
        'purpose': 'Prevents XSS, data injection',
        'what_to_check': 'Should exist and be restrictive',
        'example': "Content-Security-Policy: default-src 'self'",
        'importance': 'High'
    },
    'Strict-Transport-Security': {
        'purpose': 'Enforces HTTPS',
        'what_to_check': 'Present with a long max-age and includeSubDomains',
        'example': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'importance': 'Critical'
    },
    'X-Content-Type-Options': {
        'purpose': 'Prevents MIME-type sniffing',
        'what_to_check': 'Must be nosniff',
        'example': 'X-Content-Type-Options: nosniff',
        'importance': 'Medium'
    },
    'Referrer-Policy': {
        'purpose': 'Controls referrer info leakage',
        'what_to_check': 'Must exist and be restrictive',
        'example': 'Referrer-Policy: no-referrer',
        'importance': 'Medium'
    },
    'Permissions-Policy': {
        'purpose': 'Controls access to browser features',
        'what_to_check': 'Should exist and limit features',
        'example': 'Permissions-Policy: geolocation=(), camera=()',
        'importance': 'Medium'
    },
    'X-XSS-Protection': {
        'purpose': 'Legacy header for XSS',
        'what_to_check': 'Should be 1; mode=block (for old browsers)',
        'example': 'X-XSS-Protection: 1; mode=block',
        'importance': 'Low'
    },
    'Cross-Origin-Opener-Policy': {
        'purpose': 'Isolates browsing contexts',
        'what_to_check': 'Should exist',
        'example': 'Cross-Origin-Opener-Policy: same-origin',
        'importance': 'Medium'
    },
    'Cross-Origin-Resource-Policy': {
        'purpose': 'Controls cross-origin data sharing',
        'what_to_check': 'Should exist',
        'example': 'Cross-Origin-Resource-Policy: same-origin',
        'importance': 'Medium'
    },
    'Cross-Origin-Embedder-Policy': {
        'purpose': 'Helps in preventing data leaks',
        'what_to_check': 'Should exist',
        'example': 'Cross-Origin-Embedder-Policy: require-corp',
        'importance': 'Medium'
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
            status = 'missing'  # Default
            status_icon = '❌'
            message = f"{header_info['purpose']}: Missing"

            if header_value:
                status = 'correct'
                status_icon = '✅'
                message = f"{header_info['purpose']}: {header_info['what_to_check']} "
                suspicious_count += 0  # Good

                # Specific configuration checks
                if header_name == 'Strict-Transport-Security':
                    if 'max-age=' not in header_value or int(header_value.split('max-age=')[1].split(';')[0]) < 31536000:
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Weak max-age"
                        suspicious_count += 2
                    elif 'includeSubDomains' not in header_value:
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Missing includeSubDomains"
                        suspicious_count += 1

                elif header_name == 'X-Frame-Options':
                    if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Weak configuration ({header_value})"
                        suspicious_count += 2

                elif header_name == 'Content-Security-Policy':
                    if "default-src 'none'" not in header_value and len(header_value.split()) < 5:  # Basic restrictiveness check
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Appears too permissive"
                        suspicious_count += 1

                elif header_name == 'X-Content-Type-Options':
                    if header_value.lower() != 'nosniff':
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Should be nosniff"
                        suspicious_count += 1

                elif header_name == 'Referrer-Policy':
                    restrictive_policies = ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin']
                    if header_value not in restrictive_policies:
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Not restrictive ({header_value})"
                        suspicious_count += 1

                elif header_name == 'Permissions-Policy':
                    if len(header_value.split(',')) < 3:  # Basic check for limited features
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Should limit more features"
                        suspicious_count += 1

                elif header_name == 'X-XSS-Protection':
                    if header_value != '1; mode=block':
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Should be 1; mode=block"
                        suspicious_count += 1

                elif header_name == 'Cross-Origin-Opener-Policy':
                    if header_value != 'same-origin':
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Should be same-origin"
                        suspicious_count += 1

                elif header_name == 'Cross-Origin-Resource-Policy':
                    if header_value != 'same-origin':
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Should be same-origin"
                        suspicious_count += 1

                elif header_name == 'Cross-Origin-Embedder-Policy':
                    if header_value != 'require-corp':
                        status = 'weak'
                        status_icon = '⚠️'
                        message = f"{header_info['purpose']}: Should be require-corp"
                        suspicious_count += 1
            else:
                # Header missing
                if header_info['importance'] == 'Critical':
                    message = f"{header_info['purpose']}: Missing (Critical)"
                    suspicious_count += 3
                elif header_info['importance'] == 'High':
                    message = f"{header_info['purpose']}: Missing (High)"
                    suspicious_count += 2
                else:
                    message = f"{header_info['purpose']}: Missing"
                    suspicious_count += 1

            findings.append(f"{status_icon} {message}")
            header_analysis[header_name] = {
                'status': status,
                'status_icon': status_icon,
                'value': header_value,
                'purpose': header_info['purpose'],
                'what_to_check': header_info['what_to_check'],
                'example': header_info['example']
            }

        # Additional checks
        if not url.startswith('https://'):
            findings.append("❌ Site does not use HTTPS encryption")
            suspicious_count += 2

        # Check for insecure cookies
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie and 'secure' not in set_cookie.lower():
            findings.append("⚠️ Cookies are not marked as secure")
            suspicious_count += 1

    except requests.exceptions.HTTPError as e:
        if hasattr(e, 'response') and e.response:
            status_code = e.response.status_code
            if status_code == 403:
                findings.append("❌ Server returned 403 Forbidden - The website is blocking automated requests or requires authentication")
            elif status_code == 401:
                findings.append("❌ Server returned 401 Unauthorized - Authentication is required to access this page")
            else:
                findings.append(f"❌ Server returned HTTP {status_code} error")
            suspicious_count += 1
        else:
            findings.append(f"❌ HTTP error: {str(e)[:100]}...")
            suspicious_count += 1
        header_analysis = {"error": "Failed to retrieve headers due to HTTP error"}

    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        if len(error_msg) > 100:
            error_msg = error_msg[:100] + "..."
        findings.append(f"❌ Network error: {error_msg}")
        suspicious_count += 1
        header_analysis = {"error": "Failed to retrieve headers due to network issue"}

    # Calculate risk level based on findings
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

    # If no issues found
    if all('✅' in f for f in findings):
        findings = ["✅ All security headers are properly configured"]

    return {
        "url": url,
        "risk_level": risk_level,
        "suspicious_count": suspicious_count,
        "findings": findings,
        "header_analysis": header_analysis,
        "response_code": response.status_code if 'response' in locals() else None
    }
