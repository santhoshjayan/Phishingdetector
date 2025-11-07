"""
SSL/TLS & HTTPS Validation Module

Comprehensive SSL/TLS certificate and HTTPS security validation for phishing detection.
Checks certificate validity, TLS versions, cipher suites, HTTPS enforcement, and mixed content.
"""

import ssl
import socket
import requests
import logging
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from bs4 import BeautifulSoup
import time

logger = logging.getLogger(__name__)


def check_https_redirect(url, timeout=10):
    """
    Check if HTTP URL redirects to HTTPS

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        dict: HTTPS redirect analysis
    """
    parsed = urlparse(url)
    result = {
        'https_enforced': False,
        'redirects_to_https': False,
        'final_url': url,
        'redirect_chain': []
    }

    # Only check HTTP URLs for redirect enforcement
    if parsed.scheme != 'http':
        result['https_enforced'] = True  # HTTPS URLs are already secure
        return result

    try:
        # Try HTTP first
        http_url = url
        response = requests.get(http_url, timeout=timeout, allow_redirects=True, verify=False)

        result['final_url'] = response.url
        result['redirect_chain'] = [r.url for r in response.history] + [response.url]

        # Check if final URL is HTTPS
        if urlparse(response.url).scheme == 'https':
            result['redirects_to_https'] = True
            result['https_enforced'] = True
        else:
            result['https_enforced'] = False

    except requests.exceptions.RequestException as e:
        logger.warning(f"Error checking HTTPS redirect for {url}: {str(e)}")
        result['error'] = str(e)

    return result


def get_ssl_certificate_info(hostname, port=443, timeout=10):
    """
    Retrieve detailed SSL certificate information

    Args:
        hostname (str): The hostname to check
        port (int): SSL port (default 443)
        timeout (int): Connection timeout in seconds

    Returns:
        dict: Certificate information
    """
    cert_info = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'not_before': None,
        'not_after': None,
        'days_until_expiry': None,
        'expired': False,
        'self_signed': False,
        'error': None
    }

    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    cert_info['valid'] = True

                    # Extract certificate details
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))

                    cert_info['issuer'] = issuer.get('organizationName', 'Unknown')
                    cert_info['subject'] = subject.get('commonName', hostname)

                    # Certificate dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                    cert_info['not_before'] = not_before.isoformat()
                    cert_info['not_after'] = not_after.isoformat()

                    # Calculate days until expiry
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    days_until_expiry = (not_after - now).days
                    cert_info['days_until_expiry'] = days_until_expiry
                    cert_info['expired'] = days_until_expiry < 0

                    # Check if self-signed (issuer == subject)
                    cert_info['self_signed'] = (cert_info['issuer'] == cert_info['subject'])

    except ssl.SSLError as e:
        cert_info['error'] = f"SSL Error: {str(e)}"
    except socket.error as e:
        cert_info['error'] = f"Connection Error: {str(e)}"
    except Exception as e:
        cert_info['error'] = f"Certificate Error: {str(e)}"

    return cert_info


def check_tls_versions(hostname, port=443, timeout=10):
    """
    Check supported TLS versions

    Args:
        hostname (str): The hostname to check
        port (int): SSL port (default 443)

    Returns:
        dict: TLS version support information
    """
    tls_versions = {
        'TLSv1.0': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        'TLSv1.3': ssl.PROTOCOL_TLS
    }

    supported_versions = []
    weak_versions = []

    for version_name, protocol in tls_versions.items():
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported_versions.append(version_name)

                    # Mark weak versions
                    if version_name in ['TLSv1.0', 'TLSv1.1']:
                        weak_versions.append(version_name)

        except (ssl.SSLError, socket.error, OSError):
            continue

    return {
        'supported_versions': supported_versions,
        'weak_versions': weak_versions,
        'tls_1_2_or_higher': any(v in ['TLSv1.2', 'TLSv1.3'] for v in supported_versions),
        'has_weak_versions': len(weak_versions) > 0
    }


def check_cipher_suites(hostname, port=443, timeout=10):
    """
    Analyze SSL/TLS cipher suites

    Args:
        hostname (str): The hostname to check
        port (int): SSL port (default 443)

    Returns:
        dict: Cipher suite analysis
    """
    weak_ciphers = [
        'RC4', 'DES', '3DES', 'MD5', 'SHA', 'SHA1',
        'NULL', 'EXPORT', 'anon'
    ]

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else 'Unknown'

                # Check for weak ciphers
                has_weak_cipher = any(weak in cipher_name.upper() for weak in weak_ciphers)

                return {
                    'cipher_suite': cipher_name,
                    'has_weak_cipher': has_weak_cipher,
                    'protocol': cipher[1] if len(cipher) > 1 else 'Unknown',
                    'key_size': cipher[2] if len(cipher) > 2 else 'Unknown'
                }

    except Exception as e:
        return {
            'cipher_suite': 'Unable to determine',
            'has_weak_cipher': True,
            'protocol': 'Unknown',
            'key_size': 'Unknown',
            'error': str(e)
        }


def check_mixed_content(url, timeout=10):
    """
    Check for mixed content (HTTP resources on HTTPS pages)

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        dict: Mixed content analysis
    """
    mixed_content = {
        'has_mixed_content': False,
        'http_resources': [],
        'total_resources': 0,
        'mixed_percentage': 0.0
    }

    if not url.startswith('https://'):
        return mixed_content

    try:
        response = requests.get(url, timeout=timeout, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all resources that could be loaded over HTTP
        resource_tags = [
            ('script', 'src'),
            ('link', 'href'),
            ('img', 'src'),
            ('iframe', 'src'),
            ('source', 'src'),
            ('video', 'src'),
            ('audio', 'src')
        ]

        http_resources = []

        for tag_name, attr in resource_tags:
            elements = soup.find_all(tag_name, {attr: True})
            for element in elements:
                resource_url = element[attr]
                if resource_url.startswith('http://'):
                    http_resources.append({
                        'url': resource_url,
                        'tag': tag_name,
                        'type': 'direct_http'
                    })
                elif not resource_url.startswith(('https://', '//', 'data:')):
                    # Relative URL - check if it would be HTTP
                    full_url = urljoin(url, resource_url)
                    if full_url.startswith('http://'):
                        http_resources.append({
                            'url': full_url,
                            'tag': tag_name,
                            'type': 'relative_http'
                        })

        mixed_content['http_resources'] = http_resources
        mixed_content['has_mixed_content'] = len(http_resources) > 0
        mixed_content['total_resources'] = len(http_resources)

    except requests.exceptions.RequestException as e:
        mixed_content['error'] = str(e)

    return mixed_content


def validate_ssl_tls_security(url, timeout=15):
    """
    Comprehensive SSL/TLS and HTTPS validation

    Args:
        url (str): The URL to validate
        timeout (int): Request timeout in seconds

    Returns:
        dict: Complete SSL/TLS security analysis
    """
    findings = []
    suspicious_count = 0
    vulnerabilities = {}

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "url": url,
            "risk_level": "Unknown",
            "suspicious_count": 1,
            "findings": ["Invalid URL - no hostname found"],
            "vulnerabilities": {"error": "Invalid hostname"}
        }

    # 1. Check HTTPS enforcement
    https_redirect = check_https_redirect(url, timeout)
    if parsed.scheme == 'http':
        if https_redirect['https_enforced']:
            findings.append("✅ HTTP URL properly redirects to HTTPS")
        else:
            findings.append("❌ HTTP URL does not redirect to HTTPS")
            vulnerabilities['no_https_redirect'] = {
                'severity': 'High',
                'description': 'HTTP URLs should redirect to HTTPS for security'
            }
            suspicious_count += 2
    else:
        findings.append("✅ URL uses HTTPS")

    # 2. SSL Certificate validation
    cert_info = get_ssl_certificate_info(hostname, 443, timeout)

    if cert_info['valid']:
        findings.append("✅ SSL certificate is valid")

        # Check expiry
        if cert_info['expired']:
            findings.append("❌ SSL certificate has expired")
            vulnerabilities['expired_certificate'] = {
                'severity': 'High',
                'description': 'SSL certificate has expired',
                'days_overdue': abs(cert_info['days_until_expiry'])
            }
            suspicious_count += 3
        elif cert_info['days_until_expiry'] < 30:
            findings.append(f"⚠️ SSL certificate expires soon ({cert_info['days_until_expiry']} days)")
            vulnerabilities['certificate_expiring_soon'] = {
                'severity': 'Medium',
                'description': f'Certificate expires in {cert_info["days_until_expiry"]} days'
            }
            suspicious_count += 1
        else:
            findings.append(f"✅ SSL certificate expires in {cert_info['days_until_expiry']} days")

        # Check if self-signed
        if cert_info['self_signed']:
            findings.append("⚠️ SSL certificate appears to be self-signed")
            vulnerabilities['self_signed_certificate'] = {
                'severity': 'Medium',
                'description': 'Self-signed certificates are not trusted by browsers'
            }
            suspicious_count += 2

    else:
        findings.append("❌ SSL certificate validation failed")
        if cert_info['error']:
            findings.append(f"   Error: {cert_info['error']}")
        vulnerabilities['invalid_certificate'] = {
            'severity': 'High',
            'description': 'SSL certificate is invalid or untrusted'
        }
        suspicious_count += 3

    # 3. TLS Version check
    tls_info = check_tls_versions(hostname, 443, timeout)

    if tls_info['tls_1_2_or_higher']:
        findings.append("✅ Supports TLS 1.2 or higher")
    else:
        findings.append("❌ Does not support TLS 1.2 or higher")
        vulnerabilities['weak_tls_versions'] = {
            'severity': 'High',
            'description': 'Server does not support modern TLS versions'
        }
        suspicious_count += 3

    if tls_info['has_weak_versions']:
        findings.append(f"⚠️ Supports weak TLS versions: {', '.join(tls_info['weak_versions'])}")
        vulnerabilities['deprecated_tls'] = {
            'severity': 'Medium',
            'description': f'Server supports deprecated TLS versions: {tls_info["weak_versions"]}'
        }
        suspicious_count += 2

    # 4. Cipher suite analysis
    cipher_info = check_cipher_suites(hostname, 443, timeout)

    if not cipher_info['has_weak_cipher']:
        findings.append(f"✅ Uses secure cipher suite: {cipher_info['cipher_suite']}")
    else:
        findings.append(f"❌ Uses weak cipher suite: {cipher_info['cipher_suite']}")
        vulnerabilities['weak_cipher'] = {
            'severity': 'Medium',
            'description': f'Server uses weak cipher: {cipher_info["cipher_suite"]}'
        }
        suspicious_count += 2

    # 5. HSTS Header check
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        hsts_header = response.headers.get('Strict-Transport-Security')

        if hsts_header:
            findings.append("✅ HSTS header is present")
        else:
            findings.append("⚠️ HSTS header is missing")
            vulnerabilities['missing_hsts'] = {
                'severity': 'Medium',
                'description': 'Strict-Transport-Security header should be present for HTTPS sites'
            }
            suspicious_count += 1

    except requests.exceptions.RequestException:
        findings.append("⚠️ Could not check HSTS header")

    # 6. Mixed content check
    mixed_content = check_mixed_content(url, timeout)

    if not mixed_content['has_mixed_content']:
        findings.append("✅ No mixed content detected")
    else:
        findings.append(f"❌ Mixed content detected: {mixed_content['total_resources']} HTTP resources on HTTPS page")
        vulnerabilities['mixed_content'] = {
            'severity': 'Medium',
            'description': f'HTTPS page loads {mixed_content["total_resources"]} resources over HTTP',
            'resources': mixed_content['http_resources'][:5]  # Limit output
        }
        suspicious_count += 2

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

    # If no issues found
    if not any('❌' in f or '⚠️' in f for f in findings):
        findings = ["✅ All SSL/TLS security checks passed"]

    return {
        "url": url,
        "risk_level": risk_level,
        "suspicious_count": suspicious_count,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "certificate_info": cert_info,
        "tls_info": tls_info,
        "cipher_info": cipher_info,
        "https_redirect": https_redirect,
        "mixed_content": mixed_content
    }
