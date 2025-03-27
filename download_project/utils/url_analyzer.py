"""
URL Analyzer Module

Analyzes URLs for suspicious patterns commonly found in phishing attacks.
"""

import re
import tldextract
from urllib.parse import urlparse, unquote


def analyze_url_patterns(url):
    """
    Analyze URL for suspicious patterns that might indicate phishing
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Analysis results with suspicious patterns found
    """
    findings = []
    suspicious_count = 0
    
    # Decode URL to catch any encoded characters
    decoded_url = unquote(url)
    
    # Extract domain information
    parsed_url = urlparse(decoded_url)
    domain_info = tldextract.extract(decoded_url)
    domain = domain_info.domain
    suffix = domain_info.suffix
    subdomain = domain_info.subdomain
    full_domain = f"{domain}.{suffix}"
    
    # Check for IP address in domain
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    if re.match(ip_pattern, parsed_url.netloc):
        findings.append("URL uses an IP address instead of a domain name")
        suspicious_count += 1
    
    # Check for excessive subdomains (potential for confusion)
    if subdomain and len(subdomain.split('.')) > 2:
        findings.append("URL contains multiple subdomains which can be confusing")
        suspicious_count += 1
    
    # Check for suspicious TLDs
    suspicious_tlds = ["xyz", "top", "club", "online", "site", "tk", "ml", "ga", "cf", "gq"]
    if suffix in suspicious_tlds:
        findings.append(f"URL uses a potentially suspicious TLD: .{suffix}")
        suspicious_count += 1
    
    # Check for misleading domain names (common brands)
    common_brands = [
        "google", "microsoft", "apple", "amazon", "facebook", "instagram",
        "paypal", "netflix", "gmail", "outlook", "yahoo", "chase", "bank",
        "wellsfargo", "amex", "visa", "mastercard", "bitcoin"
    ]
    
    for brand in common_brands:
        if brand in domain and brand != domain:
            findings.append(f"Domain contains a well-known brand '{brand}' but is not the official domain")
            suspicious_count += 1
            break
    
    # Check for presence of suspicious terms in the URL
    suspicious_terms = [
        "login", "signin", "verify", "secure", "account", "update", "confirm",
        "banking", "auth", "authenticate", "password", "credential", "wallet",
        "recover", "support", "help", "security"
    ]
    
    for term in suspicious_terms:
        if term in decoded_url.lower():
            findings.append(f"URL contains potentially suspicious term: '{term}'")
            suspicious_count += 1
    
    # Check for excessive use of hyphens in domain (often seen in phishing)
    if domain.count('-') > 2:
        findings.append("Domain contains excessive hyphens")
        suspicious_count += 1
    
    # Check for URL shorteners
    url_shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cli.gs", "ow.ly",
        "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "tr.im", "twit.ac",
        "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm"
    ]
    
    if any(shortener in decoded_url for shortener in url_shorteners):
        findings.append("URL appears to be using a URL shortening service")
        suspicious_count += 1
    
    # Check for URL redirects by examining query parameters
    redirect_params = ["url=", "redirect=", "link=", "goto=", "return=", "returnTo=", "return_to="]
    for param in redirect_params:
        if param in decoded_url:
            findings.append(f"URL contains potential redirect parameter: {param}")
            suspicious_count += 1
    
    # Check for excessive use of special characters in the URL path
    path = parsed_url.path
    if path.count('@') > 0 or path.count('~') > 1:
        findings.append("URL path contains unusual special characters")
        suspicious_count += 1
    
    # Check for use of hostname in unusual locations
    if '@' in parsed_url.netloc:
        findings.append("URL contains @ symbol in domain part (potential attempt to obfuscate real domain)")
        suspicious_count += 1
    
    # Check for use of HTTPS with suspicious domain
    if parsed_url.scheme == "https" and (suspicious_count > 2):
        findings.append("URL uses HTTPS but has multiple suspicious characteristics (potential to appear trustworthy)")
        suspicious_count += 1
    
    # If no suspicious patterns found
    if not findings:
        findings.append("No suspicious URL patterns detected")
    
    return {
        "suspicious_count": suspicious_count,
        "findings": findings
    }
