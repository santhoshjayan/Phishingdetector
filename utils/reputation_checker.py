"""
Reputation Checker Module

Checks domain reputation using various services and APIs.
"""

import requests
import tldextract
import logging
import time
import os
import random
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Rate limiting parameters
RATE_LIMIT_DELAY = 1  # Seconds between requests


def check_domain_blacklists(domain):
    """
    Check if domain is in any DNS blacklists
    
    Args:
        domain (str): The domain to check
        
    Returns:
        list: Blacklists that the domain is found in
    """
    blacklists = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "spam.dnsbl.sorbs.net"
    ]
    
    found_in = []
    try:
        ip = socket.gethostbyname(domain)
        
        # Reverse the IP for checking against blacklists
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for blacklist in blacklists:
            try:
                # Try to resolve the domain in the blacklist
                check_domain = f"{reversed_ip}.{blacklist}"
                socket.gethostbyname(check_domain)
                found_in.append(blacklist)
            except socket.error:
                # Not in this blacklist
                pass
                
            # Sleep briefly to avoid overwhelming DNS servers
            time.sleep(0.1)
            
    except socket.error:
        logger.warning(f"Could not resolve domain {domain}")
    
    return found_in


def check_dns_records(domain):
    """
    Check if the domain has valid DNS records
    
    Args:
        domain (str): The domain to check
        
    Returns:
        bool: True if the domain has valid DNS records
    """
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False


def check_domain_reputation(url):
    """
    Check the reputation of a domain using various methods
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Reputation information
    """
    findings = []
    suspicious_count = 0
    
    # Extract domain
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    
    # Check if domain resolves (has valid DNS)
    if not check_dns_records(domain):
        findings.append("Domain does not have valid DNS records")
        suspicious_count += 1
    
    # Check if the domain is in any DNS blacklists
    blacklists = check_domain_blacklists(domain)
    if blacklists:
        findings.append(f"Domain is listed in DNS blacklists: {', '.join(blacklists)}")
        suspicious_count += len(blacklists)
    
    # Check if the domain has a valid SSL certificate
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        try:
            response = requests.get(url, timeout=5, verify=True)
        except requests.exceptions.SSLError:
            findings.append("Domain has an invalid SSL certificate")
            suspicious_count += 1
        except requests.exceptions.RequestException:
            findings.append("Unable to verify SSL certificate")
    
    # Perform a basic connection test
    try:
        start_time = time.time()
        response = requests.head(url, timeout=5, allow_redirects=True)
        response_time = time.time() - start_time
        
        # Check for excessive redirects
        if len(response.history) > 2:
            findings.append(f"URL has {len(response.history)} redirects")
            suspicious_count += 1
        
        # Check for unusual HTTP status codes
        if response.status_code >= 400:
            findings.append(f"URL returns HTTP error code: {response.status_code}")
            suspicious_count += 1
        
        # Check for unusual server headers
        server = response.headers.get('Server', '')
        if server and 'nginx' not in server.lower() and 'apache' not in server.lower() and 'iis' not in server.lower():
            findings.append(f"Unusual server software: {server}")
            suspicious_count += 1
        
        # Check for unusually slow response time
        if response_time > 2.0:  # More than 2 seconds
            findings.append(f"Website has slow response time: {response_time:.2f} seconds")
            suspicious_count += 1
            
    except requests.exceptions.RequestException as e:
        findings.append(f"Error connecting to website: {str(e)}")
        suspicious_count += 1
    
    # Attempt to check website content
    try:
        response = requests.get(url, timeout=5)
        content = response.text.lower()
        
        # Check for suspicious content patterns
        suspicious_patterns = [
            'password', 'credit card', 'sign in', 'login', 'credential',
            'verify your account', 'confirm your account', 'security alert',
            'update your information', 'payment information'
        ]
        
        found_patterns = [pattern for pattern in suspicious_patterns if pattern in content]
        if found_patterns:
            findings.append(f"Website contains sensitive terms: {', '.join(found_patterns)}")
            suspicious_count += 1
            
        # Check if page has a form that might be collecting information
        if '<form' in content and ('password' in content or 'login' in content):
            findings.append("Website contains a login or password form")
            suspicious_count += 1
            
    except requests.exceptions.RequestException:
        findings.append("Could not analyze website content")
    
    # If no suspicious findings
    if not findings:
        findings.append("No suspicious reputation indicators detected")
    
    return {
        "domain": domain,
        "suspicious_count": suspicious_count,
        "findings": findings
    }
