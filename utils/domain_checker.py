"""
Domain Checker Module

Provides domain registration information and checks against a list of known
phishing domains.
"""

import os
import whois
import tldextract
import datetime
import logging

logger = logging.getLogger(__name__)

# Path to known phishing domains list
PHISHING_DOMAINS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                     "data", "known_phishing_domains.txt")


def load_known_phishing_domains():
    """
    Load the list of known phishing domains from the data file
    
    Returns:
        list: List of known phishing domains
    """
    known_domains = []
    try:
        if os.path.exists(PHISHING_DOMAINS_FILE):
            with open(PHISHING_DOMAINS_FILE, 'r') as f:
                known_domains = [line.strip().lower() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error loading known phishing domains: {str(e)}")
    
    # Add some default domains if the file is empty or doesn't exist
    if not known_domains:
        known_domains = [
            "example-phishing.com",
            "badwebsite.com",
            "phishingsite.net",
            "googls.com",
            "faceboook.com",
            "paypa1.com",
            "micosoft.com",
            "mircosoft.com",
            "microsoftonline.phishing.com",
            "appleid-verify.net"
        ]
    
    return known_domains


def is_domain_new(creation_date, days_threshold=30):
    """
    Check if the domain was created recently
    
    Args:
        creation_date: The domain creation date
        days_threshold (int): Number of days to consider a domain as "new"
        
    Returns:
        bool: True if the domain is newer than the threshold
    """
    if not creation_date:
        return False
        
    # Handle cases where creation_date is a list
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    
    try:
        days_since_creation = (datetime.datetime.now() - creation_date).days
        return days_since_creation <= days_threshold
    except Exception:
        return False


def check_domain_info(url):
    """
    Check domain information for suspicious indicators
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Domain information analysis results
    """
    findings = []
    suspicious_count = 0
    whois_info = {}
    
    # Extract domain
    domain_info = tldextract.extract(url)
    domain_name = f"{domain_info.domain}.{domain_info.suffix}"
    
    # Check against known phishing domains
    known_phishing_domains = load_known_phishing_domains()
    
    if domain_name.lower() in known_phishing_domains:
        findings.append("Domain is in known phishing domains list")
        suspicious_count += 2  # Higher weight for known phishing domains
    
    # Check for similar domains with small variations (typosquatting)
    for known_domain in known_phishing_domains:
        if domain_name.lower() != known_domain and domain_info.domain in known_domain:
            findings.append(f"Domain may be typosquatting a known phishing domain: {known_domain}")
            suspicious_count += 1
            break
    
    # Get WHOIS information
    try:
        domain_whois = whois.whois(domain_name)
        
        # Extract relevant WHOIS information
        whois_info = {
            "registrar": domain_whois.registrar,
            "creation_date": domain_whois.creation_date,
            "expiration_date": domain_whois.expiration_date,
            "country": domain_whois.country,
            "organization": domain_whois.org
        }
        
        # Check if domain is new (less than 30 days old)
        if is_domain_new(domain_whois.creation_date):
            findings.append("Domain was registered within the last 30 days")
            suspicious_count += 1
        
        # Check if domain is set to expire soon
        if domain_whois.expiration_date:
            expiry_date = domain_whois.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
                
            try:
                days_to_expiry = (expiry_date - datetime.datetime.now()).days
                if days_to_expiry < 30:
                    findings.append(f"Domain is set to expire soon (in {days_to_expiry} days)")
                    suspicious_count += 1
            except Exception:
                pass
        
        # Check for missing or private WHOIS information
        if not domain_whois.org and not domain_whois.name:
            findings.append("Domain has privacy protection or missing organization/registrant information")
            suspicious_count += 1
            
    except Exception as e:
        logger.warning(f"Error retrieving WHOIS information for {domain_name}: {str(e)}")
        findings.append("Unable to retrieve WHOIS information")
        whois_info = {"error": "Failed to retrieve WHOIS information"}
    
    # If no suspicious findings detected
    if not findings:
        findings.append("No suspicious domain registration information detected")
    
    return {
        "domain": domain_name,
        "suspicious_count": suspicious_count,
        "findings": findings,
        "whois_info": whois_info
    }
