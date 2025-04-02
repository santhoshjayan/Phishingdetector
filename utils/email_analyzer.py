"""
Email Analyzer Module

Analyzes email content and headers for potential phishing indicators.
"""

import re
import logging
from datetime import datetime
import tldextract
from email_validator import validate_email, EmailNotValidError

logger = logging.getLogger(__name__)

# Keywords commonly found in phishing emails
PHISHING_KEYWORDS = [
    "urgent", "verify", "account", "suspend", "password", "update",
    "bank", "security", "alert", "restricted", "confirm", "click",
    "log in", "credential", "authorize", "unusual activity", "access",
    "reset", "upgrade", "activate", "deactivate", "validate", "expired",
    "fraud", "identity", "payment", "invoice", "statement", "lottery",
    "inheritance", "claim", "prize", "offer", "winner", "verify your identity",
    "disable"
]

# Common phishing tactic patterns
PHISHING_PATTERNS = [
    r"(?i)verify your (?:account|login|details|identity|credentials)",
    r"(?i)update (?:your|account) details",
    r"(?i)confirm (?:your|account) (?:details|information)",
    r"(?i)suspicious (?:activity|login|attempt|transaction)",
    r"(?i)account (?:suspended|blocked|locked|limited)",
    r"(?i)click (?:here|to|below) to (?:verify|confirm|validate)",
    r"(?i)security (?:alert|notice|update|breach)",
    r"(?i)password (?:expired|reset)",
    r"(?i)\bsecured by\b(?!.*\b(?:https|ssl)\b)", # Claims to be secure but isn't HTTPS
    r"(?i)\blimited time\b"
]

def is_valid_email(email):
    """
    Check if the email has a valid format
    
    Args:
        email (str): The email address to validate
        
    Returns:
        bool: True if the email has a valid format
    """
    try:
        validation = validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

def check_sender_domain(sender_email):
    """
    Check the sender domain for suspicious patterns
    
    Args:
        sender_email (str): The sender's email address
        
    Returns:
        dict: Analysis results with any suspicious findings
    """
    findings = []
    suspicious = False
    
    # Extract domain from email
    if '@' not in sender_email:
        findings.append("Sender email is in an invalid format (missing @)")
        return {"suspicious": True, "findings": findings}
    
    domain = sender_email.split('@')[1]
    extract = tldextract.extract(domain)
    
    # Check for suspicious domain patterns
    if len(extract.domain) >= 20:
        findings.append(f"Suspiciously long domain name: {domain}")
        suspicious = True
    
    if extract.domain.isdigit():
        findings.append(f"Domain consists only of numbers: {domain}")
        suspicious = True
    
    if re.search(r'\d{4,}', extract.domain):
        findings.append(f"Domain contains a long numeric string: {domain}")
        suspicious = True
    
    if extract.domain.count('-') > 2:
        findings.append(f"Domain contains many hyphens: {domain}")
        suspicious = True
    
    if extract.domain[0] == '-' or extract.domain[-1] == '-':
        findings.append(f"Domain starts or ends with a hyphen: {domain}")
        suspicious = True
    
    # Check for randomized or auto-generated domain patterns
    consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', extract.domain)
    if consonant_clusters:
        findings.append(f"Domain contains unusual consonant clusters: {domain}")
        suspicious = True
    
    # Check for lookalike domain tactics (e.g., paypa1.com instead of paypal.com)
    if re.search(r'[a-z][0-9]|[0-9][a-z]', extract.domain):
        findings.append(f"Domain may be using lookalike tactics (mixing letters and numbers): {domain}")
        suspicious = True
    
    return {
        "suspicious": suspicious,
        "findings": findings
    }

def check_email_headers(headers):
    """
    Analyze email headers for suspicious indicators
    
    Args:
        headers (dict): The email headers to analyze
        
    Returns:
        dict: Analysis results
    """
    findings = []
    suspicious = False
    
    # Check for mismatched or suspicious From/Reply-To
    from_header = headers.get('from', '').lower()
    reply_to = headers.get('reply-to', '').lower()
    
    if from_header and reply_to and '@' in from_header and '@' in reply_to:
        from_domain = from_header.split('@')[1]
        reply_domain = reply_to.split('@')[1]
        
        if from_domain != reply_domain:
            findings.append(f"Mismatched From ({from_header}) and Reply-To ({reply_to}) domains")
            suspicious = True
    
    # Check if Return-Path doesn't match From
    return_path = headers.get('return-path', '').lower()
    if from_header and return_path and '@' in from_header and '@' in return_path:
        if from_header.split('@')[1] != return_path.split('@')[1]:
            findings.append(f"Return-Path domain ({return_path}) doesn't match From domain ({from_header})")
            suspicious = True
    
    # Check for suspicious X-Mailer headers
    mailer = headers.get('x-mailer', '').lower()
    suspicious_mailers = [
        'phishing', 'hack', 'exploit', 'spoof', 'mass mail', 'bulk mail'
    ]
    for s_mailer in suspicious_mailers:
        if s_mailer in mailer:
            findings.append(f"Suspicious X-Mailer header: {mailer}")
            suspicious = True
            break
    
    # Check for missing or suspicious Message-ID
    message_id = headers.get('message-id', '')
    if not message_id:
        findings.append("Missing Message-ID header")
        suspicious = True
    
    # Check for unusual User-Agent
    user_agent = headers.get('user-agent', '').lower()
    if user_agent and ('curl' in user_agent or 'script' in user_agent or 'bot' in user_agent):
        findings.append(f"Suspicious User-Agent: {user_agent}")
        suspicious = True
    
    return {
        "suspicious": suspicious,
        "findings": findings
    }

def analyze_email_content(content):
    """
    Analyze email content for phishing indicators
    
    Args:
        content (str): The email content to analyze
        
    Returns:
        dict: Analysis results
    """
    findings = []
    suspicious = False
    
    # Check for phishing keywords in content
    keyword_count = 0
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', content, re.IGNORECASE):
            keyword_count += 1
            found_keywords.append(keyword)
    
    if keyword_count >= 3:
        findings.append(f"Contains multiple phishing keywords: {', '.join(found_keywords[:5])}" + 
                      (f" and {keyword_count - 5} more" if keyword_count > 5 else ""))
        suspicious = True
    
    # Check for phishing patterns
    pattern_matches = []
    for pattern in PHISHING_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            pattern_matches.extend(matches[:2])  # Limit to first 2 matches per pattern
    
    if pattern_matches:
        findings.append(f"Contains phishing patterns: {', '.join(pattern_matches[:3])}" +
                      (f" and {len(pattern_matches) - 3} more" if len(pattern_matches) > 3 else ""))
        suspicious = True
    
    # Check for urgent language
    urgency_patterns = [
        r'(?i)urgent\b', 
        r'(?i)immediate\b', 
        r'(?i)important\b', 
        r'(?i)attention\b', 
        r'(?i)action required\b',
        r'(?i)expires\b',
        r'(?i)deadline\b',
        r'(?i)limited time\b',
        r'(?i)act now\b'
    ]
    
    urgency_count = sum(1 for pattern in urgency_patterns if re.search(pattern, content))
    if urgency_count >= 2:
        findings.append("Uses urgent or time-pressure language")
        suspicious = True
    
    # Check for threats or consequences
    threat_patterns = [
        r'(?i)account.*(?:suspend|close|terminate|restrict)',
        r'(?i)(?:suspend|close|terminate|restrict).*account',
        r'(?i)access.*(?:denied|blocked|restricted)',
        r'(?i)(?:avoid|prevent).*(?:suspension|termination)',
        r'(?i)failure to',
        r'(?i)will result in',
        r'(?i)consequences'
    ]
    
    threat_count = sum(1 for pattern in threat_patterns if re.search(pattern, content))
    if threat_count >= 1:
        findings.append("Contains threatening language or consequences")
        suspicious = True
    
    # Check for unusual URLs or redirects
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
    
    display_urls = []
    shortened_urls = []
    for url in urls:
        # Check for URL masking with different display and actual URLs
        display_url_pattern = r'(?i)<a[^>]*href=[\'"](https?://[^\'">]+)[\'"][^>]*>(https?://[^<]+|[^<]{2,}\.(?:com|org|net|edu|gov|biz))</a>'
        display_url_matches = re.findall(display_url_pattern, content)
        
        for match in display_url_matches:
            actual_url, displayed_url = match
            if displayed_url.startswith('http') and actual_url != displayed_url:
                display_urls.append((displayed_url, actual_url))
                suspicious = True
        
        # Check for URL shorteners
        shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'tiny.cc', 'lnkd.in', 'sho.rt']
        for domain in shortener_domains:
            if domain in url:
                shortened_urls.append(url)
                break
    
    if display_urls:
        findings.append(f"URL masking found - displayed URLs differ from actual URLs: {display_urls[:2]}" +
                      (f" and {len(display_urls) - 2} more" if len(display_urls) > 2 else ""))
    
    if shortened_urls:
        findings.append(f"Uses URL shorteners: {shortened_urls[:2]}" +
                      (f" and {len(shortened_urls) - 2} more" if len(shortened_urls) > 2 else ""))
        suspicious = True
    
    # Check for requests for personal/sensitive information
    info_request_patterns = [
        r'(?i)(?:enter|confirm|verify|update|provide).*(?:password|username|login|account|credit card|ssn|social security|credentials)',
        r'(?i)(?:password|username|login|account|credit card|ssn|social security|credentials).*(?:enter|confirm|verify|update|provide)',
        r'(?i)verification.*(?:form|details|information|process)',
        r'(?i)security.*(?:check|verify|confirm|update)'
    ]
    
    info_request_count = sum(1 for pattern in info_request_patterns if re.search(pattern, content))
    if info_request_count >= 1:
        findings.append("Requests sensitive personal information")
        suspicious = True
    
    return {
        "suspicious": suspicious,
        "suspicious_score": keyword_count + len(pattern_matches) + urgency_count + threat_count + len(display_urls) + len(shortened_urls) + info_request_count,
        "findings": findings
    }

def analyze_email(email_data):
    """
    Analyze an email for phishing indicators
    
    Args:
        email_data (dict): The email data containing 'from', 'headers', and 'content'
        
    Returns:
        dict: Comprehensive analysis results
    """
    sender = email_data.get('from', '')
    subject = email_data.get('subject', '')
    headers = email_data.get('headers', {})
    content = email_data.get('content', '')
    
    # Initialize results
    results = {
        'email': sender,
        'subject': subject,
        'risk_level': 'Unknown',
        'suspicious_indicators': 0,
        'sender_analysis': {},
        'header_analysis': {},
        'content_analysis': {},
        'findings': [],
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    try:
        # Validate sender email format
        valid_email = is_valid_email(sender) if sender else False
        if not valid_email and sender:
            results['findings'].append("Invalid sender email format")
            results['suspicious_indicators'] += 1
        
        # Analyze sender domain
        if sender:
            sender_analysis = check_sender_domain(sender)
            results['sender_analysis'] = sender_analysis
            
            if sender_analysis['suspicious']:
                results['findings'].extend(sender_analysis['findings'])
                results['suspicious_indicators'] += len(sender_analysis['findings'])
        
        # Analyze headers
        if headers:
            header_analysis = check_email_headers(headers)
            results['header_analysis'] = header_analysis
            
            if header_analysis['suspicious']:
                results['findings'].extend(header_analysis['findings'])
                results['suspicious_indicators'] += len(header_analysis['findings'])
        
        # Analyze content
        if content:
            content_analysis = analyze_email_content(content)
            results['content_analysis'] = content_analysis
            
            if content_analysis['suspicious']:
                results['findings'].extend(content_analysis['findings'])
                results['suspicious_indicators'] += content_analysis['suspicious_score']
        
        # Determine risk level
        if results['suspicious_indicators'] >= 7:
            results['risk_level'] = 'High'
        elif results['suspicious_indicators'] >= 4:
            results['risk_level'] = 'Medium'
        elif results['suspicious_indicators'] >= 2:
            results['risk_level'] = 'Low'
        elif results['suspicious_indicators'] > 0:
            results['risk_level'] = 'Very Low'
        else:
            results['risk_level'] = 'Safe'
            
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}")
        results['error'] = str(e)
    
    return results