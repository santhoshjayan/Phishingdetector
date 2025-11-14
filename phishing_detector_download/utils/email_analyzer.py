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
    # Urgency/Action terms
    "urgent", "immediate", "alert", "warning", "attention", "important", 
    "action required", "deadline", "expires", "expiration", "limited time",
    "act now", "respond now", "time-sensitive", "critical", "urgent notice",
    
    # Account-related terms
    "verify", "account", "suspend", "password", "access", "credential", 
    "login", "sign-in", "username", "user ID", "account verification",
    "confirm identity", "security check", "authenticate", "reactivate",
    "unlock", "restricted", "restore access", "disabled", "deactivated",
    "unusual activity", "suspicious login", "unauthorized", "validate",
    "reset", "update", "upgrade", "expired", "disable", "secure",
    
    # Financial/Payment terms
    "bank", "payment", "transaction", "transfer", "deposit", "withdrawal",
    "refund", "reimbursement", "statement", "invoice", "billing", "financial",
    "credit card", "debit card", "wire transfer", "paypal", "e-transfer",
    "direct deposit", "tax", "IRS", "revenue", "fee", "charge", "outstanding",
    
    # Threatening language
    "terminated", "suspended", "breach", "compromised", "fraud", "stolen",
    "identity theft", "penalty", "fine", "legal action", "law enforcement",
    "investigation", "police", "report", "complaint", "violation",
    
    # Enticement terms
    "lottery", "inheritance", "claim", "prize", "offer", "winner", "promotion",
    "discount", "free", "bonus", "gift", "reward", "exclusive", "selected",
    "congratulations", "won", "contest", "sweepstakes", "lucky", "beneficiary",
    
    # Technical terms used to intimidate
    "security protocol", "verification system", "firewall", "encryption",
    "security measure", "malware", "virus", "hack", "system update",
    "maintenance", "server", "technical team", "IT department", "administrator"
]

# Common phishing tactic patterns
PHISHING_PATTERNS = [
    # Account verification/update patterns - frequently used in phishing
    r"(?i)verify your (?:account|login|details|identity|credentials|payment method|banking details)",
    r"(?i)update (?:your|account|payment|billing) (?:details|information|records|data)",
    r"(?i)confirm (?:your|account|personal|identity|payment|banking) (?:details|information|data)",
    r"(?i)(?:unusual|suspicious|unrecognized|unauthorized) (?:activity|login|attempt|transaction|sign-in|access)",
    r"(?i)(?:your|the) account (?:has been|was|is|will be) (?:suspended|blocked|locked|limited|restricted|disabled|compromised)",
    r"(?i)account (?:suspension|termination|deactivation|restriction) (?:notice|warning|alert)",
    r"(?i)(?:click|tap|follow|use) (?:the link|here|this link|below|button) to (?:verify|confirm|validate|update|restore|resolve)",
    r"(?i)(?:urgent|immediate) (?:action|response|attention) (?:required|needed|necessary)",
    
    # Security-related patterns
    r"(?i)security (?:alert|notice|update|breach|issue|problem|concern|incident|procedure|protocol)",
    r"(?i)password (?:expired|reset|changed|compromised|security|update)",
    r"(?i)(?:suspicious|unauthorized|unusual) (?:login|activity|access|attempt) (?:detected|identified|found|reported)",
    r"(?i)system (?:update|upgrade|maintenance|security) (?:required|needed|scheduled|mandatory)",
    r"(?i)\bsecured by\b(?!.*\b(?:https|ssl)\b)", # Claims to be secure but isn't HTTPS
    
    # Time pressure and consequences
    r"(?i)\blimited time\b",
    r"(?i)within (?:24|48|72) hours",
    r"(?i)(?:immediate|urgent|prompt) (?:action|response|attention)",
    r"(?i)(?:failure|failing) to (?:respond|reply|comply|confirm|verify)",
    r"(?i)will (?:result in|lead to|cause) (?:suspension|termination|closing|penalty|restriction)",
    r"(?i)(?:prevent|avoid) (?:suspension|termination|restriction|deactivation|closure)",
    
    # Financial hooks
    r"(?i)(?:outstanding|pending|unprocessed) (?:payment|transaction|transfer|refund)",
    r"(?i)(?:unauthorized|suspicious) (?:charge|transaction|purchase|payment)",
    r"(?i)(?:refund|reimbursement|payment) (?:request|processed|approved|pending)",
    r"(?i)tax (?:refund|return|rebate|credit|payment|filing)",
    r"(?i)(?:inheritance|unclaimed funds|lottery|prize|award) (?:claim|collect|receive)",
    
    # Personal information requests
    r"(?i)(?:update|confirm|verify|provide) (?:your|personal|account) (?:information|details|data)",
    r"(?i)(?:for security|to verify|to confirm) (?:please|kindly|we need) (?:provide|enter|send)",
    r"(?i)(?:SSN|social security|tax ID|passport|license number|date of birth)",
    r"(?i)(?:confirm|update|verify) your (?:name|address|phone|email|contact details)",
    
    # Impersonation indicators
    r"(?i)(?:technical support|customer service|helpdesk|service desk|IT department|security team)",
    r"(?i)(?:official|important|confidential) (?:notice|message|communication|alert|update)",
    r"(?i)(?:on behalf of|representing|from) (?:administration|management|team)",
    
    # Hybrid threats (common modern phishing attack types)
    r"(?i)voice ?mail(?:.*?)(?:attached|listen|hear|play)",
    r"(?i)(?:new|unread) (?:message|notification|fax|document)(?:.*?)(?:view|review|check|access)",
    r"(?i)shared (?:document|file|folder)(?:.*?)(?:access|view|download)",
    r"(?i)invoice(?:.*?)(?:attached|enclosed|review|view|download)",
    
    # Modern phishing patterns - newer tactics and themes
    
    # Videoconferencing impersonation
    r"(?i)(?:zoom|teams|webex|google meet)(?:.*?)(?:invite|invitation|meeting|join|conference|scheduled)",
    r"(?i)missed (?:call|video call|meeting|conference)(?:.*?)(?:join|reschedule|view)",
    
    # Cloud storage attacks
    r"(?i)(?:onedrive|sharepoint|google drive|dropbox|box)(?:.*?)(?:shared|access|document|file)",
    r"(?i)(?:cloud|online|shared) (?:document|spreadsheet|presentation|file)(?:.*?)(?:needs|requires)(?:.*?)(?:attention|review)",
    r"(?i)secure (?:message|document)(?:.*?)(?:portal|platform)",
    
    # Delivery/package notification
    r"(?i)(?:package|shipment|delivery|order|parcel)(?:.*?)(?:delayed|scheduled|rescheduled|waiting|pending)",
    r"(?i)(?:delivery|shipping|tracking) (?:notification|update|status|change)",
    r"(?i)(?:usps|ups|fedex|dhl|amazon)(?:.*?)(?:delivery|package|shipment)(?:.*?)(?:confirm|update|reschedule)",
    
    # COVID/Health themed phishing
    r"(?i)(?:covid|coronavirus|pandemic|vaccine|vaccination)(?:.*?)(?:update|register|appointment|schedule)",
    r"(?i)(?:health|insurance|medical|prescription)(?:.*?)(?:update|notification|coverage|change)",
    r"(?i)(?:test results|medical records|patient portal)(?:.*?)(?:available|ready|access)",
    
    # Job/HR related phishing
    r"(?i)(?:job|employment|position|career|opportunity)(?:.*?)(?:offer|application|interest|interview)",
    r"(?i)(?:human resources|HR|payroll|benefits|salary)(?:.*?)(?:update|notification|change|verify)",
    r"(?i)(?:resume|job application|employment)(?:.*?)(?:received|review|status)",
    
    # Social media/brand impersonation
    r"(?i)(?:instagram|facebook|twitter|linkedin|tiktok)(?:.*?)(?:verify|login|account|suspicious|activity)",
    r"(?i)(?:copyright|trademark|infringement|violation|community)(?:.*?)(?:notice|warning|report)",
    r"(?i)(?:account|profile|page)(?:.*?)(?:restricted|limited|suspended|blocked)(?:.*?)(?:appeal|review)",
    
    # Modern financial schemes
    r"(?i)(?:cryptocurrency|bitcoin|ethereum|wallet|blockchain)(?:.*?)(?:transfer|payment|confirmation|verify)",
    r"(?i)(?:subscription|membership|trial|service)(?:.*?)(?:expires|expired|renewal|renew|cancel)",
    r"(?i)(?:cancelled|failed|declined) (?:transaction|payment|charge)(?:.*?)(?:retry|update)",
    
    # Technical support scams
    r"(?i)(?:antivirus|security|protection)(?:.*?)(?:expired|subscription|renew)",
    r"(?i)(?:computer|device|system|windows|mac)(?:.*?)(?:infected|virus|malware|compromised)",
    r"(?i)(?:technical issue|support ticket|help desk)(?:.*?)(?:opened|created|requires attention)",
    
    # Document based phishing
    r"(?i)(?:docusign|adobe|pdf)(?:.*?)(?:document|file|signature|signed|review)",
    r"(?i)(?:electronic|digital) (?:signature|document|form)(?:.*?)(?:required|pending|awaiting)",
    r"(?i)(?:contract|agreement|proposal|offer|document)(?:.*?)(?:sign|review|approve)",
    
    # Compliance and legal pressure
    r"(?i)(?:terms of service|privacy policy|user agreement)(?:.*?)(?:updated|changed|review)",
    r"(?i)(?:legal|compliance|regulatory|privacy)(?:.*?)(?:notice|update|required|mandatory)",
    r"(?i)(?:gdpr|privacy|data protection)(?:.*?)(?:compliance|regulations|requirements)"
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
    
    # Common trusted domains - banking, government, education, large companies
    trusted_domains = [
        'amazon', 'apple', 'google', 'microsoft', 'facebook', 'twitter', 'instagram',
        'linkedin', 'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citi', 'amex',
        'netflix', 'spotify', 'adobe', 'dropbox', 'github', 'yahoo', 'ebay', 'walmart',
        'target', 'costco', 'fedex', 'ups', 'usps', 'irs.gov', 'gov', 'edu'
    ]
    
    # Phishing-specific detection: Check for lookalike domains
    for trusted in trusted_domains:
        # Skip exact matches (those are legitimate)
        if extract.domain == trusted:
            continue
            
        # Check for typosquatting (character substitution/addition/omission)
        if (trusted in extract.domain and trusted != extract.domain) or \
           (extract.domain in trusted and trusted != extract.domain) or \
           levenshtein_distance(extract.domain, trusted) <= 2:
            findings.append(f"Potential lookalike domain mimicking '{trusted}': {domain}")
            suspicious = True
            break
    
    # Domain age check (new domains are more suspicious - handled in domain_checker.py)
    # We could check against domain creation date here but skip for simplicity

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
    
    # Check for excessive use of hyphens (phishers often use hyphens to create legitimate-looking domains)
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
    
    # Check for character substitution tactics (e.g., paypa1.com instead of paypal.com)
    if re.search(r'[a-z][0-9]|[0-9][a-z]', extract.domain):
        findings.append(f"Domain may be using lookalike tactics (mixing letters and numbers): {domain}")
        suspicious = True
    
    # Check for excessive repeating characters (often in auto-generated domains)
    for char in set(extract.domain):
        if extract.domain.count(char) >= 4 and len(extract.domain) >= 7:
            findings.append(f"Domain contains excessive repeating characters: {domain}")
            suspicious = True
            break
    
    # Check for unusual TLDs (less common TLDs are more often used in phishing)
    unusual_tlds = [
        'xyz', 'top', 'club', 'online', 'site', 'work', 'icu', 'cyou', 'buzz',
        'monster', 'best', 'live', 'world', 'shop', 'store', 'link'
    ]
    
    if extract.suffix in unusual_tlds:
        findings.append(f"Uses a less common TLD (.{extract.suffix}) which is frequently associated with phishing")
        suspicious = True
    
    # Check for alphanumeric or non-letter domain extensions (unusual)
    if re.search(r'[^a-z]', extract.suffix):
        findings.append(f"Domain has an unusual extension (.{extract.suffix}) containing non-alphabetic characters")
        suspicious = True
    
    return {
        "suspicious": suspicious,
        "findings": findings
    }
    
# Helper function for domain similarity comparison
def levenshtein_distance(s1, s2):
    """Calculate the Levenshtein distance between two strings (simple implementation)"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Calculate insertions, deletions and substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

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
    
    # 1. Address Mismatch Checks - Different "From", "Reply-To", "Return-Path" domains
    # A key phishing tactic is having different sender/reply domains
    
    # Get all email addresses from different headers
    from_header = headers.get('from', '').lower()
    reply_to = headers.get('reply-to', '').lower()
    return_path = headers.get('return-path', '').lower()
    sender = headers.get('sender', '').lower()
    
    # Extract email addresses and domains from header fields
    email_domains = {}
    
    for field_name, value in [
        ('From', from_header), 
        ('Reply-To', reply_to), 
        ('Return-Path', return_path),
        ('Sender', sender)
    ]:
        if value and '@' in value:
            try:
                # Extract domain part
                domain = value.split('@')[1].strip('>')
                email_domains[field_name] = domain
            except Exception:
                # Malformed email header
                findings.append(f"Malformed email address in {field_name} header: {value}")
                suspicious = True
    
    # Compare domains - mismatches are suspicious
    if len(email_domains) >= 2:
        mismatched_pairs = []
        
        domains = list(email_domains.items())
        for i in range(len(domains)):
            for j in range(i+1, len(domains)):
                field1, domain1 = domains[i]
                field2, domain2 = domains[j]
                
                if domain1 != domain2:
                    mismatched_pairs.append((field1, field2))
                    suspicious = True
        
        if mismatched_pairs:
            mismatch_text = ", ".join([f"{a}/{b}" for a, b in mismatched_pairs])
            findings.append(f"Mismatched email domains between {mismatch_text} headers")
            
            # Detail the mismatches
            for field, domain in email_domains.items():
                findings.append(f"- {field} domain: {domain}")
    
    # 2. Display Name Spoofing - Check for deceptive display names
    if from_header:
        # Extract display name if present (e.g., "John Doe <john@example.com>")
        display_name_match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
        if display_name_match:
            display_name = display_name_match.group(1).lower()
            email = display_name_match.group(2).lower()
            
            # Check for company/service names in display name
            company_keywords = [
                'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'instagram',
                'bank', 'chase', 'wells fargo', 'citi', 'amex', 'american express', 'netflix',
                'support', 'service', 'team', 'admin', 'account', 'security', 'notification',
                'alert', 'update', 'verify', 'billing', 'payment'
            ]
            
            for company in company_keywords:
                if company in display_name and company not in email:
                    findings.append(f"Potential display name spoofing: '{display_name}' doesn't match email domain ({email})")
                    suspicious = True
                    break
    
    # 3. Header Presence/Absence Analysis
    # Critical headers that should be present
    essential_headers = [
        'message-id', 'date', 'from'
    ]
    
    for header in essential_headers:
        if header not in headers or not headers[header]:
            findings.append(f"Missing essential email header: {header}")
            suspicious = True
    
    # 4. Suspicious X-Mailer values
    mailer = headers.get('x-mailer', '').lower()
    suspicious_mailers = [
        'phishing', 'hack', 'exploit', 'spoof', 'mass mail', 'bulk mail',
        'email spoofer', 'email generator', 'mass mailer', 'anonymous'
    ]
    
    legitimate_mailers = [
        'outlook', 'apple mail', 'iphone mail', 'gmail', 'thunderbird', 
        'yahoo', 'ms exchange', 'office 365', 'mozilla', 'postbox'
    ]
    
    if mailer:
        for s_mailer in suspicious_mailers:
            if s_mailer in mailer:
                findings.append(f"Suspicious X-Mailer header: {mailer}")
                suspicious = True
                break
        
        # If not a known legitimate mailer, flag as unusual (lower priority)
        if not suspicious and not any(legit in mailer for legit in legitimate_mailers):
            findings.append(f"Unusual X-Mailer header: {mailer}")
            suspicious = True
            
    # 5. Check for unusual User-Agent
    user_agent = headers.get('user-agent', '').lower()
    if user_agent:
        suspicious_agents = ['curl', 'wget', 'script', 'bot', 'python', 'http', 'request']
        
        for agent in suspicious_agents:
            if agent in user_agent:
                findings.append(f"Suspicious User-Agent suggesting automation: {user_agent}")
                suspicious = True
                break
                
    # 6. Unusual Received chains
    received_headers = [v for k, v in headers.items() if k.lower() == 'received']
    if received_headers:
        # Check for suspicious patterns in received headers
        suspicious_patterns = [
            r'localhost', r'private', r'internal', r'unknown', 
            r'unverified', r'unauthenticated', r'\b(?:IP|range)\b'
        ]
        
        for received in received_headers:
            for pattern in suspicious_patterns:
                if re.search(pattern, received, re.IGNORECASE):
                    findings.append(f"Suspicious routing information in Received header: {pattern}")
                    suspicious = True
    else:
        findings.append("Missing Received headers - unusual for legitimate email")
        suspicious = True
        
    # 7. Unusual Authentication Results
    auth_results = headers.get('authentication-results', '').lower()
    if auth_results:
        if 'fail' in auth_results or 'neutral' in auth_results:
            findings.append("Email failed authentication checks")
            suspicious = True
    
    # 8. Missing Authentication Headers
    spf_headers = headers.get('received-spf', '')
    dkim_headers = headers.get('dkim-signature', '')
    dmarc_headers = headers.get('dmarc-status', '')
    
    missing_auth = []
    if not spf_headers:
        missing_auth.append("SPF")
    if not dkim_headers:
        missing_auth.append("DKIM")
    if not dmarc_headers:
        missing_auth.append("DMARC")
    
    if missing_auth:
        findings.append(f"Missing email authentication headers: {', '.join(missing_auth)}")
        suspicious = True
    
    # 9. Suspicious subject patterns
    subject = headers.get('subject', '').lower()
    if subject:
        # Check for common phishing subject patterns
        subject_patterns = [
            r'(?i)urgent', r'(?i)important', r'(?i)action required',
            r'(?i)verify', r'(?i)update', r'(?i)account',
            r'(?i)security', r'(?i)suspicious', r'(?i)unusual activity',
            r'(?i)password', r'(?i)confirm', r'(?i)information'
        ]
        
        subject_matches = sum(1 for pattern in subject_patterns if re.search(pattern, subject))
        if subject_matches >= 2:
            findings.append(f"Subject contains multiple suspicious patterns: '{subject}'")
            suspicious = True
        
        # Check for non-UTF-8 characters or encoding tricks
        try:
            subject.encode('ascii')
        except UnicodeEncodeError:
            # Contains non-ASCII characters - check for homograph attacks
            # (characters that look like Latin but aren't)
            if re.search(r'[^\x00-\x7F]', subject):
                findings.append(f"Subject contains non-ASCII characters, possible homograph attack: '{subject}'")
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
    
    # Skip analysis if no content
    if not content:
        findings.append("Empty email content - suspicious for a legitimate email")
        return {"suspicious": True, "suspicious_score": 1, "findings": findings}
    
    # 1. KEYWORD ANALYSIS - Check for phishing keywords in content
    keyword_count = 0
    found_keywords = []
    keyword_categories = {}
    
    for keyword in PHISHING_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', content, re.IGNORECASE):
            keyword_count += 1
            found_keywords.append(keyword)
    
    if keyword_count >= 3:
        findings.append(f"Contains multiple phishing keywords: {', '.join(found_keywords[:5])}" + 
                      (f" and {keyword_count - 5} more" if keyword_count > 5 else ""))
        suspicious = True
    
    # 2. PATTERN ANALYSIS - Check for phishing language patterns
    pattern_matches = []
    for pattern in PHISHING_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            pattern_matches.extend(matches[:2])  # Limit to first 2 matches per pattern
    
    if pattern_matches:
        findings.append(f"Contains phishing patterns: {', '.join(str(match) for match in pattern_matches[:3])}" +
                      (f" and {len(pattern_matches) - 3} more" if len(pattern_matches) > 3 else ""))
        suspicious = True
    
    # 3. URGENCY ANALYSIS - Check for urgent language (common in phishing)
    urgency_patterns = [
        r'(?i)urgent\b', 
        r'(?i)immediate\b', 
        r'(?i)important\b', 
        r'(?i)attention\b', 
        r'(?i)action required\b',
        r'(?i)expires?\b',
        r'(?i)deadline\b',
        r'(?i)limited time\b',
        r'(?i)act now\b',
        r'(?i)respond (?:now|immediately|today|within)\b',
        r'(?i)as soon as possible\b',
        r'(?i)time(?:-|\s)sensitive\b',
        r'(?i)(?:today|tomorrow|now) only\b',
        r'(?i)running out of time\b',
        r'(?i)before it\'s too late\b'
    ]
    
    urgency_count = sum(1 for pattern in urgency_patterns if re.search(pattern, content))
    if urgency_count >= 2:
        findings.append(f"Uses urgent or time-pressure language ({urgency_count} instances)")
        suspicious = True
    
    # 4. THREAT ANALYSIS - Check for threats or consequences (common in phishing)
    threat_patterns = [
        r'(?i)account.*(?:suspend|close|terminate|restrict|deactivate|delete|remove|block)',
        r'(?i)(?:suspend|close|terminate|restrict|deactivate|delete|remove|block).*account',
        r'(?i)access.*(?:denied|blocked|restricted|removed|revoked)',
        r'(?i)(?:avoid|prevent).*(?:suspension|termination|cancellation|deactivation)',
        r'(?i)failure to (?:comply|respond|confirm|verify|update|act)',
        r'(?i)will (?:result in|lead to|cause|initiate) (?:suspension|termination|cancellation|penalty|restriction|limitation)',
        r'(?i)(?:consequenc|penalt|charg|fee)(?:e|es|ed|y|ies)',
        r'(?i)legal (?:action|consequences|proceedings|measures)',
        r'(?i)security (?:breach|violation|issue|compromise|incident)',
        r'(?i)(?:unauthorized|illegal|fraudulent) (?:access|activity|transaction|charge)',
        r'(?i)(?:criminal|civil) (?:charges|prosecution|investigation)',
        r'(?i)failure to (?:comply|respond|verify)'
    ]
    
    threat_count = sum(1 for pattern in threat_patterns if re.search(pattern, content))
    if threat_count >= 1:
        findings.append(f"Contains threatening language or consequences ({threat_count} instances)")
        suspicious = True
    
    # 5. URL ANALYSIS - Check for suspicious URLs or URL masking tactics
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
    
    # Statistics about URLs
    url_count = len(urls)
    secure_count = sum(1 for url in urls if url.startswith('https://'))
    insecure_count = sum(1 for url in urls if url.startswith('http://'))
    
    display_urls = []
    shortened_urls = []
    ip_address_urls = []
    suspicious_urls = []
    
    # Analyze each URL found
    for url in urls:
        # 5a. Check for URL masking with different display and actual URLs (HTML emails)
        # This is when the displayed text is different from the actual URL in the href
        display_url_pattern = r'(?i)<a[^>]*href=[\'"](https?://[^\'">]+)[\'"][^>]*>(https?://[^<]+|[^<]{2,}\.(?:com|org|net|edu|gov|biz))</a>'
        display_url_matches = re.findall(display_url_pattern, content)
        
        for match in display_url_matches:
            actual_url, displayed_url = match
            if displayed_url.startswith('http') and actual_url != displayed_url:
                display_urls.append((displayed_url, actual_url))
                suspicious = True
        
        # 5b. Check for URL shorteners (can hide malicious destinations)
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
            'buff.ly', 'tiny.cc', 'lnkd.in', 'sho.rt', 'cutt.ly', 'tr.im',
            'snip.ly', 'cli.gs', 'rebrandly', 'shorte.st', 'adf.ly'
        ]
        for domain in shortener_domains:
            if domain in url:
                shortened_urls.append(url)
                break
        
        # 5c. Check for IP addresses in URLs (suspicious, legitimate sites use domain names)
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            ip_address_urls.append(url)
            suspicious = True
        
        # 5d. Check for other suspicious URL patterns
        suspicious_url_patterns = [
            r'(?i)(?:secure|login|auth|account|banking|verify|verification|update|password).*\.(?:tk|ga|ml|cf|gq)',  # Free domains often used in phishing
            r'(?i)(?:paypal|apple|microsoft|google|facebook|amazon).*\.(?!com|net|org|edu|gov)',  # Spoofed domains with wrong TLD
            r'(?i)(?:-secure-|-verify-|-login-|-auth-|-account-)',  # Excess hyphens in domain
            r'(?i)(?:signin|login|auth|account|verify|secure).*?(?:signin|login|auth|account|verify|secure)',  # Multiple authentication terms
            r'(?i)data:text/html',  # Data URI (can be used for obfuscation)
            r'(?i)javascript:'  # JavaScript URI (can be used for obfuscation)
        ]
        
        for pattern in suspicious_url_patterns:
            if re.search(pattern, url):
                suspicious_urls.append(url)
                suspicious = True
                break
    
    # Add findings for URL analysis
    if display_urls:
        findings.append(f"URL masking found - displayed URLs differ from actual URLs: {display_urls[:2]}" +
                      (f" and {len(display_urls) - 2} more" if len(display_urls) > 2 else ""))
    
    if shortened_urls:
        findings.append(f"Uses URL shorteners which can hide malicious destinations: {shortened_urls[:2]}" +
                      (f" and {len(shortened_urls) - 2} more" if len(shortened_urls) > 2 else ""))
        suspicious = True
    
    if ip_address_urls:
        findings.append(f"Contains URLs with IP addresses (unusual for legitimate organizations): {ip_address_urls[:2]}" +
                      (f" and {len(ip_address_urls) - 2} more" if len(ip_address_urls) > 2 else ""))
    
    if suspicious_urls:
        findings.append(f"Contains suspicious URL patterns: {suspicious_urls[:2]}" +
                      (f" and {len(suspicious_urls) - 2} more" if len(suspicious_urls) > 2 else ""))
    
    if insecure_count > 0 and url_count > 0:
        findings.append(f"Contains insecure (HTTP) URLs: {insecure_count} out of {url_count} total URLs")
        suspicious = True
    
    # 6. PERSONAL INFO REQUEST ANALYSIS - Check if email asks for sensitive information
    info_request_patterns = [
        r'(?i)(?:enter|confirm|verify|update|provide).*(?:password|username|login|account|credit card|ssn|social security|credentials|pin|security question)',
        r'(?i)(?:password|username|login|account|credit card|ssn|social security|credentials|pin|security question).*(?:enter|confirm|verify|update|provide)',
        r'(?i)(?:verification|security|authentication).*(?:form|details|information|process|code|token)',
        r'(?i)(?:security|account).*(?:check|verify|confirm|update|validate)',
        r'(?i)(?:banking|financial|payment).*(?:details|information|verification)',
        r'(?i)(?:identity|id).*(?:verification|confirm|validate|prove|proof)',
        r'(?i)click.*(?:link|button|here).*(?:login|sign in|access|verify|confirm|validate)',
        r'(?i)visit.*(?:site|page|portal|platform).*(?:login|sign in|access|verify|confirm|validate)',
        r'(?i)attach(?:ed|ment).*(?:form|document).*(?:complete|fill|submit)'
    ]
    
    info_request_count = sum(1 for pattern in info_request_patterns if re.search(pattern, content))
    if info_request_count >= 1:
        findings.append(f"Requests sensitive personal information ({info_request_count} instances)")
        suspicious = True
    
    # 7. ATTACHMENT ANALYSIS - Check for suspicious attachment mentions
    attachment_patterns = [
        r'(?i)(?:open|view|check|access|download|see).*(?:attachment|file|document|invoice|receipt|statement|report)',
        r'(?i)attach(?:ed|ment).*(?:invoice|receipt|statement|report|document|file)',
        r'(?i)(?:invoice|receipt|statement|report|document|file).*attach(?:ed|ment)',
        r'(?i)(?:zip|rar|7z|pdf|doc|docx|xls|xlsx|exe|bat|bin).*(?:file|attachment)'
    ]
    
    attachment_count = sum(1 for pattern in attachment_patterns if re.search(pattern, content))
    if attachment_count >= 1:
        findings.append(f"References attachments which may contain malware ({attachment_count} instances)")
        suspicious = True
    
    # 8. GRAMMAR & STYLE ANALYSIS - Check for poor grammar/formatting (common in phishing)
    poor_grammar_indicators = [
        # Multiple consecutive punctuation
        len(re.findall(r'[!?]{2,}', content)) > 0,
        # ALL CAPS sections (excluding acronyms)
        len(re.findall(r'\b[A-Z]{5,}\b', content)) > 0,
        # Excessive spacing
        len(re.findall(r'\s{3,}', content)) > 3,
        # No greeting or weird greeting
        not re.search(r'(?i)(?:dear|hello|hi|greetings|good\s+(?:morning|afternoon|evening))\s+\w+', content)
    ]
    
    if sum(poor_grammar_indicators) >= 2:
        findings.append("Contains poor grammar or unusual formatting typical of phishing emails")
        suspicious = True
    
    # 9. IMPERSONATION ANALYSIS - Check for common impersonation tactics
    impersonation_patterns = [
        r'(?i)(?:bank|paypal|apple|microsoft|amazon|google).*(?:security|verification|confirm|update|alert|notice|team)',
        r'(?i)(?:security|verification|confirm|update|alert|notice|team).*(?:bank|paypal|apple|microsoft|amazon|google)',
        r'(?i)(?:technical|support|customer service|helpdesk|IT department).*(?:team|staff|personnel|representative)',
        r'(?i)(?:billing|payment|account|admin|administrator|system).*(?:team|staff|personnel|representative)',
        r'(?i)(?:official|important|confidential|secure).*(?:notification|message|communication|notice|alert)'
    ]
    
    impersonation_count = sum(1 for pattern in impersonation_patterns if re.search(pattern, content))
    if impersonation_count >= 1:
        findings.append(f"Contains language that may be impersonating legitimate organizations ({impersonation_count} instances)")
        suspicious = True
    
    # 10. LINK INSTRUCTION ANALYSIS - Check for instructions to click links
    link_instruction_patterns = [
        r'(?i)(?:click|tap|follow|visit|open|access).*(?:link|url|website|portal|button|here)',
        r'(?i)(?:link|url|website|portal|button).*(?:below|following|attached)',
        r'(?i)(?:verify|update|confirm|check|access).*(?:account|information|details).*(?:link|url|website|portal|button|here)',
        r'(?i)(?:sign|log) (?:in|on).*(?:link|url|website|portal|button|here)',
    ]
    
    link_instruction_count = sum(1 for pattern in link_instruction_patterns if re.search(pattern, content))
    if link_instruction_count >= 2:
        findings.append(f"Contains multiple instructions to click links ({link_instruction_count} instances)")
        suspicious = True
    
    # Calculate comprehensive suspicious score
    suspicious_score = (
        keyword_count + 
        len(pattern_matches) + 
        urgency_count + 
        threat_count * 2 +  # Weight threatening language more heavily
        len(display_urls) * 2 +  # Weight URL masking more heavily
        len(shortened_urls) + 
        len(ip_address_urls) * 2 +
        len(suspicious_urls) + 
        info_request_count * 3 +  # Weight sensitive info requests heavily
        attachment_count +
        sum(poor_grammar_indicators) +
        impersonation_count * 2 +
        link_instruction_count
    )
    
    return {
        "suspicious": suspicious,
        "suspicious_score": suspicious_score,
        "findings": findings
    }

def analyze_email(email_data):
    """
    Analyze an email for phishing indicators
    
    Args:
        email_data (dict): The email data containing 'from', 'headers', and 'content'
        
    Returns:
        dict: Comprehensive analysis results with risk assessment and specific findings
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
        'subject_analysis': {},
        'findings': [],
        'risk_factors': {},  # For categorized risk findings
        'safety_advice': [],  # Recommendations based on findings
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    try:
        # Initialize risk categories
        risk_categories = {
            'sender_risk': 0,
            'header_risk': 0,
            'content_risk': 0,
            'subject_risk': 0,
            'behavioral_risk': 0,
            'url_risk': 0,
            'attachment_risk': 0,
            'grammar_risk': 0,
        }
        
        # SUBJECT ANALYSIS - Often overlooked but important
        if subject:
            subject_suspicious = False
            subject_findings = []
            
            # Check for phishing keywords in subject
            subject_keywords = [
                'urgent', 'important', 'action required', 'verify', 'account', 
                'security', 'update', 'alert', 'suspicious', 'confirm', 'password',
                'login', 'access', 'banking', 'payment', 'invoice', 'receipt',
                'tax', 'refund', 'document', 'package', 'delivery', 'notification'
            ]
            
            subject_keyword_count = sum(1 for keyword in subject_keywords 
                                    if re.search(r'\b' + re.escape(keyword) + r'\b', 
                                                subject, re.IGNORECASE))
            
            if subject_keyword_count >= 2:
                subject_suspicious = True
                subject_findings.append(f"Subject contains multiple phishing keywords")
                risk_categories['subject_risk'] += subject_keyword_count
                
            # Check for urgency or fear indicators in subject
            urgency_patterns = [
                r'(?i)urgent', r'(?i)immediate', r'(?i)attention', r'(?i)important',
                r'(?i)alert', r'(?i)warning', r'(?i)security', r'(?i)required',
                r'(?i)action', r'(?i)now', r'(?i)today', r'(?i)expires?'
            ]
            
            urgency_count = sum(1 for pattern in urgency_patterns 
                              if re.search(pattern, subject))
            
            if urgency_count >= 1:
                subject_suspicious = True
                subject_findings.append(f"Subject uses urgent language to prompt immediate action")
                risk_categories['subject_risk'] += urgency_count
                
            # Check for ALL CAPS or excessive punctuation (common in phishing)
            if re.search(r'\b[A-Z]{5,}\b', subject) or re.search(r'[!?]{2,}', subject):
                subject_suspicious = True
                subject_findings.append("Subject uses unusual formatting (ALL CAPS or excessive punctuation)")
                risk_categories['subject_risk'] += 1
                
            # Add to results
            if subject_suspicious:
                results['subject_analysis'] = {
                    'suspicious': True,
                    'findings': subject_findings
                }
                results['findings'].extend(subject_findings)
        
        # SENDER ANALYSIS
        # Validate sender email format
        valid_email = is_valid_email(sender) if sender else False
        if not valid_email and sender:
            results['findings'].append("Invalid sender email format")
            risk_categories['sender_risk'] += 2
        
        # Analyze sender domain
        if sender:
            sender_analysis = check_sender_domain(sender)
            results['sender_analysis'] = sender_analysis
            
            if sender_analysis['suspicious']:
                results['findings'].extend(sender_analysis['findings'])
                risk_categories['sender_risk'] += len(sender_analysis['findings']) * 2 # Weight sender domain issues heavily
        
        # HEADER ANALYSIS
        if headers:
            header_analysis = check_email_headers(headers)
            results['header_analysis'] = header_analysis
            
            if header_analysis['suspicious']:
                results['findings'].extend(header_analysis['findings'])
                risk_categories['header_risk'] += len(header_analysis['findings'])
        
        # CONTENT ANALYSIS
        if content:
            content_analysis = analyze_email_content(content)
            results['content_analysis'] = content_analysis
            
            if content_analysis['suspicious']:
                results['findings'].extend(content_analysis['findings'])
                
                # Distribute content analysis scores to specific risk categories
                risk_categories['content_risk'] += content_analysis.get('suspicious_score', 0) // 2
                
                # Extract specific risk types from content
                for finding in content_analysis.get('findings', []):
                    finding_lower = finding.lower()
                    
                    # URL risks
                    if 'url' in finding_lower or 'link' in finding_lower or 'http' in finding_lower:
                        risk_categories['url_risk'] += 2
                    
                    # Attachment risks
                    if 'attachment' in finding_lower or 'file' in finding_lower or 'document' in finding_lower:
                        risk_categories['attachment_risk'] += 2
                    
                    # Behavioral manipulation
                    if 'urgency' in finding_lower or 'threat' in finding_lower or 'pressure' in finding_lower:
                        risk_categories['behavioral_risk'] += 2
                    
                    # Grammar/style issues
                    if 'grammar' in finding_lower or 'format' in finding_lower:
                        risk_categories['grammar_risk'] += 1
        
        # Calculate total suspicious indicators with weighted categories
        results['suspicious_indicators'] = sum(risk_categories.values())
        results['risk_factors'] = risk_categories
        
        # Determine risk level with more granular scale
        if results['suspicious_indicators'] >= 15:
            results['risk_level'] = 'Critical'
            results['safety_advice'] = [
                "This is almost certainly a phishing email - DO NOT interact with it in any way",
                "Do not click any links or download any attachments",
                "Delete this email immediately",
                "If it appears to be from a service you use, contact that service through official channels to verify"
            ]
        elif results['suspicious_indicators'] >= 10:
            results['risk_level'] = 'High'
            results['safety_advice'] = [
                "This email shows strong signs of being a phishing attempt",
                "Do not click any links or download any attachments",
                "Delete this email or report it as phishing"
            ]
        elif results['suspicious_indicators'] >= 5:
            results['risk_level'] = 'Medium'
            results['safety_advice'] = [
                "This email contains suspicious elements that may indicate phishing",
                "Exercise caution - do not click links or provide any personal information",
                "Verify the sender through official channels before taking any action"
            ]
        elif results['suspicious_indicators'] >= 2:
            results['risk_level'] = 'Low'
            results['safety_advice'] = [
                "This email has some minor suspicious indicators",
                "Exercise normal caution when interacting with this email",
                "Verify the sender if you're at all uncertain"
            ]
        elif results['suspicious_indicators'] > 0:
            results['risk_level'] = 'Very Low'
            results['safety_advice'] = [
                "This email has very few suspicious elements",
                "Follow normal email safety practices"
            ]
        else:
            results['risk_level'] = 'Safe'
            results['safety_advice'] = [
                "No suspicious indicators were found in this email",
                "Still follow good email security practices"
            ]
            
        # Add a summary of highest risk factors
        risk_summary = []
        for category, score in sorted(risk_categories.items(), key=lambda x: x[1], reverse=True)[:3]:
            if score > 0:
                category_name = category.replace('_risk', '').title()
                risk_summary.append(f"{category_name} ({score} points)")
        
        if risk_summary:
            results['risk_summary'] = f"Highest risk factors: {', '.join(risk_summary)}"
        
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}")
        results['error'] = str(e)
    
    return results