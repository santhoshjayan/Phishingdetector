"""
Generate Test Data

This script generates test data for SpeeDefender, including URLs and emails
with various risk levels to populate the history.
"""

import os
import json
import time
from datetime import datetime, timedelta
import random

# Create necessary directories
def ensure_dirs():
    """Ensure all necessary directories exist."""
    os.makedirs('analysis_history', exist_ok=True)
    os.makedirs('data/scanned_emails', exist_ok=True)
    
# Generate URL test data with various risk levels
def generate_url_test_data():
    """Generate test URL analysis with various risk levels."""
    # Sample domains with different risk levels
    domains = {
        'Critical': [
            'fake-paypal-login.com',
            'bankofamerica-secure-login.net',
            'amazonsecurity.phishing.com',
            'account-verify-apple.com',
            'microsoft365-password-reset.net'
        ],
        'High': [
            'login-secure-payment.com',
            'banking-update-required.com',
            'verify-account-now.net',
            'security-alert-update.com',
            'password-reset-confirm.net'
        ],
        'Medium': [
            'free-gift-cards.com',
            'download-free-movies.net',
            'online-surveys-paid.com',
            'lottery-winner-claim.net',
            'investment-opportunity.org'
        ],
        'Low': [
            'news-blog-daily.com',
            'weather-forecast-local.net',
            'sports-updates-live.com',
            'recipe-collection.org',
            'travel-tips-blog.net'
        ],
        'Safe': [
            'google.com',
            'microsoft.com',
            'amazon.com',
            'facebook.com',
            'apple.com'
        ]
    }
    
    # Create timestamped filenames
    now = datetime.now()
    
    # Create history entries for each risk level
    for risk_level, domain_list in domains.items():
        for domain in domain_list:
            # Create a unique timestamp for each entry (5 minutes apart)
            timestamp = now - timedelta(minutes=random.randint(5, 1000))
            timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S')
            
            # Create the URL and safe filename
            url = f"https://{domain}"
            safe_domain = domain.replace('.', '_')
            filename = f"{timestamp_str}_https_{safe_domain}.json"
            filepath = os.path.join('analysis_history', filename)
            
            # Generate suspicious indicators based on risk level
            if risk_level == 'Critical':
                indicators = random.randint(7, 10)
            elif risk_level == 'High': 
                indicators = random.randint(5, 7)
            elif risk_level == 'Medium':
                indicators = random.randint(3, 5)
            elif risk_level == 'Low':
                indicators = random.randint(1, 3)
            else:  # Safe
                indicators = 0
            
            # Create findings based on risk level
            findings = []
            
            if risk_level in ['Critical', 'High']:
                findings.append("Domain registered recently")
                findings.append("Domain mimics a well-known brand")
                findings.append("Uses suspicious URL patterns")
                findings.append("Contains login form with suspicious action URL")
                
            if risk_level in ['Critical', 'High', 'Medium']:
                findings.append("Website requests sensitive information")
                findings.append("Contains suspicious keywords")
                
            if risk_level in ['Critical', 'High', 'Medium', 'Low']:
                findings.append("Missing HTTPS")
                
            # Limit findings based on indicators count
            findings = findings[:indicators]
            
            # Create analysis result
            result = {
                "timestamp": timestamp.isoformat(),
                "url": url,
                "risk_level": risk_level,
                "suspicious_indicators": indicators,
                "findings": findings,
                "domain_info": {
                    "registrar": "Example Registrar, Inc.",
                    "creation_date": (timestamp - timedelta(days=30 if risk_level == 'Critical' else 365)).isoformat(),
                    "expiration_date": (timestamp + timedelta(days=365)).isoformat(),
                    "country": "US",
                    "organization": "Example Org"
                },
                "screenshot": None
            }
            
            # Save the analysis result
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=4)
            
            print(f"Created test URL analysis: {url} with risk level {risk_level}")
            
            # Add a small delay to ensure unique timestamps
            time.sleep(0.1)

# Generate email test data with various risk levels
def generate_email_test_data():
    """Generate test email analysis with various risk levels."""
    # Sample email data with different risk levels
    email_data = {
        'Critical': [
            {
                'from': 'security@paypal-account-verify.com',
                'subject': 'URGENT: Your PayPal account has been limited',
                'content': 'Your account access has been limited. Click here to verify your information immediately or your account will be suspended.'
            },
            {
                'from': 'support@microsoft365-password-reset.net',
                'subject': 'Microsoft 365: Password reset required immediately',
                'content': 'Our security system has detected unauthorized access to your account. Click the link to reset your password now.'
            }
        ],
        'High': [
            {
                'from': 'amazon-orders@shipping-update.com',
                'subject': 'Amazon Order #12345: Action Required',
                'content': 'Your recent Amazon order requires verification. Please confirm your payment details to avoid order cancellation.'
            },
            {
                'from': 'helpdesk@account-security-alert.net',
                'subject': 'Security Alert: Unusual Sign-in Activity',
                'content': 'We detected unusual sign-in activity on your account. Please verify your identity by clicking the secure link below.'
            }
        ],
        'Medium': [
            {
                'from': 'newsletter@special-offers.com',
                'subject': 'Exclusive Limited Time Offer Inside!',
                'content': 'You\'ve been selected for our exclusive offer. Limited time only - 80% discount on premium products.'
            },
            {
                'from': 'support@subscription-renewal.net',
                'subject': 'Your subscription is about to expire',
                'content': 'Your service subscription will expire soon. Click here to renew and avoid service interruption.'
            }
        ],
        'Low': [
            {
                'from': 'newsletter@retail-store.com',
                'subject': 'This Week\'s Deals and Promotions',
                'content': 'Check out this week\'s best deals and promotions. Save big on selected items while supplies last.'
            },
            {
                'from': 'updates@business-newsletter.net',
                'subject': 'Industry Updates and News',
                'content': 'Stay informed with the latest industry trends and business news. Read our weekly update.'
            }
        ],
        'Safe': [
            {
                'from': 'no-reply@google.com',
                'subject': 'Your Google Account: monthly security update',
                'content': 'Here\'s your regular update on your Google Account activity and security settings.'
            },
            {
                'from': 'news@microsoft.com',
                'subject': 'Microsoft Developer Newsletter',
                'content': 'The latest updates, technical resources, and developer events from Microsoft.'
            }
        ]
    }
    
    # Create data directory if it doesn't exist
    os.makedirs('data/scanned_emails', exist_ok=True)
    
    # Current time
    now = datetime.now()
    
    # Create email analysis entries for each risk level
    for risk_level, email_list in email_data.items():
        for email in email_list:
            # Create a unique timestamp for each entry
            timestamp = now - timedelta(minutes=random.randint(5, 1000))
            timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S')
            
            # Create safe filename
            safe_subject = ''.join(e for e in email['subject'] if e.isalnum())[:30]
            filename = f"data/scanned_emails/{timestamp_str}_{safe_subject}_{risk_level}.json"
            
            # Generate findings based on risk level
            findings = []
            
            if risk_level in ['Critical', 'High']:
                findings.append("Sender domain mimics legitimate business")
                findings.append("Email contains urgent call to action")
                findings.append("Contains suspicious links")
                findings.append("Requests sensitive information")
                
            if risk_level in ['Critical', 'High', 'Medium']:
                findings.append("Suspicious subject line")
                findings.append("Contains unusual attachments")
                
            if risk_level in ['Critical', 'High', 'Medium', 'Low']:
                findings.append("Sender domain registered recently")
            
            # Create email data
            email_data = {
                "email_data": {
                    "from": email['from'],
                    "to": "user@example.com",
                    "subject": email['subject'],
                    "date": timestamp.isoformat(),
                },
                "analysis_results": {
                    "risk_level": risk_level,
                    "findings": findings,
                    "sender_analysis": {
                        "domain": email['from'].split('@')[1],
                        "suspicious": risk_level in ['Critical', 'High']
                    },
                    "content_analysis": {
                        "suspicious_links": risk_level in ['Critical', 'High'],
                        "suspicious_keywords": risk_level in ['Critical', 'High', 'Medium']
                    }
                },
                "action_taken": {
                    "timestamp": timestamp.isoformat(),
                    "email_id": f"email_{timestamp_str}",
                    "from": email['from'],
                    "subject": email['subject'],
                    "risk_level": risk_level,
                    "action_taken": "quarantine" if risk_level in ['Critical'] else 
                                   "spam" if risk_level in ['High', 'Medium'] else
                                   "tag" if risk_level == 'Low' else "none",
                    "success": True,
                    "used_predetermined_rules": True
                }
            }
            
            # Save the email analysis
            with open(filename, 'w') as f:
                json.dump(email_data, f, indent=4)
            
            print(f"Created test email analysis from {email['from']} with risk level {risk_level}")
            
            # Add a small delay to ensure unique timestamps
            time.sleep(0.1)
    
    # Also create an email actions log
    actions = []
    
    # Need to recreate the email data structure for the log
    email_senders = {
        'Critical': [
            ('security@paypal-account-verify.com', 'URGENT: Your PayPal account has been limited'),
            ('support@microsoft365-password-reset.net', 'Microsoft 365: Password reset required immediately')
        ],
        'High': [
            ('amazon-orders@shipping-update.com', 'Amazon Order #12345: Action Required'),
            ('helpdesk@account-security-alert.net', 'Security Alert: Unusual Sign-in Activity')
        ],
        'Medium': [
            ('newsletter@special-offers.com', 'Exclusive Limited Time Offer Inside!'),
            ('support@subscription-renewal.net', 'Your subscription is about to expire')
        ],
        'Low': [
            ('newsletter@retail-store.com', 'This Week\'s Deals and Promotions'),
            ('updates@business-newsletter.net', 'Industry Updates and News')
        ],
        'Safe': [
            ('no-reply@google.com', 'Your Google Account: monthly security update'),
            ('news@microsoft.com', 'Microsoft Developer Newsletter')
        ]
    }
    
    for risk_level, sender_list in email_senders.items():
        for sender_info in sender_list:
            timestamp = now - timedelta(minutes=random.randint(5, 1000))
            sender_email, subject = sender_info
            
            action = {
                "timestamp": timestamp.isoformat(),
                "email_id": f"email_{timestamp.strftime('%Y%m%d_%H%M%S')}",
                "from": sender_email,
                "subject": subject,
                "risk_level": risk_level,
                "action_taken": "quarantine" if risk_level in ['Critical'] else 
                               "spam" if risk_level in ['High', 'Medium'] else
                               "tag" if risk_level == 'Low' else "none",
                "success": True,
                "used_predetermined_rules": True
            }
            
            actions.append(action)
    
    # Save the actions log
    os.makedirs('data', exist_ok=True)
    with open('data/email_actions.json', 'w') as f:
        json.dump(actions, f, indent=4)
    
    print(f"Created email actions log with {len(actions)} entries")

# Main execution
if __name__ == "__main__":
    ensure_dirs()
    generate_url_test_data()
    generate_email_test_data()
    print("Test data generation complete!")