"""
Email Scanner Module

Automatically scans emails for phishing indicators and takes appropriate actions.
"""

import os
import sys
import logging
import json
import time
from datetime import datetime
import threading
from pathlib import Path

# Set up path to access other utility modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from utils.email_analyzer import analyze_email
from utils.email_automation.email_connector import EmailConnector
from utils.email_automation.email_notifications import EmailNotifier

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_automation.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class EmailScanner:
    """Class to automatically scan emails for phishing threats and take actions."""
    
    def __init__(self, config=None):
        """
        Initialize the email scanner with configuration.
        
        Args:
            config (dict): Configuration settings. If None, will load from file.
        """
        self.config = config or self._load_config()
        self.email_connector = EmailConnector(self.config.get('email_connection', {}))
        self.email_notifier = EmailNotifier(self.config.get('notifications', {}))
        self.actions_taken = []
        self.running = False
        self.scan_thread = None
        
        # Ensure required directories exist
        os.makedirs('config', exist_ok=True)
        os.makedirs('data/scanned_emails', exist_ok=True)
        
        # Create actions log file if it doesn't exist
        self.actions_log_path = 'data/email_actions.json'
        if not os.path.exists(self.actions_log_path):
            with open(self.actions_log_path, 'w') as f:
                json.dump([], f)
    
    def _load_config(self):
        """Load scanner configuration from file."""
        config_path = 'config/email_scanner_config.json'
        
        # Create default config if it doesn't exist
        if not os.path.exists(config_path):
            os.makedirs('config', exist_ok=True)
            default_config = {
                "email_connection": {
                    "imap_server": "imap.example.com",
                    "imap_port": 993,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "email": "your_email@example.com",
                    "password": "your_password",
                    "use_ssl": True,
                    "scan_folder": "INBOX",
                    "spam_folder": "Spam",
                    "quarantine_folder": "Quarantine"
                },
                "scanning": {
                    "scan_interval": 300,  # seconds
                    "max_emails_per_scan": 20,
                    "unread_only": True,
                    "use_predetermined_analysis": True  # Use predetermined rules for faster processing
                },
                "actions": {
                    "critical_action": "quarantine",  # quarantine, spam, tag, none
                    "high_action": "spam",  # Changed default to move to spam 
                    "medium_action": "spam",  # Changed default to move to spam
                    "low_action": "tag",
                    "safe_action": "none",
                    "send_notifications": False,  # Disabled by default to avoid requiring SendGrid
                    "notification_recipients": ["admin@example.com"],
                    "automatically_handle_threats": True  # Automatically process emails without confirmation
                },
                "notifications": {
                    "sendgrid_api_key": "",  # Will use environment variable if not set
                    "sender_email": "noreply@speedefender.com",
                    "sender_name": "SpeeDefender",
                    "alerts_enabled": False,  # Disabled by default
                    "system_alerts_enabled": False  # Disabled by default
                },
                "predetermined_rules": {
                    "enabled": True,
                    "blocklist_domains": [
                        "suspicious-domain.com",
                        "phishing-attempt.net",
                        "malware-link.org"
                    ],
                    "suspicious_keywords": [
                        "urgent action required",
                        "verify your account immediately",
                        "unusual sign-in activity",
                        "password reset required",
                        "banking information update",
                        "payment processing failed",
                        "claim your prize",
                        "lottery winner",
                        "bitcoin investment"
                    ],
                    "trusted_domains": [
                        "google.com",
                        "microsoft.com",
                        "apple.com"
                    ]
                }
            }
            
            with open(config_path, 'w') as config_file:
                json.dump(default_config, config_file, indent=4)
            
            logger.info(f"Created default config at {config_path}. Please update with your details.")
        
        try:
            with open(config_path, 'r') as config_file:
                return json.load(config_file)
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            return {}
    
    def _save_action_log(self, action):
        """
        Save taken action to the log file.
        
        Args:
            action (dict): Action data to save
        """
        try:
            if os.path.exists(self.actions_log_path):
                with open(self.actions_log_path, 'r') as f:
                    actions = json.load(f)
            else:
                actions = []
            
            actions.append(action)
            
            with open(self.actions_log_path, 'w') as f:
                json.dump(actions, f, indent=4)
                
        except Exception as e:
            logger.error(f"Error saving action log: {str(e)}")
    
    def _get_action_for_risk(self, risk_level):
        """
        Determine what action to take based on risk level.
        
        Args:
            risk_level (str): The email risk level (Critical, High, Medium, Low, Safe)
            
        Returns:
            str: Action to take (quarantine, spam, tag, none)
        """
        actions_config = self.config.get('actions', {})
        risk_level = risk_level.lower()
        
        if risk_level == "critical":
            return actions_config.get('critical_action', 'quarantine')
        elif risk_level == "high":
            return actions_config.get('high_action', 'quarantine')
        elif risk_level == "medium":
            return actions_config.get('medium_action', 'tag')
        elif risk_level == "low":
            return actions_config.get('low_action', 'tag')
        else:  # Safe or unknown
            return actions_config.get('safe_action', 'none')
    
    def _take_action(self, email_id, email_data, analysis_results):
        """
        Take appropriate action based on email analysis results.
        
        Args:
            email_id (str): Email ID
            email_data (dict): Raw email data
            analysis_results (dict): Analysis results
            
        Returns:
            dict: Action taken details
        """
        risk_level = analysis_results.get('risk_level', 'Unknown')
        action_type = self._get_action_for_risk(risk_level)
        
        action_details = {
            "timestamp": datetime.now().isoformat(),
            "email_id": email_id,
            "from": email_data.get('from', ''),
            "subject": email_data.get('subject', ''),
            "risk_level": risk_level,
            "action_taken": action_type,
            "success": False
        }
        
        # Execute action based on type
        if action_type == 'quarantine':
            quarantine_folder = self.config.get('email_connection', {}).get('quarantine_folder', 'Quarantine')
            success = self.email_connector.move_to_folder(email_id, quarantine_folder)
            action_details["success"] = success
            action_details["destination"] = quarantine_folder
            logger.info(f"Quarantined email from {email_data.get('from', '')} with subject: {email_data.get('subject', '')}")
            
        elif action_type == 'spam':
            spam_folder = self.config.get('email_connection', {}).get('spam_folder', 'Spam')
            success = self.email_connector.move_to_folder(email_id, spam_folder)
            action_details["success"] = success
            action_details["destination"] = spam_folder
            logger.info(f"Moved to spam: email from {email_data.get('from', '')} with subject: {email_data.get('subject', '')}")
            
        elif action_type == 'tag':
            # Currently, tagging isn't implemented as it requires modifying the email
            # Mark as read instead
            success = self.email_connector.mark_as_read(email_id)
            action_details["success"] = success
            action_details["note"] = "Tagged as potentially suspicious (marked as read)"
            logger.info(f"Tagged email from {email_data.get('from', '')} with subject: {email_data.get('subject', '')}")
            
        else:  # 'none' action
            action_details["success"] = True
            action_details["note"] = "No action taken"
            logger.info(f"No action taken for email from {email_data.get('from', '')} with subject: {email_data.get('subject', '')}")
        
        # Send notification if configured
        if self.config.get('actions', {}).get('send_notifications', False) and risk_level.lower() in ['critical', 'high']:
            recipients = self.config.get('actions', {}).get('notification_recipients', [])
            
            for recipient in recipients:
                # Use the EmailNotifier to send a formatted phishing alert
                sent = self.email_notifier.send_phishing_alert(
                    recipient=recipient,
                    email_data=email_data,
                    analysis_results=analysis_results,
                    action_taken=action_details
                )
                
                if sent:
                    action_details["notification_sent"] = True
                    logger.info(f"Sent phishing alert notification to {recipient}")
                else:
                    logger.warning(f"Failed to send phishing alert notification to {recipient}")
        
        # Save the action to the log
        self._save_action_log(action_details)
        
        # Save the full analysis to a file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_subject = ''.join(e for e in email_data.get('subject', 'no_subject') if e.isalnum())[:30]
        filename = f"data/scanned_emails/{timestamp}_{safe_subject}_{risk_level}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "email_data": {
                    "from": email_data.get('from', ''),
                    "to": email_data.get('to', ''),
                    "subject": email_data.get('subject', ''),
                    "date": email_data.get('date', ''),
                },
                "analysis_results": analysis_results,
                "action_taken": action_details
            }, f, indent=4)
        
        return action_details
    
    def _apply_predetermined_rules(self, email_data):
        """
        Apply predetermined rules to quickly analyze an email without full analysis.
        
        Args:
            email_data (dict): Email data including from, subject, content
            
        Returns:
            dict: Preliminary analysis results with risk level
        """
        # Get predetermined rules configuration
        rules = self.config.get('predetermined_rules', {})
        if not rules.get('enabled', False):
            return None
            
        # Extract email components for analysis
        from_address = email_data.get('from', '').lower()
        subject = email_data.get('subject', '').lower()
        content = email_data.get('content', '').lower()
        
        # Initialize the results
        results = {
            'risk_level': 'Unknown',
            'findings': []
        }
        
        # Check sender domain against blocklist
        blocklist_domains = rules.get('blocklist_domains', [])
        for domain in blocklist_domains:
            if domain.lower() in from_address:
                results['risk_level'] = 'Critical'
                results['findings'].append(f"Sender domain {domain} is in blocklist")
                return results
        
        # Check for trusted domains (considered safe)
        trusted_domains = rules.get('trusted_domains', [])
        sender_is_trusted = False
        for domain in trusted_domains:
            if domain.lower() in from_address:
                sender_is_trusted = True
                break
                
        # Check for suspicious keywords in subject and content
        suspicious_keywords = rules.get('suspicious_keywords', [])
        keyword_matches = []
        
        for keyword in suspicious_keywords:
            keyword = keyword.lower()
            if keyword in subject:
                keyword_matches.append(f"Subject contains suspicious keyword: {keyword}")
            if keyword in content:
                keyword_matches.append(f"Content contains suspicious keyword: {keyword}")
        
        # Determine risk level based on findings
        if len(keyword_matches) > 3:
            results['risk_level'] = 'High'
            results['findings'].extend(keyword_matches)
        elif len(keyword_matches) > 1:
            results['risk_level'] = 'Medium'
            results['findings'].extend(keyword_matches)
        elif len(keyword_matches) > 0:
            results['risk_level'] = 'Low'
            results['findings'].extend(keyword_matches)
        elif sender_is_trusted:
            results['risk_level'] = 'Safe'
            results['findings'].append("Sender domain is trusted")
        else:
            results['risk_level'] = 'Low'
            results['findings'].append("No suspicious patterns detected, but sender not in trusted list")
            
        return results
    
    def scan_and_act(self):
        """
        Scan emails and take appropriate actions.
        
        Returns:
            list: Actions taken during this scan
        """
        if not self.email_connector.connect_imap():
            logger.error("Failed to connect to email server. Cannot scan emails.")
            return []
        
        # Get emails to scan
        scan_config = self.config.get('scanning', {})
        max_emails = scan_config.get('max_emails_per_scan', 10)
        unread_only = scan_config.get('unread_only', True)
        scan_folder = self.config.get('email_connection', {}).get('scan_folder', 'INBOX')
        use_predetermined = scan_config.get('use_predetermined_analysis', False)
        
        emails = self.email_connector.get_emails(
            folder=scan_folder,
            limit=max_emails,
            unread_only=unread_only
        )
        
        if not emails:
            logger.info(f"No emails to scan in {scan_folder}")
            self.email_connector.disconnect()
            return []
        
        actions_taken = []
        auto_handle = self.config.get('actions', {}).get('automatically_handle_threats', True)
        
        # Process each email
        for email_data in emails:
            try:
                from_address = email_data.get('from', '')
                subject = email_data.get('subject', '')
                logger.info(f"Analyzing email from {from_address} with subject: {subject}")
                
                # Track whether predetermined rules were used
                used_predetermined = False
                
                # Determine if we should use predetermined rules or full analysis
                if use_predetermined:
                    # Try predetermined rules first for efficiency
                    prelim_results = self._apply_predetermined_rules(email_data)
                    
                    # If we got valid predetermined results and automatic handling is enabled
                    if prelim_results and auto_handle:
                        analysis_results = prelim_results
                        used_predetermined = True
                        logger.info(f"Used predetermined rules: {analysis_results['risk_level']} risk for email from {from_address}")
                    else:
                        # Fall back to full analysis
                        analysis_results = analyze_email({
                            'from': from_address,
                            'headers': email_data.get('headers', {}),
                            'content': email_data.get('content', '')
                        })
                else:
                    # Use full analysis
                    analysis_results = analyze_email({
                        'from': from_address,
                        'headers': email_data.get('headers', {}),
                        'content': email_data.get('content', '')
                    })
                
                # Add flag to indicate if predetermined rules were used
                if used_predetermined:
                    analysis_results['used_predetermined_rules'] = True
                
                # Take appropriate action
                action = self._take_action(email_data['id'], email_data, analysis_results)
                
                # Add flag to action record
                if used_predetermined:
                    action['used_predetermined_rules'] = True
                    
                actions_taken.append(action)
                
            except Exception as e:
                logger.error(f"Error processing email: {str(e)}")
        
        # Disconnect from the server
        self.email_connector.disconnect()
        
        logger.info(f"Completed scan. Processed {len(emails)} emails. Took {len(actions_taken)} actions.")
        return actions_taken
    
    def _scanning_loop(self):
        """Background scanning loop that runs at intervals."""
        while self.running:
            try:
                self.actions_taken = self.scan_and_act()
            except Exception as e:
                logger.error(f"Error in scanning loop: {str(e)}")
            
            # Sleep for the configured interval
            scan_interval = self.config.get('scanning', {}).get('scan_interval', 300)
            time.sleep(scan_interval)
    
    def start_automatic_scanning(self):
        """Start the automatic scanning process in a background thread."""
        if self.running:
            logger.warning("Automatic scanning is already running.")
            return False
        
        self.running = True
        self.scan_thread = threading.Thread(target=self._scanning_loop)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        logger.info("Started automatic email scanning.")
        return True
    
    def stop_automatic_scanning(self):
        """Stop the automatic scanning process."""
        if not self.running:
            logger.warning("Automatic scanning is not running.")
            return False
        
        self.running = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(2.0)  # Wait for thread to finish
        
        logger.info("Stopped automatic email scanning.")
        return True
    
    def get_status(self):
        """
        Get the current status of the scanner.
        
        Returns:
            dict: Status information
        """
        # Get scanning statistics
        try:
            with open(self.actions_log_path, 'r') as f:
                actions = json.load(f)
        except:
            actions = []
        
        # Count actions by risk level
        risk_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Safe': 0
        }
        
        for action in actions:
            risk_level = action.get('risk_level', 'Unknown')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        return {
            "running": self.running,
            "config": self.config,
            "statistics": {
                "total_emails_processed": len(actions),
                "emails_by_risk_level": risk_counts,
                "recent_actions": actions[-10:] if actions else []
            }
        }


def run_single_scan():
    """Run a single email scan for testing or manual execution."""
    scanner = EmailScanner()
    actions = scanner.scan_and_act()
    return actions


if __name__ == "__main__":
    print("Email Scanner - Running a test scan...")
    actions = run_single_scan()
    print(f"Scan complete. Took {len(actions)} actions.")
    
    # Optionally start automatic scanning
    # scanner = EmailScanner()
    # scanner.start_automatic_scanning()
    # 
    # try:
    #     # Keep the script running
    #     while True:
    #         time.sleep(60)
    # except KeyboardInterrupt:
    #     scanner.stop_automatic_scanning()
    #     print("Scanner stopped.")