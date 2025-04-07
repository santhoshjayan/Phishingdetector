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
                    "unread_only": True
                },
                "actions": {
                    "critical_action": "quarantine",  # quarantine, spam, tag, none
                    "high_action": "quarantine",
                    "medium_action": "tag",
                    "low_action": "tag",
                    "safe_action": "none",
                    "send_notifications": True,
                    "notification_recipients": ["admin@example.com"]
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
                subject = f"[ALERT] {risk_level} Risk Email Detected"
                message = f"""
                <html>
                <body>
                    <h2>Suspicious Email Detected</h2>
                    <p><strong>Risk Level:</strong> {risk_level}</p>
                    <p><strong>From:</strong> {email_data.get('from', '')}</p>
                    <p><strong>Subject:</strong> {email_data.get('subject', '')}</p>
                    <p><strong>Action Taken:</strong> {action_type}</p>
                    <hr>
                    <h3>Analysis Details:</h3>
                    <ul>
                        <li><strong>Suspicious Indicators:</strong> {analysis_results.get('suspicious_indicators', 0)}</li>
                    </ul>
                    <p>For more details, please check the security dashboard.</p>
                </body>
                </html>
                """
                
                sent = self.email_connector.send_notification(recipient, subject, message)
                if sent:
                    action_details["notification_sent"] = True
        
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
        
        # Process each email
        for email_data in emails:
            try:
                logger.info(f"Analyzing email from {email_data.get('from', '')} with subject: {email_data.get('subject', '')}")
                
                # Analyze the email
                analysis_results = analyze_email({
                    'from': email_data.get('from', ''),
                    'headers': email_data.get('headers', {}),
                    'content': email_data.get('content', '')
                })
                
                # Take appropriate action
                action = self._take_action(email_data['id'], email_data, analysis_results)
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