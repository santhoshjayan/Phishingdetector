"""
Email Automation Controller Module

Provides functionality to control and manage the email scanner.
"""

import os
import json
import logging
from datetime import datetime
import threading
from utils.email_automation.email_scanner import EmailScanner

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

class AutomationController:
    """Class to control email scanning automation."""
    
    def __init__(self):
        """Initialize the controller."""
        self.scanner = EmailScanner()
        self.scanner_thread = None
        self.scanner_running = False
        
        # Make sure necessary directories exist
        os.makedirs('config', exist_ok=True)
        os.makedirs('data', exist_ok=True)
    
    def update_config(self, config_data):
        """
        Update the scanner configuration.
        
        Args:
            config_data (dict): New configuration data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # First, update in-memory config
            if 'email_connection' in config_data:
                self.scanner.config['email_connection'] = config_data['email_connection']
            
            if 'scanning' in config_data:
                self.scanner.config['scanning'] = config_data['scanning']
            
            if 'actions' in config_data:
                self.scanner.config['actions'] = config_data['actions']
            
            # Save to file
            config_path = 'config/email_scanner_config.json'
            with open(config_path, 'w') as config_file:
                json.dump(self.scanner.config, config_file, indent=4)
            
            # Update scanner's email connector with new config if needed
            if 'email_connection' in config_data:
                self.scanner.email_connector.config = config_data['email_connection']
            
            logger.info("Email scanner configuration updated")
            return True
        except Exception as e:
            logger.error(f"Error updating configuration: {str(e)}")
            return False
    
    def get_config(self):
        """
        Get the current scanner configuration.
        
        Returns:
            dict: Current configuration
        """
        # Return a deep copy of config to avoid direct modification
        import copy
        config = copy.deepcopy(self.scanner.config)
        
        # Redact sensitive information like passwords
        if 'email_connection' in config and 'password' in config['email_connection']:
            config['email_connection']['password'] = '********'
        
        return config
    
    def test_email_connection(self):
        """
        Test the email connection.
        
        Returns:
            dict: Test results
        """
        try:
            # Try to connect to both IMAP and SMTP
            imap_success = self.scanner.email_connector.connect_imap()
            smtp_success = self.scanner.email_connector.connect_smtp()
            
            # Disconnect after testing
            self.scanner.email_connector.disconnect()
            
            return {
                "success": imap_success and smtp_success,
                "imap_connection": imap_success,
                "smtp_connection": smtp_success,
                "message": "Connection test successful" if (imap_success and smtp_success) else "Connection test failed"
            }
        except Exception as e:
            logger.error(f"Error testing connection: {str(e)}")
            return {
                "success": False,
                "imap_connection": False,
                "smtp_connection": False,
                "message": f"Error: {str(e)}"
            }
    
    def start_scanner(self):
        """
        Start the email scanner.
        
        Returns:
            dict: Result of the operation
        """
        if self.scanner_running:
            return {"success": False, "message": "Scanner is already running"}
        
        try:
            # Start the scanner in a separate thread
            self.scanner_running = True
            self.scanner_thread = threading.Thread(target=self._scanner_thread)
            self.scanner_thread.daemon = True
            self.scanner_thread.start()
            
            logger.info("Email scanner started")
            return {"success": True, "message": "Scanner started successfully"}
        except Exception as e:
            self.scanner_running = False
            logger.error(f"Error starting scanner: {str(e)}")
            return {"success": False, "message": f"Error: {str(e)}"}
    
    def _scanner_thread(self):
        """Thread function for running the scanner."""
        try:
            self.scanner.start_automatic_scanning()
            
            # Keep thread alive while scanner is running
            while self.scanner_running:
                import time
                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in scanner thread: {str(e)}")
        finally:
            self.scanner.stop_automatic_scanning()
            self.scanner_running = False
    
    def stop_scanner(self):
        """
        Stop the email scanner.
        
        Returns:
            dict: Result of the operation
        """
        if not self.scanner_running:
            return {"success": False, "message": "Scanner is not running"}
        
        try:
            # Stop the scanner
            self.scanner_running = False
            self.scanner.stop_automatic_scanning()
            
            # Wait for thread to finish
            if self.scanner_thread and self.scanner_thread.is_alive():
                self.scanner_thread.join(2.0)
            
            logger.info("Email scanner stopped")
            return {"success": True, "message": "Scanner stopped successfully"}
        except Exception as e:
            logger.error(f"Error stopping scanner: {str(e)}")
            return {"success": False, "message": f"Error: {str(e)}"}
    
    def get_scanner_status(self):
        """
        Get the current status of the scanner.
        
        Returns:
            dict: Status information
        """
        # Get basic status from scanner
        status = self.scanner.get_status()
        
        # Add controller-specific information
        status.update({
            "controller_status": {
                "thread_running": self.scanner_thread.is_alive() if self.scanner_thread else False,
                "controller_running": self.scanner_running
            }
        })
        
        return status
    
    def run_manual_scan(self):
        """
        Run a manual scan.
        
        Returns:
            dict: Scan results
        """
        try:
            logger.info("Starting manual scan")
            actions = self.scanner.scan_and_act()
            
            logger.info(f"Manual scan completed. Took {len(actions)} actions.")
            return {
                "success": True,
                "message": f"Scan completed. Processed {len(actions)} emails.",
                "actions": actions
            }
        except Exception as e:
            logger.error(f"Error running manual scan: {str(e)}")
            return {
                "success": False,
                "message": f"Error: {str(e)}",
                "actions": []
            }
    
    def get_action_history(self, limit=100):
        """
        Get history of actions taken by the scanner.
        
        Args:
            limit (int): Maximum number of actions to return
            
        Returns:
            list: Action history
        """
        try:
            actions_log_path = 'data/email_actions.json'
            if not os.path.exists(actions_log_path):
                return []
            
            with open(actions_log_path, 'r') as f:
                actions = json.load(f)
            
            # Return most recent actions up to the limit
            return actions[-limit:] if limit < len(actions) else actions
        except Exception as e:
            logger.error(f"Error getting action history: {str(e)}")
            return []
    
    def get_statistics(self):
        """
        Get statistics on scanner operation.
        
        Returns:
            dict: Statistics information
        """
        try:
            # Get action history
            actions = self.get_action_history(limit=1000)  # Use more data for better stats
            
            if not actions:
                return {
                    "total_emails": 0,
                    "by_risk_level": {
                        "Critical": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Safe": 0
                    },
                    "by_action": {
                        "quarantine": 0,
                        "spam": 0,
                        "tag": 0,
                        "none": 0
                    },
                    "success_rate": 0
                }
            
            # Count by risk level
            risk_counts = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Safe": 0
            }
            
            # Count by action type
            action_counts = {
                "quarantine": 0,
                "spam": 0,
                "tag": 0,
                "none": 0
            }
            
            # Count successful actions
            success_count = 0
            
            for action in actions:
                # Count by risk level
                risk_level = action.get('risk_level', 'Unknown')
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1
                
                # Count by action type
                action_type = action.get('action_taken', 'none')
                if action_type in action_counts:
                    action_counts[action_type] += 1
                
                # Count successful actions
                if action.get('success', False):
                    success_count += 1
            
            # Calculate success rate
            success_rate = (success_count / len(actions)) * 100 if actions else 0
            
            return {
                "total_emails": len(actions),
                "by_risk_level": risk_counts,
                "by_action": action_counts,
                "success_rate": success_rate
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {}