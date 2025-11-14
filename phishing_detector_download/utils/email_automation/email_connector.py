"""
Email Connector Module

Handles connections to email services via IMAP, POP3, and SMTP protocols.
Provides functionality to read, scan, and take actions on emails.
"""

import imaplib
import email
import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json

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

class EmailConnector:
    """Class to handle email connections and operations."""
    
    def __init__(self, config=None):
        """
        Initialize the email connector with configuration.
        
        Args:
            config (dict): Configuration with email server details.
                If None, will try to load from config file.
        """
        self.config = config or self._load_config()
        self.imap_connection = None
        self.smtp_connection = None
    
    def _load_config(self):
        """Load email configuration from file."""
        config_path = 'config/email_config.json'
        
        # Create default config if it doesn't exist
        if not os.path.exists(config_path):
            os.makedirs('config', exist_ok=True)
            default_config = {
                'imap_server': 'imap.example.com',
                'imap_port': 993,
                'smtp_server': 'smtp.example.com',
                'smtp_port': 587,
                'email': 'your_email@example.com',
                'password': 'your_password',
                'use_ssl': True,
                'scan_folder': 'INBOX',
                'spam_folder': 'Spam',
                'quarantine_folder': 'Quarantine',
                'risk_threshold': 'Medium'
            }
            
            with open(config_path, 'w') as config_file:
                json.dump(default_config, config_file, indent=4)
            
            logger.info(f"Created default config at {config_path}. Please update with your email details.")
        
        try:
            with open(config_path, 'r') as config_file:
                return json.load(config_file)
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            return {}
    
    def connect_imap(self):
        """
        Connect to the IMAP server.
        
        Returns:
            bool: True if connection successful, False otherwise.
        """
        try:
            if self.config.get('use_ssl', True):
                self.imap_connection = imaplib.IMAP4_SSL(
                    self.config.get('imap_server', ''), 
                    self.config.get('imap_port', 993)
                )
            else:
                self.imap_connection = imaplib.IMAP4(
                    self.config.get('imap_server', ''), 
                    self.config.get('imap_port', 143)
                )
            
            self.imap_connection.login(
                self.config.get('email', ''), 
                self.config.get('password', '')
            )
            
            logger.info(f"Connected to IMAP server: {self.config.get('imap_server')}")
            return True
        except Exception as e:
            logger.error(f"IMAP connection error: {str(e)}")
            return False
    
    def connect_smtp(self):
        """
        Connect to the SMTP server.
        
        Returns:
            bool: True if connection successful, False otherwise.
        """
        try:
            if self.config.get('use_ssl', True):
                self.smtp_connection = smtplib.SMTP_SSL(
                    self.config.get('smtp_server', ''), 
                    self.config.get('smtp_port', 465)
                )
            else:
                self.smtp_connection = smtplib.SMTP(
                    self.config.get('smtp_server', ''), 
                    self.config.get('smtp_port', 587)
                )
                self.smtp_connection.starttls()
            
            self.smtp_connection.login(
                self.config.get('email', ''), 
                self.config.get('password', '')
            )
            
            logger.info(f"Connected to SMTP server: {self.config.get('smtp_server')}")
            return True
        except Exception as e:
            logger.error(f"SMTP connection error: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from all active connections."""
        if self.imap_connection:
            try:
                self.imap_connection.logout()
            except:
                pass
            self.imap_connection = None
        
        if self.smtp_connection:
            try:
                self.smtp_connection.quit()
            except:
                pass
            self.smtp_connection = None
        
        logger.info("Disconnected from email servers")
    
    def get_emails(self, folder='INBOX', limit=10, unread_only=True):
        """
        Fetch emails from the specified folder.
        
        Args:
            folder (str): Folder to scan, default is INBOX
            limit (int): Maximum number of emails to fetch
            unread_only (bool): Whether to fetch only unread emails
            
        Returns:
            list: List of email data dictionaries
        """
        if not self.imap_connection:
            if not self.connect_imap():
                return []
        
        emails = []
        try:
            folder_to_scan = self.config.get('scan_folder', folder)
            status, select_data = self.imap_connection.select(folder_to_scan)
            
            if status != 'OK':
                logger.error(f"Error selecting folder: {folder_to_scan}")
                return []
            
            search_criterion = 'UNSEEN' if unread_only else 'ALL'
            status, data = self.imap_connection.search(None, search_criterion)
            
            if status != 'OK':
                logger.error("Error searching for emails")
                return []
            
            email_ids = data[0].split()
            
            # Get the most recent emails (up to the limit)
            email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            
            for email_id in email_ids:
                status, data = self.imap_connection.fetch(email_id, '(RFC822)')
                
                if status != 'OK':
                    logger.error(f"Error fetching email ID: {email_id}")
                    continue
                
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                
                # Extract email data
                email_data = {
                    'id': email_id.decode('utf-8'),
                    'from': email_message.get('From', ''),
                    'to': email_message.get('To', ''),
                    'subject': email_message.get('Subject', ''),
                    'date': email_message.get('Date', ''),
                    'content': '',
                    'headers': {key: email_message.get(key, '') for key in email_message.keys()},
                }
                
                # Get email content
                if email_message.is_multipart():
                    for part in email_message.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get('Content-Disposition', ''))
                        
                        # Skip attachments
                        if 'attachment' in content_disposition:
                            continue
                        
                        # Get text content
                        if content_type == 'text/plain' or content_type == 'text/html':
                            try:
                                body = part.get_payload(decode=True).decode('utf-8')
                                email_data['content'] += body
                            except:
                                pass
                else:
                    try:
                        body = email_message.get_payload(decode=True).decode('utf-8')
                        email_data['content'] = body
                    except:
                        pass
                
                emails.append(email_data)
            
            logger.info(f"Retrieved {len(emails)} emails from {folder_to_scan}")
            return emails
        except Exception as e:
            logger.error(f"Error getting emails: {str(e)}")
            return []
    
    def move_to_folder(self, email_id, target_folder):
        """
        Move an email to a specified folder.
        
        Args:
            email_id (str): ID of the email to move
            target_folder (str): Destination folder
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.imap_connection:
            if not self.connect_imap():
                return False
        
        try:
            # Make sure the target folder exists
            self._ensure_folder_exists(target_folder)
            
            # Copy the email to the target folder
            self.imap_connection.select('INBOX')
            status, data = self.imap_connection.copy(email_id, target_folder)
            
            if status != 'OK':
                logger.error(f"Error copying email to {target_folder}")
                return False
            
            # Mark the original email for deletion
            self.imap_connection.store(email_id, '+FLAGS', '\\Deleted')
            self.imap_connection.expunge()
            
            logger.info(f"Moved email {email_id} to {target_folder}")
            return True
        except Exception as e:
            logger.error(f"Error moving email: {str(e)}")
            return False
    
    def _ensure_folder_exists(self, folder_name):
        """
        Check if a folder exists, create it if it doesn't.
        
        Args:
            folder_name (str): Name of the folder to check/create
        """
        try:
            status, data = self.imap_connection.list('', folder_name)
            if status != 'OK' or not data[0]:
                # Folder doesn't exist, create it
                self.imap_connection.create(folder_name)
                logger.info(f"Created folder: {folder_name}")
        except Exception as e:
            logger.error(f"Error checking/creating folder {folder_name}: {str(e)}")
    
    def mark_as_read(self, email_id):
        """
        Mark an email as read.
        
        Args:
            email_id (str): ID of the email to mark
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.imap_connection:
            if not self.connect_imap():
                return False
        
        try:
            self.imap_connection.store(email_id, '+FLAGS', '\\Seen')
            logger.info(f"Marked email {email_id} as read")
            return True
        except Exception as e:
            logger.error(f"Error marking email as read: {str(e)}")
            return False
    
    def send_notification(self, recipient, subject, message):
        """
        Send a notification email.
        
        Args:
            recipient (str): Email address of recipient
            subject (str): Email subject
            message (str): Email message content
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.smtp_connection:
            if not self.connect_smtp():
                return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.get('email', '')
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'html'))
            
            self.smtp_connection.send_message(msg)
            logger.info(f"Sent notification to {recipient}")
            return True
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False