"""
Email Notifications Module

Handles sending email notifications using SendGrid API.
Provides functionality to send notifications about phishing alerts
and system events from the email automation scanner.
"""

import os
import logging
import json
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

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

class EmailNotifier:
    """Class to handle sending email notifications via SendGrid."""
    
    def __init__(self, config=None):
        """
        Initialize the email notifier with configuration.
        
        Args:
            config (dict): Configuration settings. If None, will load from environment.
        """
        self.config = config or {}
        self.api_key = os.environ.get('SENDGRID_API_KEY') or self.config.get('sendgrid_api_key')
        
        # Default sender details
        self.default_sender = self.config.get('sender_email', 'noreply@speedefender.com')
        self.sender_name = self.config.get('sender_name', 'SpeeDefender')
    
    def send_notification(self, recipient, subject, html_content, text_content=None):
        """
        Send an email notification.
        
        Args:
            recipient (str): Email address of the recipient
            subject (str): Email subject
            html_content (str): HTML content of the email
            text_content (str, optional): Plain text content as fallback
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        if not self.api_key:
            logger.error("SendGrid API key is not configured")
            return False
        
        try:
            # Create the email message
            from_email = Email(self.default_sender, self.sender_name)
            to_email = To(recipient)
            
            # Use plain text as fallback if provided
            content = Content("text/html", html_content)
            
            message = Mail(from_email, to_email, subject, content)
            
            # Add plain text version if provided
            if text_content:
                message.add_content(Content("text/plain", text_content))
            
            # Send the email
            sg = SendGridAPIClient(self.api_key)
            response = sg.send(message)
            
            # Log the response
            status_code = response.status_code
            
            if status_code >= 200 and status_code < 300:
                logger.info(f"Email notification sent successfully to {recipient}")
                return True
            else:
                logger.error(f"Failed to send email notification: Status code {status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
            return False
    
    def send_phishing_alert(self, recipient, email_data, analysis_results, action_taken):
        """
        Send a phishing alert notification.
        
        Args:
            recipient (str): Email address of the recipient
            email_data (dict): Original email data that triggered the alert
            analysis_results (dict): Analysis results
            action_taken (dict): Actions taken on the email
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        risk_level = analysis_results.get('risk_level', 'Unknown')
        
        # Create email subject based on risk level
        subject = f"[ALERT] {risk_level} Risk Phishing Email Detected"
        
        # Format the email HTML content
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #dddddd; border-radius: 5px;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <h1 style="color: #4e73df;">SpeeDefender</h1>
                    <p style="font-size: 16px; font-weight: bold;">Phishing Email Alert</p>
                </div>
                
                <div style="background-color: {self._get_risk_color(risk_level)}; color: white; padding: 10px; border-radius: 5px; margin-bottom: 20px;">
                    <h2 style="margin: 0;">{risk_level} Risk Level Detected</h2>
                </div>
                
                <h3>Email Details:</h3>
                <ul>
                    <li><strong>From:</strong> {email_data.get('from', 'Unknown')}</li>
                    <li><strong>Subject:</strong> {email_data.get('subject', 'No Subject')}</li>
                    <li><strong>Date:</strong> {email_data.get('date', 'Unknown')}</li>
                </ul>
                
                <h3>Analysis Results:</h3>
                <ul>
                    <li><strong>Suspicious Indicators:</strong> {analysis_results.get('suspicious_indicators', 0)}</li>
                    <li><strong>Risk Level:</strong> {risk_level}</li>
                </ul>
                
                <h3>Action Taken:</h3>
                <p>This email has been automatically <strong>{action_taken.get('action_taken', 'flagged')}</strong>.</p>
                
                <div style="background-color: #f8f9fc; padding: 15px; border-radius: 5px; margin-top: 20px;">
                    <p style="margin: 0;">For more details and to manage email security settings, please visit your SpeeDefender dashboard.</p>
                </div>
                
                <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #777777;">
                    <p>This is an automated notification from your SpeeDefender security system.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create plain text version as fallback
        text_content = f"""
        SpeeDefender Phishing Email Alert
        
        {risk_level} Risk Level Detected
        
        Email Details:
        - From: {email_data.get('from', 'Unknown')}
        - Subject: {email_data.get('subject', 'No Subject')}
        - Date: {email_data.get('date', 'Unknown')}
        
        Analysis Results:
        - Suspicious Indicators: {analysis_results.get('suspicious_indicators', 0)}
        - Risk Level: {risk_level}
        
        Action Taken:
        This email has been automatically {action_taken.get('action_taken', 'flagged')}.
        
        For more details and to manage email security settings, please visit your SpeeDefender dashboard.
        
        This is an automated notification from your SpeeDefender security system.
        """
        
        return self.send_notification(recipient, subject, html_content, text_content)
    
    def send_system_notification(self, recipient, subject, message, details=None):
        """
        Send a system notification email.
        
        Args:
            recipient (str): Email address of the recipient
            subject (str): Notification subject
            message (str): Main notification message
            details (dict, optional): Additional details to include
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        # Format the email HTML content
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #dddddd; border-radius: 5px;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <h1 style="color: #4e73df;">SpeeDefender</h1>
                    <p style="font-size: 16px; font-weight: bold;">System Notification</p>
                </div>
                
                <div style="background-color: #4e73df; color: white; padding: 10px; border-radius: 5px; margin-bottom: 20px;">
                    <h2 style="margin: 0;">{subject}</h2>
                </div>
                
                <p>{message}</p>
                
                {self._format_details_html(details) if details else ''}
                
                <div style="background-color: #f8f9fc; padding: 15px; border-radius: 5px; margin-top: 20px;">
                    <p style="margin: 0;">For more information, please visit your SpeeDefender dashboard.</p>
                </div>
                
                <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #777777;">
                    <p>This is an automated notification from your SpeeDefender security system.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create plain text version as fallback
        text_content = f"""
        SpeeDefender System Notification
        
        {subject}
        
        {message}
        
        {self._format_details_text(details) if details else ''}
        
        For more information, please visit your SpeeDefender dashboard.
        
        This is an automated notification from your SpeeDefender security system.
        """
        
        return self.send_notification(recipient, subject, html_content, text_content)
    
    def _get_risk_color(self, risk_level):
        """Get the color for a risk level."""
        colors = {
            'Critical': '#212529',
            'High': '#e74a3b',
            'Medium': '#f6c23e',
            'Low': '#36b9cc',
            'Very Low': '#adb5bd',
            'Safe': '#1cc88a',
            'Unknown': '#6c757d'
        }
        return colors.get(risk_level, '#6c757d')
    
    def _format_details_html(self, details):
        """Format details as HTML."""
        if not details:
            return ''
        
        html = '<h3>Additional Details:</h3><ul>'
        
        for key, value in details.items():
            # Format key with Title Case and replace underscores with spaces
            formatted_key = key.replace('_', ' ').title()
            html += f'<li><strong>{formatted_key}:</strong> {value}</li>'
        
        html += '</ul>'
        return html
    
    def _format_details_text(self, details):
        """Format details as plain text."""
        if not details:
            return ''
        
        text = 'Additional Details:\n'
        
        for key, value in details.items():
            # Format key with Title Case and replace underscores with spaces
            formatted_key = key.replace('_', ' ').title()
            text += f'- {formatted_key}: {value}\n'
        
        return text