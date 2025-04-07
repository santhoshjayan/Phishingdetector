"""
API Routes Module

Provides API endpoints for the email automation system and phishing detection.
"""

from flask import Blueprint, request, jsonify
import json
import os
from utils.email_automation.controller import AutomationController
from utils.email_automation.email_notifications import EmailNotifier

# Create API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Initialize controllers
email_automation_controller = AutomationController()

# Email Automation API Routes
@api_bp.route('/email_automation/status', methods=['GET'])
def email_automation_status():
    """Get the current status of the email automation system."""
    status = email_automation_controller.get_scanner_status()
    return jsonify(status)

@api_bp.route('/email_automation/config', methods=['GET'])
def get_email_automation_config():
    """Get the email automation configuration."""
    config = email_automation_controller.get_config()
    return jsonify(config)

@api_bp.route('/email_automation/config', methods=['POST'])
def update_email_automation_config():
    """Update the email automation configuration."""
    config = request.json
    success = email_automation_controller.update_config(config)
    
    if success:
        return jsonify({"success": True, "message": "Configuration updated successfully"})
    else:
        return jsonify({"success": False, "message": "Failed to update configuration"})

@api_bp.route('/email_automation/test_connection', methods=['GET'])
def test_email_connection():
    """Test the email connection."""
    result = email_automation_controller.test_email_connection()
    return jsonify(result)

@api_bp.route('/email_automation/test_notification', methods=['POST'])
def test_notification():
    """Test sending a notification email using SendGrid."""
    data = request.json
    
    # Check if SendGrid API key is provided in request or available in environment
    api_key = data.get('api_key') or os.environ.get('SENDGRID_API_KEY')
    
    if not api_key:
        return jsonify({
            'success': False, 
            'message': 'SendGrid API key is required. Please provide it in the request or set the SENDGRID_API_KEY environment variable.'
        })
    
    # Required parameters
    recipient = data.get('recipient')
    if not recipient:
        return jsonify({
            'success': False, 
            'message': 'Recipient email address is required'
        })
    
    # Configure sender (use default if not provided)
    sender_email = data.get('sender_email', 'noreply@speedefender.com')
    sender_name = data.get('sender_name', 'SpeeDefender')
    
    # Create notifier with the provided API key
    notifier = EmailNotifier({
        'sendgrid_api_key': api_key,
        'sender_email': sender_email,
        'sender_name': sender_name
    })
    
    # Send a test email
    subject = "SpeeDefender Notification Test"
    html_content = """
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
        <h2 style="color: #4a6ee0;">SpeeDefender Notification Test</h2>
        <p>This is a test email from SpeeDefender to verify your notification settings.</p>
        <p>If you received this email, your notification system is configured correctly.</p>
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666;">
            <p>This is an automated message from SpeeDefender. Please do not reply to this email.</p>
        </div>
    </div>
    """
    
    text_content = "SpeeDefender Notification Test\n\nThis is a test email from SpeeDefender to verify your notification settings.\nIf you received this email, your notification system is configured correctly."
    
    try:
        success = notifier.send_notification(recipient, subject, html_content, text_content)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Test email sent successfully to {recipient}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send test email. Please check your SendGrid configuration.'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error sending test email: {str(e)}'
        })

@api_bp.route('/email_automation/start', methods=['POST'])
def start_email_automation():
    """Start the email automation scanner."""
    result = email_automation_controller.start_scanner()
    return jsonify(result)

@api_bp.route('/email_automation/stop', methods=['POST'])
def stop_email_automation():
    """Stop the email automation scanner."""
    result = email_automation_controller.stop_scanner()
    return jsonify(result)

@api_bp.route('/email_automation/scan', methods=['POST'])
def manual_email_scan():
    """Run a manual email scan."""
    result = email_automation_controller.run_manual_scan()
    return jsonify(result)

@api_bp.route('/email_automation/history', methods=['GET'])
def get_email_automation_history():
    """Get the email automation action history."""
    limit = request.args.get('limit', 20, type=int)
    history = email_automation_controller.get_action_history(limit=limit)
    return jsonify(history)

@api_bp.route('/email_automation/statistics', methods=['GET'])
def get_email_automation_statistics():
    """Get the email automation statistics."""
    statistics = email_automation_controller.get_statistics()
    return jsonify(statistics)

# URL Analysis API Routes
@api_bp.route('/analyze/url', methods=['POST'])
def api_analyze_url():
    """API endpoint for analyzing URLs."""
    from phishing_detector import analyze_url, is_valid_url
    
    data = request.json
    if not data or not data.get('url'):
        return jsonify({
            'success': False, 
            'message': 'URL parameter is required'
        })
    
    url = data.get('url')
    
    # Validate URL
    if not is_valid_url(url):
        return jsonify({
            'success': False, 
            'message': 'Invalid URL format'
        })
    
    # Analyze the URL
    try:
        results = analyze_url(url, verbose=False)
        
        # Save to history if requested
        if data.get('save_to_history', True):
            from main import save_to_history
            save_to_history(url, results)
        
        return jsonify({
            'success': True,
            'results': results
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error analyzing URL: {str(e)}'
        })

# Email Analysis API Routes
@api_bp.route('/analyze/email', methods=['POST'])
def api_analyze_email():
    """API endpoint for analyzing emails."""
    from utils.email_analyzer import analyze_email, is_valid_email
    
    data = request.json
    if not data:
        return jsonify({
            'success': False, 
            'message': 'Email data is required'
        })
    
    # Check for required fields
    required_fields = ['from', 'headers', 'content']
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return jsonify({
            'success': False, 
            'message': f'Missing required fields: {", ".join(missing_fields)}'
        })
    
    # Validate sender email
    if not is_valid_email(data.get('from', '')):
        return jsonify({
            'success': False, 
            'message': 'Invalid sender email format'
        })
    
    # Analyze the email
    try:
        results = analyze_email(data)
        
        # Save to history if requested
        if data.get('save_to_history', True):
            from main import save_email_to_history
            save_email_to_history(data, results)
        
        return jsonify({
            'success': True,
            'results': results
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error analyzing email: {str(e)}'
        })