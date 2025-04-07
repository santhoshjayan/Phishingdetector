"""
API Routes Module

Provides API endpoints for the email automation system and phishing detection.
"""

from flask import Blueprint, request, jsonify
import json
import os
from utils.email_automation.controller import AutomationController

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