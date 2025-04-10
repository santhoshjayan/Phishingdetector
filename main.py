from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import json
import collections
from datetime import datetime, timedelta
from phishing_detector import analyze_url, is_valid_url
from utils.email_analyzer import analyze_email
from utils.pdf_generator import generate_report_pdf
from api_routes import api_bp

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "temporary_secret_key")

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple user model
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Temporary users - replace with database in production
users = {'admin@example.com': {'password': 'admin123'}}

# Pending access requests
pending_requests = []

@app.route('/request_access', methods=['GET', 'POST'])
def request_access():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        organization = request.form.get('organization')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        reason = request.form.get('reason')
        
        # Validate passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('request_access'))
            
        # Validate password strength
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('request_access'))
            
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Store the request (in production, save to database)
        pending_requests.append({
            'name': name,
            'email': email,
            'organization': organization,
            'password': hashed_password,
            'reason': reason,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        flash('Your access request has been submitted for approval', 'success')
        return redirect(url_for('login'))
    
    return render_template('request_access.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if email in users and users[email]['password'] == password:
            user = User(email)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Register API blueprint
app.register_blueprint(api_bp)

# Create necessary directories
HISTORY_DIR = "analysis_history"
os.makedirs(HISTORY_DIR, exist_ok=True)
os.makedirs("config", exist_ok=True)
os.makedirs("data/scanned_emails", exist_ok=True)

def json_serializable_results(results):
    """
    Convert any non-JSON serializable objects in the results to their string 
    representation to make the entire results dictionary JSON serializable.
    """
    # Create a copy of the results to avoid modifying the original
    processed_results = results.copy()
    
    # Process domain_info section which contains datetime objects
    if 'domain_info' in processed_results and 'whois_info' in processed_results['domain_info']:
        whois_info = processed_results['domain_info']['whois_info'].copy()
        
        # Convert creation_date to string
        if 'creation_date' in whois_info and whois_info['creation_date'] is not None:
            if isinstance(whois_info['creation_date'], list):
                whois_info['creation_date'] = [str(d) for d in whois_info['creation_date']]
            else:
                whois_info['creation_date'] = str(whois_info['creation_date'])
        
        # Convert expiration_date to string
        if 'expiration_date' in whois_info and whois_info['expiration_date'] is not None:
            if isinstance(whois_info['expiration_date'], list):
                whois_info['expiration_date'] = [str(d) for d in whois_info['expiration_date']]
            else:
                whois_info['expiration_date'] = str(whois_info['expiration_date'])
        
        # Update the results with the processed whois_info
        processed_results['domain_info']['whois_info'] = whois_info
    
    return processed_results

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'No URL provided'
        }), 400
    
    # Check if URL is valid
    if not is_valid_url(url):
        return jsonify({
            'success': False,
            'message': 'Invalid URL format'
        }), 400
    
    # Analyze the URL
    try:
        results = analyze_url(url, verbose=False)
        
        # Make the results JSON serializable
        serializable_results = json_serializable_results(results)
        
        # Save the analysis to history
        save_to_history(url, serializable_results)
        
        return jsonify({
            'success': True,
            'results': serializable_results
        })
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing URL: {str(e)}'
        }), 500

@app.route('/history')
@login_required
def history():
    history_files = os.listdir(HISTORY_DIR)
    history_data = []
    
    for file in sorted(history_files, reverse=True)[:20]:  # Get the 20 most recent entries
        if file.endswith('.json'):
            with open(os.path.join(HISTORY_DIR, file), 'r') as f:
                try:
                    data = json.load(f)
                    history_data.append(data)
                except:
                    continue
    
    return render_template('history.html', history=history_data)

@app.route('/batch_analysis')
@login_required
def batch_analysis():
    return render_template('batch_analysis.html')

@app.route('/email_analysis', methods=['GET', 'POST'])
@login_required
def email_analysis():
    if request.method == 'POST':
        try:
            # Get form data
            sender = request.form.get('sender', '')
            subject = request.form.get('subject', '')
            headers_text = request.form.get('headers', '')
            content = request.form.get('content', '')
            
            # Parse headers
            headers = {}
            if headers_text:
                for line in headers_text.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
            
            # Create email data dictionary
            email_data = {
                'from': sender,
                'subject': subject,
                'headers': headers,
                'content': content
            }
            
            # Analyze the email
            results = analyze_email(email_data)
            
            # Make the results JSON serializable
            serializable_results = json_serializable_results(results)
            
            # Save to history
            save_email_to_history(email_data, serializable_results)
            
            return render_template('email_analysis.html', results=results)
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            return render_template('email_analysis.html', error=f"Error analyzing email: {str(e)}")
    
    return render_template('email_analysis.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all history files
    history_files = [f for f in os.listdir(HISTORY_DIR) if f.endswith('.json')]
    
    # Initialize analytics data
    analytics = {
        'total_urls': 0,
        'total_emails': 0,
        'risk_levels': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Very Low': 0, 'Safe': 0},
        'suspicious_patterns': collections.Counter(),
        'tld_distribution': collections.Counter(),
        'daily_scans': collections.Counter(),
        'email_indicators': collections.Counter(),
        'recent_high_risk': [],
        'recent_high_risk_emails': []
    }
    
    # Process each history file
    for file in history_files:
        with open(os.path.join(HISTORY_DIR, file), 'r') as f:
            try:
                data = json.load(f)
                
                # Determine if this is a URL or email analysis
                is_email = 'email' in data and 'subject' in data
                
                # Count total items by type
                if is_email:
                    analytics['total_emails'] += 1
                else:
                    analytics['total_urls'] += 1
                
                # Count risk levels
                risk_level = data.get('risk_level', 'Unknown')
                if risk_level in analytics['risk_levels']:
                    analytics['risk_levels'][risk_level] += 1
                
                # Extract date for daily scans
                timestamp = data.get('timestamp', '')
                if timestamp:
                    date = timestamp.split(' ')[0]  # Extract just the date part
                    analytics['daily_scans'][date] += 1
                
                if is_email:
                    # Process email-specific data
                    
                    # Extract top email risk factors
                    if 'risk_factors' in data:
                        for factor, score in data['risk_factors'].items():
                            if score > 0:
                                factor_name = factor.replace('_risk', '').title()
                                analytics['email_indicators'][factor_name] += score
                    
                    # Collect recent high risk emails (up to 5)
                    if risk_level in ['Critical', 'High'] and len(analytics['recent_high_risk_emails']) < 5:
                        analytics['recent_high_risk_emails'].append({
                            'email': data.get('email', ''),
                            'subject': data.get('subject', ''),
                            'timestamp': timestamp,
                            'indicators': data.get('suspicious_indicators', 0)
                        })
                
                else:
                    # Process URL-specific data
                    
                    # Extract TLD
                    url = data.get('url', '')
                    if '.' in url:
                        tld = url.split('.')[-1].split('/')[0]  # Get the TLD
                        analytics['tld_distribution'][tld] += 1
                    
                    # Count suspicious patterns
                    for pattern in data.get('url_patterns', {}).get('suspicious_patterns', []):
                        analytics['suspicious_patterns'][pattern] += 1
                    
                    # Collect recent high risk URLs (up to 5)
                    if risk_level in ['Critical', 'High'] and len(analytics['recent_high_risk']) < 5:
                        analytics['recent_high_risk'].append({
                            'url': data.get('url', ''),
                            'timestamp': timestamp,
                            'indicators': data.get('suspicious_indicators', 0)
                        })
                
            except Exception as e:
                logger.error(f"Error processing history file {file}: {str(e)}")
    
    # Get last 7 days for chart
    today = datetime.now().date()
    last_7_days = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
    last_7_days.reverse()  # Order from oldest to newest
    
    # Separate URLs and emails for each day
    daily_url_scans = collections.Counter()
    daily_email_scans = collections.Counter()
    
    # Process each history file to count URLs and emails by date
    for file in history_files:
        with open(os.path.join(HISTORY_DIR, file), 'r') as f:
            try:
                data = json.load(f)
                timestamp = data.get('timestamp', '')
                if timestamp:
                    date = timestamp.split(' ')[0]  # Extract just the date part
                    # Determine if this is a URL or email analysis
                    is_email = 'email' in data and 'subject' in data
                    if is_email:
                        daily_email_scans[date] += 1
                    else:
                        daily_url_scans[date] += 1
            except Exception as e:
                pass  # Already logged above
    
    # Prepare daily scan data for chart
    daily_url_data = [daily_url_scans.get(day, 0) for day in last_7_days]
    daily_email_data = [daily_email_scans.get(day, 0) for day in last_7_days]
    
    # Get top suspicious patterns (top 5)
    top_patterns = dict(analytics['suspicious_patterns'].most_common(5))
    
    # Get TLD distribution (top 5)
    top_tlds = dict(analytics['tld_distribution'].most_common(5))
    
    # Get top email indicators (top 5)
    top_email_indicators = dict(analytics['email_indicators'].most_common(5))
    
    return render_template('dashboard.html', 
                          analytics=analytics, 
                          daily_scan_labels=json.dumps(last_7_days),
                          daily_url_data=json.dumps(daily_url_data),
                          daily_email_data=json.dumps(daily_email_data),
                          top_patterns=json.dumps(top_patterns),
                          top_tlds=json.dumps(top_tlds),
                          top_email_indicators=json.dumps(top_email_indicators))

@app.route('/api/docs')
@login_required
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/analyze', methods=['GET'])
def api_analyze():
    url = request.args.get('url')
    
    if not url:
        return jsonify({
            'success': False,
            'message': 'No URL provided. Please add ?url=https://example.com to your request.',
            'product': 'SpeeDefender API'
        }), 400
    
    if not is_valid_url(url):
        return jsonify({
            'success': False,
            'message': 'Invalid URL format',
            'product': 'SpeeDefender API'
        }), 400
    
    try:
        results = analyze_url(url, verbose=False)
        # Make the results JSON serializable
        serializable_results = json_serializable_results(results)
        return jsonify({
            'success': True,
            'results': serializable_results,
            'product': 'SpeeDefender API',
            'version': '1.0'
        })
    except Exception as e:
        logger.error(f"API Error analyzing URL: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing URL: {str(e)}',
            'product': 'SpeeDefender API'
        }), 500

@app.route('/api/analyze_email', methods=['POST'])
def api_analyze_email():
    """API endpoint for analyzing emails"""
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'Request must be JSON format',
            'product': 'SpeeDefender API'
        }), 400
    
    data = request.get_json()
    
    # Check required fields
    required_fields = ['from', 'headers', 'content']
    for field in required_fields:
        if field not in data:
            return jsonify({
                'success': False,
                'message': f'Missing required field: {field}',
                'product': 'SpeeDefender API'
            }), 400
    
    try:
        # Create email data dictionary
        email_data = {
            'from': data.get('from', ''),
            'subject': data.get('headers', {}).get('Subject', '') or data.get('headers', {}).get('subject', ''),
            'headers': data.get('headers', {}),
            'content': data.get('content', '')
        }
        
        # Analyze the email
        results = analyze_email(email_data)
        
        # Make the results JSON serializable
        serializable_results = json_serializable_results(results)
        
        # Save the analysis to history
        save_email_to_history(email_data, serializable_results)
        
        return jsonify({
            'success': True,
            'results': serializable_results,
            'product': 'SpeeDefender API',
            'version': '1.0'
        })
    except Exception as e:
        logger.error(f"API Error analyzing email: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing email: {str(e)}',
            'product': 'SpeeDefender API'
        }), 500

def save_to_history(url, results):
    """Save the URL analysis results to a JSON file in the history directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = url.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{timestamp}_{domain}.json"
    
    # Add timestamp to results
    results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(os.path.join(HISTORY_DIR, filename), 'w') as f:
        json.dump(results, f)

def save_email_to_history(email_data, results):
    """Save the email analysis results to a JSON file in the history directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sender = email_data.get('from', '').replace("@", "_at_").replace(".", "_")
    filename = f"{timestamp}_email_{sender}.json"
    
    # Add timestamp to results
    results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(os.path.join(HISTORY_DIR, filename), 'w') as f:
        json.dump(results, f)

# Routes for PDF reports
@app.route('/export/url_report/<path:id>', methods=['GET'])
def export_url_report(id):
    """Generate and download a PDF report for URL analysis"""
    try:
        # Find the URL analysis result by ID (timestamp)
        for file in os.listdir(HISTORY_DIR):
            if file.startswith(id) and file.endswith('.json') and '_email_' not in file:
                with open(os.path.join(HISTORY_DIR, file), 'r') as f:
                    results = json.load(f)
                    
                    # Generate PDF report
                    success, pdf_path = generate_report_pdf(results, 'url')
                    
                    if success:
                        # Extract filename from path
                        filename = os.path.basename(pdf_path)
                        # Return the PDF file
                        return send_from_directory(
                            os.path.join(os.getcwd(), 'static', 'reports'),
                            filename,
                            as_attachment=True,
                            download_name=f"SpeeDefender_URL_Report_{id}.pdf"
                        )
                    else:
                        return jsonify({
                            'success': False,
                            'message': f'Error generating PDF report: {pdf_path}'
                        }), 500
                
        # If no matching file found
        return jsonify({
            'success': False,
            'message': 'Analysis not found'
        }), 404
    except Exception as e:
        logger.error(f"Error exporting URL report: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error exporting PDF report: {str(e)}'
        }), 500

@app.route('/export/email_report/<path:id>', methods=['GET'])
def export_email_report(id):
    """Generate and download a PDF report for email analysis"""
    try:
        # Find the email analysis result by ID (timestamp)
        for file in os.listdir(HISTORY_DIR):
            if file.startswith(id) and file.endswith('.json') and '_email_' in file:
                with open(os.path.join(HISTORY_DIR, file), 'r') as f:
                    results = json.load(f)
                    
                    # Generate PDF report
                    success, pdf_path = generate_report_pdf(results, 'email')
                    
                    if success:
                        # Extract filename from path
                        filename = os.path.basename(pdf_path)
                        # Return the PDF file
                        return send_from_directory(
                            os.path.join(os.getcwd(), 'static', 'reports'),
                            filename,
                            as_attachment=True,
                            download_name=f"SpeeDefender_Email_Report_{id}.pdf"
                        )
                    else:
                        return jsonify({
                            'success': False,
                            'message': f'Error generating PDF report: {pdf_path}'
                        }), 500
                
        # If no matching file found
        return jsonify({
            'success': False,
            'message': 'Analysis not found'
        }), 404
    except Exception as e:
        logger.error(f"Error exporting email report: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error exporting PDF report: {str(e)}'
        }), 500

# Email Automation route
@app.route('/admin/approve_requests')
@login_required
def approve_requests():
    if request.args.get('approve'):
        email = request.args.get('email')
        # Find and approve the request
        for req in pending_requests:
            if req['email'] == email:
                users[email] = {'password': req['password']}
                pending_requests.remove(req)
                flash(f'Access approved for {email}', 'success')
                break
    elif request.args.get('reject'):
        email = request.args.get('email')
        reason = request.args.get('reason', 'No reason provided')
        # Find and reject the request
        for req in pending_requests:
            if req['email'] == email:
                pending_requests.remove(req)
                flash(f'Request rejected for {email}. Reason: {reason}', 'warning')
                break
    if request.args.get('approve') or request.args.get('reject'):
        return redirect(url_for('approve_requests'))
    
    return render_template('admin/approve_requests.html', requests=pending_requests)

@app.route('/email_automation')
@login_required
def email_automation():
    """Email Automation Dashboard"""
    return render_template('email_automation.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7856, debug=True)