from flask import Flask, render_template, request, jsonify, redirect, url_for
import logging
import os
import json
import collections
from datetime import datetime, timedelta
from phishing_detector import analyze_url, is_valid_url
from utils.email_analyzer import analyze_email

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "temporary_secret_key")

# Create a directory to store analysis history
HISTORY_DIR = "analysis_history"
os.makedirs(HISTORY_DIR, exist_ok=True)

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
def batch_analysis():
    return render_template('batch_analysis.html')

@app.route('/email_analysis', methods=['GET', 'POST'])
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
            
            # Save to history (could be implemented similar to URL history)
            # save_email_to_history(email_data, results)
            
            return render_template('email_analysis.html', results=results)
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            return render_template('email_analysis.html', error=f"Error analyzing email: {str(e)}")
    
    return render_template('email_analysis.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/dashboard')
def dashboard():
    # Get all history files
    history_files = [f for f in os.listdir(HISTORY_DIR) if f.endswith('.json')]
    
    # Initialize analytics data
    analytics = {
        'total_urls': len(history_files),
        'risk_levels': {'High': 0, 'Medium': 0, 'Low': 0, 'Safe': 0},
        'suspicious_patterns': collections.Counter(),
        'tld_distribution': collections.Counter(),
        'daily_scans': collections.Counter(),
        'recent_high_risk': []
    }
    
    # Process each history file
    for file in history_files:
        with open(os.path.join(HISTORY_DIR, file), 'r') as f:
            try:
                data = json.load(f)
                
                # Count risk levels
                risk_level = data.get('risk_level', 'Unknown')
                analytics['risk_levels'][risk_level] = analytics['risk_levels'].get(risk_level, 0) + 1
                
                # Extract date for daily scans
                timestamp = data.get('timestamp', '')
                if timestamp:
                    date = timestamp.split(' ')[0]  # Extract just the date part
                    analytics['daily_scans'][date] += 1
                
                # Extract TLD
                url = data.get('url', '')
                if '.' in url:
                    tld = url.split('.')[-1].split('/')[0]  # Get the TLD
                    analytics['tld_distribution'][tld] += 1
                
                # Count suspicious patterns
                for pattern in data.get('url_patterns', {}).get('suspicious_patterns', []):
                    analytics['suspicious_patterns'][pattern] += 1
                
                # Collect recent high risk URLs (up to 5)
                if risk_level == 'High' and len(analytics['recent_high_risk']) < 5:
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
    
    # Prepare daily scan data for chart
    daily_scan_data = [analytics['daily_scans'].get(day, 0) for day in last_7_days]
    
    # Get top suspicious patterns (top 5)
    top_patterns = dict(analytics['suspicious_patterns'].most_common(5))
    
    # Get TLD distribution (top 5)
    top_tlds = dict(analytics['tld_distribution'].most_common(5))
    
    return render_template('dashboard.html', 
                          analytics=analytics, 
                          daily_scan_labels=json.dumps(last_7_days),
                          daily_scan_data=json.dumps(daily_scan_data),
                          top_patterns=json.dumps(top_patterns),
                          top_tlds=json.dumps(top_tlds))

@app.route('/api/docs')
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

def save_to_history(url, results):
    """Save the analysis results to a JSON file in the history directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = url.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{timestamp}_{domain}.json"
    
    # Add timestamp to results
    results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(os.path.join(HISTORY_DIR, filename), 'w') as f:
        json.dump(results, f)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)