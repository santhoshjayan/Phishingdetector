from flask import Flask, render_template, request, jsonify, redirect, url_for
import logging
import os
import json
from datetime import datetime
from phishing_detector import analyze_url, is_valid_url
import re

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

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/analyze', methods=['GET'])
def api_analyze():
    url = request.args.get('url')

    if not url:
        return jsonify({
            'success': False,
            'message': 'No URL provided. Please add ?url=https://example.com to your request.'
        }), 400

    if not is_valid_url(url):
        return jsonify({
            'success': False,
            'message': 'Invalid URL format'
        }), 400

    try:
        results = analyze_url(url, verbose=False)
        # Make the results JSON serializable
        serializable_results = json_serializable_results(results)
        return jsonify({
            'success': True,
            'results': serializable_results
        })
    except Exception as e:
        logger.error(f"API Error analyzing URL: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing URL: {str(e)}'
        }), 500

@app.route('/ssl_tls_checker', methods=['GET', 'POST'])
def ssl_tls_checker():
    """SSL/TLS & HTTPS Validator"""
    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            return render_template('ssl_tls_checker.html', error="Please provide a URL")

        if not is_valid_url(url):
            return render_template('ssl_tls_checker.html', error="Invalid URL format")

        try:
            from utils.ssl_tls_validator import validate_ssl_tls_security
            results = validate_ssl_tls_security(url)
            # Save the analysis to history
            save_ssl_tls_to_history(url, results)
            return render_template('ssl_tls_checker.html', results=results)
        except Exception as e:
            logger.error(f"Error validating SSL/TLS: {str(e)}")
            return render_template('ssl_tls_checker.html', error=f"Error validating SSL/TLS: {str(e)}")

    return render_template('ssl_tls_checker.html')

def save_to_history(url, results):
    """Save the analysis results to a JSON file in the history directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = url.replace("://", "_").replace("/", "_").replace(".", "_")
    filename = f"{timestamp}_{domain}.json"

    # Add timestamp to results
    results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(os.path.join(HISTORY_DIR, filename), 'w') as f:
        json.dump(results, f)

def save_ssl_tls_to_history(url, results):
    """Save the SSL/TLS validation results to a JSON file in the history directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = url.replace("://", "_").replace("/", "_").replace(".", "_")
    domain = re.sub(r'[<>:"/\\|?*]', '_', domain)
    filename = f"{timestamp}_ssl_tls_{domain}.json"

    # Add timestamp to results
    results['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info(f"Saving SSL/TLS analysis to file: {filename}")

    try:
        with open(os.path.join(HISTORY_DIR, filename), 'w') as f:
            json.dump(results, f)
    except Exception as e:
        logger.error(f"Failed to save SSL/TLS analysis to history file {filename}: {str(e)}")
        raise

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)