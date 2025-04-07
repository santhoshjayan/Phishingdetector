import os
import logging
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from datetime import datetime
from phishing_detector import analyze_url, is_valid_url

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "temporary_secret_key")

# Create necessary directories
HISTORY_DIR = "analysis_history"
os.makedirs(HISTORY_DIR, exist_ok=True)

@app.route('/')
def index():
    return """
    <html>
    <head>
        <title>SpeeDefender Phishing Detection Tool</title>
        <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    </head>
    <body class="bg-dark text-light">
        <div class="container mt-5">
            <div class="row">
                <div class="col-12 text-center">
                    <h1>SpeeDefender</h1>
                    <h3>Phishing Detection Tool</h3>
                    <p class="lead">Running on port 5001</p>
                </div>
            </div>
            <div class="row mt-4">
                <div class="col-md-8 offset-md-2">
                    <div class="card bg-secondary">
                        <div class="card-body">
                            <h5 class="card-title">Analyze a URL</h5>
                            <form id="analyze-form">
                                <div class="form-group">
                                    <input type="text" class="form-control" id="url-input" 
                                           placeholder="Enter URL to analyze (e.g., https://example.com)">
                                </div>
                                <button type="submit" class="btn btn-primary mt-3">Analyze</button>
                            </form>
                        </div>
                    </div>
                    <div id="results" class="mt-4" style="display: none;">
                        <div class="card">
                            <div class="card-header bg-info">
                                Analysis Results
                            </div>
                            <div class="card-body" id="results-content">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            document.getElementById('analyze-form').addEventListener('submit', function(e) {
                e.preventDefault();
                const url = document.getElementById('url-input').value;
                
                fetch('/api/analyze?url=' + encodeURIComponent(url))
                    .then(response => response.json())
                    .then(data => {
                        const resultsDiv = document.getElementById('results');
                        const resultsContent = document.getElementById('results-content');
                        
                        if (data.success) {
                            const results = data.results;
                            let riskClass = 'text-success';
                            
                            if (results.risk_level === 'Critical' || results.risk_level === 'High') {
                                riskClass = 'text-danger';
                            } else if (results.risk_level === 'Medium') {
                                riskClass = 'text-warning';
                            }
                            
                            resultsContent.innerHTML = `
                                <h5>URL: <span class="text-info">${results.url}</span></h5>
                                <h5>Risk Level: <span class="${riskClass}">${results.risk_level}</span></h5>
                                <h5>Suspicious Indicators: ${results.suspicious_indicators}</h5>
                                <hr>
                                <h6>Pattern Analysis:</h6>
                                <ul>
                                    ${results.url_patterns.suspicious_patterns.length > 0 
                                        ? results.url_patterns.suspicious_patterns.map(p => `<li>${p}</li>`).join('')
                                        : '<li>No suspicious URL patterns detected</li>'}
                                </ul>
                                <h6>Domain Information:</h6>
                                <ul>
                                    ${results.domain_info.is_recently_created 
                                        ? '<li class="text-danger">Domain was created recently</li>' 
                                        : ''}
                                    ${results.domain_info.is_known_phishing 
                                        ? '<li class="text-danger">Domain is in the known phishing list</li>' 
                                        : ''}
                                </ul>
                                <h6>Recommendation:</h6>
                                <p>${results.recommendation}</p>
                            `;
                        } else {
                            resultsContent.innerHTML = `
                                <div class="alert alert-danger">
                                    ${data.message}
                                </div>
                            `;
                        }
                        
                        resultsDiv.style.display = 'block';
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        const resultsDiv = document.getElementById('results');
                        const resultsContent = document.getElementById('results-content');
                        
                        resultsContent.innerHTML = `
                            <div class="alert alert-danger">
                                An error occurred during analysis. Please try again.
                            </div>
                        `;
                        
                        resultsDiv.style.display = 'block';
                    });
            });
        </script>
    </body>
    </html>
    """

@app.route('/api/analyze')
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
        # Convert any non-serializable objects to strings
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

def check_port_availability(port):
    """Check if the specified port is available"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    available = True
    try:
        sock.bind(('0.0.0.0', port))
    except socket.error:
        available = False
    finally:
        sock.close()
    return available

if __name__ == "__main__":
    PORT = 5001
    print("=========================================")
    print("STARTING SPEEDEFENDER ON PORT 5001")
    print("=========================================")
    
    # Check if port 5001 is available
    if not check_port_availability(PORT):
        print("ERROR: Port 5001 is already in use!")
        print("Please stop any services using this port first.")
        print("Alternatively, you can modify this script to use a different port.")
        import sys
        sys.exit(1)
    
    print("✅ Port 5001 is available")
    print("To access the application, use port 5001")
    print("For example: http://localhost:5001/")
    print("=========================================")
    print("SpeeDefender v1.0")
    print("A comprehensive phishing detection platform")
    print("=========================================")
    app.run(host='0.0.0.0', port=PORT, debug=True)