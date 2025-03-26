from flask import Flask, render_template, request, jsonify, redirect, url_for
import logging
import os
import json
from datetime import datetime
from phishing_detector import analyze_url, is_valid_url

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "temporary_secret_key")

# Create a directory to store analysis history
HISTORY_DIR = "analysis_history"
os.makedirs(HISTORY_DIR, exist_ok=True)

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
        
        # Save the analysis to history
        save_to_history(url, results)
        
        return jsonify({
            'success': True,
            'results': results
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
        return jsonify({
            'success': True,
            'results': results
        })
    except Exception as e:
        logger.error(f"API Error analyzing URL: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing URL: {str(e)}'
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