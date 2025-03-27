# Phishing URL Detector

A comprehensive tool for analyzing URLs and detecting potential phishing attempts by examining suspicious patterns, domain reputation, and checking against known malicious domains.

## Features

- **URL Pattern Analysis**: Examines URL structures to detect phishing indicators
- **Domain Information Analysis**: Checks domain registration details and age
- **Reputation Analysis**: Analyzes domain reputation against various sources
- **Web Interface**: User-friendly web interface to analyze URLs
- **History Tracking**: Saves analysis results for future reference
- **Batch Analysis**: Process multiple URLs at once
- **API Access**: Programmatic access via REST API

## Project Structure

- `main.py`: Flask web application
- `phishing_detector.py`: Core phishing detection functionality
- `utils/`: Supporting modules
  - `url_analyzer.py`: URL pattern analysis
  - `domain_checker.py`: Domain information checking
  - `reputation_checker.py`: Domain reputation verification
- `templates/`: HTML templates for the web interface
- `data/`: Data files including known phishing domains

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install flask flask-sqlalchemy gunicorn python-whois requests tldextract trafilatura psycopg2-binary
   ```
3. Run the application:
   ```
   python main.py
   ```
   or with Gunicorn:
   ```
   gunicorn --bind 0.0.0.0:5000 main:app
   ```

## Usage

### Web Interface

Access the web interface by visiting `http://localhost:5000` in your browser.

1. Enter a URL to analyze
2. View the analysis results including:
   - Overall risk level
   - Suspicious indicators count
   - Pattern analysis
   - Domain information
   - Reputation information

### Command Line Usage

You can also use the tool from the command line:

```
python phishing_detector.py https://example.com -v
```

Options:
- `-v, --verbose`: Display detailed analysis information
- `-f, --file FILE`: Process URLs from a file (one per line)
- `-o, --output FILE`: Save results to an output file

### API Usage

The tool provides a REST API for programmatic access:

```
GET /api/analyze?url=https://example.com
```

Response:
```json
{
  "success": true,
  "results": {
    "url": "https://example.com",
    "risk_level": "Low",
    "suspicious_indicators": 1,
    "pattern_analysis": {
      "findings": ["No suspicious URL patterns detected"]
    },
    "domain_info": {
      "findings": ["Domain is older than 30 days which is good"],
      "whois_info": {
        "registrar": "Example Registrar",
        "creation_date": "2010-01-01",
        "expiration_date": "2025-01-01",
        "country": "US",
        "organization": "Example Organization"
      }
    },
    "reputation": {
      "findings": ["Website contains sensitive terms: login"]
    },
    "recommendation": "This URL has minor suspicious indicators but appears relatively safe."
  }
}
```

## Disclaimer

This tool provides an analysis of URLs based on known phishing patterns and indicators. While it attempts to be accurate, it cannot guarantee 100% detection of all phishing websites. Always use caution when visiting unfamiliar websites.

## License

This project is licensed under the MIT License - see the LICENSE file for details.