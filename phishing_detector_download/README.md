# Phishing URL Detector

A comprehensive Python-based phishing detection tool that analyzes URLs for suspicious patterns and checks against known malicious domains.

## Features

- **URL Pattern Analysis**: Examines URL structures to identify suspicious patterns
- **Domain Information Analysis**: Checks domain registration information for red flags
- **Reputation Analysis**: Verifies domain reputation against various sources
- **Web Interface**: User-friendly web interface for easy analysis
- **API Access**: REST API for programmatic access
- **Batch Analysis**: Analyze multiple URLs at once
- **History Tracking**: Keep a record of previously analyzed URLs

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python main.py
   ```

## Usage

### Web Interface

Access the web interface by navigating to `http://localhost:5000` in your browser.

### Command Line

```bash
python phishing_detector.py https://example.com -v
```

Options:
- `-v, --verbose`: Print detailed information
- `-f, --file FILE`: File containing URLs to check (one per line)
- `-o, --output FILE`: Output file for the results

### API

The API endpoint is available at `/api/analyze`:

```
GET /api/analyze?url=https://example.com
```

## Requirements

- Python 3.6+
- Flask
- Requests
- Python-whois
- TLDExtract
- Trafilatura

## License

This project is open-source and available under the MIT License.