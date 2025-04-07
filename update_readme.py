#!/usr/bin/env python3
"""
Update the README.md file with SpeeDefender documentation
"""

readme_content = """# SpeeDefender: Phishing Detection Platform

## Overview

SpeeDefender is a comprehensive phishing detection platform designed to analyze URLs and emails for potential phishing attempts. It provides detailed analysis reports, batch processing capabilities, and automated email scanning to help protect users from phishing threats.

## Features

### URL Analysis
- Domain reputation checking
- Structural analysis of URLs
- Known phishing domain detection
- Technical and WHOIS information retrieval
- Risk level assessment

### Email Analysis
- Header inspection
- Sender domain verification
- Content analysis for suspicious patterns
- Link extraction and verification
- Attachment scanning

### Key Features
- User-friendly web interface
- Detailed analysis reports with risk scoring
- PDF report export
- Batch analysis for multiple URLs
- API access for programmatic integration
- Email automation system with filtering capabilities
- Dashboard with security metrics

## Running SpeeDefender

### Port 5001 Solution

Due to potential port conflicts with Replit's default port 5000, SpeeDefender now includes multiple options for running on port 5001:

#### Option 1: Use the Launcher Script (Recommended)

```bash
python run_speedefender_5001.py
```

When prompted, select option 1 to run the standalone server or option 2 to run the full application.

#### Option 2: Run the Shell Script

```bash
./start_speedefender_5001.sh
```

#### Option 3: Run the Standalone Server Directly

```bash
python standalone_server.py
```

### Default Port 5000 Option

If port 5000 is available, you can still use the original application:

```bash
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

## API Usage

SpeeDefender provides a REST API for programmatic access:

```
http://localhost:5001/api/analyze?url=https://example.com
```

For email analysis:

```
POST http://localhost:5001/api/analyze/email
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
"""

# Write the new README.md
with open('README.md', 'w') as f:
    f.write(readme_content)

print("README.md updated successfully with SpeeDefender documentation.")