#!/usr/bin/env python3
"""
Test script for SSL/TLS validation functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.ssl_tls_validator import validate_ssl_tls_security

def test_ssl_validation():
    """Test SSL validation with various URLs"""

    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://httpbin.org",
        "https://expired.badssl.com",  # Known expired certificate
        "https://self-signed.badssl.com",  # Known self-signed certificate
    ]

    print("Testing SSL/TLS Validation")
    print("=" * 50)

    for url in test_urls:
        print(f"\nTesting: {url}")
        print("-" * 30)

        try:
            result = validate_ssl_tls_security(url, timeout=10)

            print(f"Risk Level: {result['risk_level']}")
            print(f"Suspicious Count: {result['suspicious_count']}")
            print("Findings:")
            for finding in result['findings']:
                print(f"  {finding}")

            if result['vulnerabilities']:
                print("Vulnerabilities:")
                for vuln_name, vuln_info in result['vulnerabilities'].items():
                    print(f"  {vuln_name}: {vuln_info['severity']} - {vuln_info['description']}")

        except Exception as e:
            print(f"Error testing {url}: {str(e)}")

        print()

if __name__ == "__main__":
    test_ssl_validation()
