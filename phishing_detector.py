#!/usr/bin/env python3
"""
Phishing Detection Tool

A comprehensive tool for analyzing URLs and detecting potential phishing attempts
by examining suspicious patterns, domain reputation, and checking against known
phishing domains.
"""

import argparse
import logging
import sys
import os
from urllib.parse import urlparse
from utils.url_analyzer import analyze_url_patterns
from utils.domain_checker import check_domain_info
from utils.reputation_checker import check_domain_reputation
from utils.security_headers_checker import check_security_headers
from utils.web_security_scanner import scan_web_security_vulnerabilities

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_detection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def is_valid_url(url):
    """Check if the URL has a valid format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def analyze_url(url, verbose=False):
    """
    Analyze a URL for phishing indicators
    
    Args:
        url (str): The URL to analyze
        verbose (bool): Whether to print detailed information
        
    Returns:
        dict: Analysis results including risk level and detailed findings
    """
    if not is_valid_url(url):
        logger.error(f"Invalid URL format: {url}")
        return {
            "url": url,
            "is_valid": False,
            "risk_level": "Unknown",
            "message": "Invalid URL format"
        }
    
    logger.info(f"Analyzing URL: {url}")
    
    # Get pattern analysis
    pattern_results = analyze_url_patterns(url)
    
    # Get domain information
    domain_info = check_domain_info(url)
    
    # Check reputation
    reputation_info = check_domain_reputation(url)
    
    # Check security headers
    security_headers = check_security_headers(url)
    
    # Scan for web security vulnerabilities
    web_security = scan_web_security_vulnerabilities(url)
    
    # Calculate overall risk level
    suspicious_indicators = sum([
        pattern_results['suspicious_count'],
        domain_info['suspicious_count'],
        reputation_info['suspicious_count'],
        security_headers['suspicious_count'],
        web_security['suspicious_count']
    ])
    
    if suspicious_indicators >= 5:
        risk_level = "High"
    elif suspicious_indicators >= 3:
        risk_level = "Medium"
    elif suspicious_indicators >= 1:
        risk_level = "Low"
    else:
        risk_level = "Safe"
    
    # Compile results
    results = {
        "url": url,
        "is_valid": True,
        "risk_level": risk_level,
        "suspicious_indicators": suspicious_indicators,
        "pattern_analysis": pattern_results,
        "domain_info": domain_info,
        "reputation": reputation_info,
        "security_headers": security_headers,
        "web_security": web_security
    }
    
    # Log the outcome
    logger.info(f"Analysis complete for {url} - Risk level: {risk_level}")
    
    # Print detailed information if verbose mode is on
    if verbose:
        print("\n" + "="*50)
        print(f"URL ANALYSIS REPORT: {url}")
        print("="*50)
        print(f"RISK LEVEL: {risk_level}")
        print(f"SUSPICIOUS INDICATORS: {suspicious_indicators}")
        
        print("\nPATTERN ANALYSIS:")
        for finding in pattern_results['findings']:
            print(f"- {finding}")
            
        print("\nDOMAIN INFORMATION:")
        for key, value in domain_info['whois_info'].items():
            print(f"- {key}: {value}")
            
        print("\nREPUTATION INFORMATION:")
        for finding in reputation_info['findings']:
            print(f"- {finding}")
        
        print("\nSECURITY HEADERS ANALYSIS:")
        for finding in security_headers['findings']:
            print(f"- {finding}")
        
        print("\nWEB SECURITY SCAN:")
        for finding in web_security['findings']:
            print(f"- {finding}")
        
        print("\nRECOMMENDATION:")
        if risk_level == "High":
            print("This URL has a high likelihood of being a phishing attempt. Avoid accessing it.")
        elif risk_level == "Medium":
            print("This URL shows some suspicious characteristics. Proceed with caution.")
        elif risk_level == "Low":
            print("This URL has minor suspicious indicators but appears relatively safe.")
        else:
            print("This URL appears to be safe based on our analysis.")
        print("="*50 + "\n")
    
    return results


def main():
    """Main function to run the phishing detection tool"""
    parser = argparse.ArgumentParser(description='Phishing URL Detection Tool')
    parser.add_argument('url', nargs='?', help='URL to check')
    parser.add_argument('-f', '--file', help='File containing URLs to check (one per line)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed information')
    parser.add_argument('-o', '--output', help='Output file for the results')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
    
    results = []
    
    # Process a single URL
    if args.url:
        result = analyze_url(args.url, args.verbose)
        results.append(result)
    
    # Process URLs from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            for url in urls:
                result = analyze_url(url, args.verbose)
                results.append(result)
                
        except FileNotFoundError:
            logger.error(f"File not found: {args.file}")
            print(f"Error: File not found: {args.file}")
            sys.exit(1)
    
    # Write results to output file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for result in results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Valid URL: {result['is_valid']}\n")
                    if result['is_valid']:
                        f.write(f"Risk Level: {result['risk_level']}\n")
                        f.write(f"Suspicious Indicators: {result['suspicious_indicators']}\n")
                        f.write("\n")
            
            print(f"Results saved to {args.output}")
        except Exception as e:
            logger.error(f"Error writing to output file: {str(e)}")
            print(f"Error writing to output file: {str(e)}")
    
    # Print summary
    print("\nSUMMARY:")
    for result in results:
        risk_icon = {
            "High": "🔴",
            "Medium": "🟠",
            "Low": "🟡",
            "Safe": "🟢",
            "Unknown": "⚪"
        }.get(result['risk_level'], "⚪")
        
        print(f"{risk_icon} {result['url']} - {'Invalid URL' if not result['is_valid'] else result['risk_level']}")


if __name__ == "__main__":
    main()
