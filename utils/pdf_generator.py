"""
PDF Generator Module

Generates PDF reports from phishing detection analysis results.
"""

import os
import logging
from datetime import datetime
import json
from xhtml2pdf import pisa

logger = logging.getLogger(__name__)

def convert_html_to_pdf(html_string, output_filename):
    """
    Convert HTML to PDF
    
    Args:
        html_string (str): HTML content to convert
        output_filename (str): Output PDF file path
        
    Returns:
        bool: Success status
    """
    # Ensure reports directory exists
    os.makedirs('static/reports', exist_ok=True)
    
    # Open the output file for writing
    with open(output_filename, "wb") as out_file:
        # Convert HTML to PDF
        pisa_status = pisa.CreatePDF(
            html_string,  # the HTML to convert
            dest=out_file  # file handle to receive result
        )
    
    # Return True on success and False on errors
    return pisa_status.err == 0

def generate_url_report_html(results):
    """
    Generate HTML for URL analysis report
    
    Args:
        results (dict): URL analysis results
        
    Returns:
        str: HTML content
    """
    timestamp = results.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    url = results.get('url', 'Unknown URL')
    risk_level = results.get('risk_level', 'Unknown')
    risk_color = get_risk_color(risk_level)
    
    # Create HTML content
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>SpeeDefender URL Analysis Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                color: #333;
                line-height: 1.5;
                margin: 0;
                padding: 20px;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #ddd;
            }}
            .report-title {{
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 10px;
                color: #2c3e50;
            }}
            .logo {{
                font-size: 28px;
                font-weight: bold;
                color: #3498db;
                margin-bottom: 15px;
            }}
            .timestamp {{
                color: #7f8c8d;
                font-size: 14px;
                margin-bottom: 15px;
            }}
            .risk-badge {{
                display: inline-block;
                padding: 8px 16px;
                font-weight: bold;
                color: white;
                background-color: {risk_color};
                border-radius: 4px;
                margin-bottom: 15px;
            }}
            .section {{
                margin-bottom: 25px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 5px;
            }}
            .section-title {{
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 15px;
                color: #2c3e50;
                border-bottom: 1px solid #ddd;
                padding-bottom: 5px;
            }}
            ul {{
                margin: 0;
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 5px;
            }}
            .summary {{
                font-weight: bold;
                margin-bottom: 20px;
                font-size: 16px;
            }}
            .footer {{
                margin-top: 30px;
                text-align: center;
                font-size: 12px;
                color: #7f8c8d;
                border-top: 1px solid #ddd;
                padding-top: 15px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #f2f2f2;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="logo">🛡️ SpeeDefender</div>
            <div class="report-title">URL Analysis Report</div>
            <div class="timestamp">Generated on: {timestamp}</div>
        </div>
        
        <div class="section">
            <div class="section-title">Analysis Summary</div>
            <p><strong>URL:</strong> {url}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge">{risk_level}</span></p>
            <p><strong>Suspicious Indicators:</strong> {results.get('suspicious_indicators', 0)}</p>
            
            {f'<p class="summary">{results.get("risk_summary", "")}</p>' if results.get("risk_summary") else ''}
        </div>
    '''
    
    # URL Patterns Analysis
    if 'url_patterns' in results and 'suspicious_patterns' in results['url_patterns']:
        patterns = results['url_patterns']['suspicious_patterns']
        html += '''
        <div class="section">
            <div class="section-title">URL Pattern Analysis</div>
            <ul>
        '''
        
        for pattern in patterns:
            html += f'<li>{pattern}</li>'
        
        if 'pattern_analysis' in results and 'findings' in results['pattern_analysis']:
            for finding in results['pattern_analysis']['findings']:
                html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Domain Information
    if 'domain_info' in results and 'findings' in results['domain_info']:
        html += '''
        <div class="section">
            <div class="section-title">Domain Information</div>
            <ul>
        '''
        
        for finding in results['domain_info']['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        '''
        
        # Add WHOIS information if available
        if 'whois_info' in results['domain_info']:
            whois_info = results['domain_info']['whois_info']
            html += '''
            <div class="section-title" style="font-size: 16px; margin-top: 15px;">WHOIS Details</div>
            <table>
            '''
            
            for key, value in whois_info.items():
                if key in ['creation_date', 'expiration_date', 'registrar', 'registrant_country']:
                    html += f'''
                    <tr>
                        <th>{key.replace('_', ' ').title()}</th>
                        <td>{value}</td>
                    </tr>
                    '''
            
            html += '''
            </table>
            '''
        
        html += '''
        </div>
        '''
    
    # Reputation Information
    if 'reputation' in results and 'findings' in results['reputation']:
        html += '''
        <div class="section">
            <div class="section-title">Reputation Information</div>
            <ul>
        '''
        
        for finding in results['reputation']['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Safety Advice
    if 'safety_advice' in results and results['safety_advice']:
        html += '''
        <div class="section">
            <div class="section-title">Safety Recommendations</div>
            <ul>
        '''
        
        for advice in results['safety_advice']:
            html += f'<li>{advice}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Add footer
    html += '''
        <div class="footer">
            <p>This report was generated by SpeeDefender - Advanced Phishing Detection Tool</p>
            <p>© 2025 SpeeDefender - All rights reserved</p>
        </div>
    </body>
    </html>
    '''
    
    return html

def generate_email_report_html(results):
    """
    Generate HTML for Email analysis report
    
    Args:
        results (dict): Email analysis results
        
    Returns:
        str: HTML content
    """
    timestamp = results.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    email = results.get('email', 'Unknown Sender')
    subject = results.get('subject', 'No Subject')
    risk_level = results.get('risk_level', 'Unknown')
    risk_color = get_risk_color(risk_level)
    
    # Create HTML content
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>SpeeDefender Email Analysis Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                color: #333;
                line-height: 1.5;
                margin: 0;
                padding: 20px;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #ddd;
            }}
            .report-title {{
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 10px;
                color: #2c3e50;
            }}
            .logo {{
                font-size: 28px;
                font-weight: bold;
                color: #3498db;
                margin-bottom: 15px;
            }}
            .timestamp {{
                color: #7f8c8d;
                font-size: 14px;
                margin-bottom: 15px;
            }}
            .risk-badge {{
                display: inline-block;
                padding: 8px 16px;
                font-weight: bold;
                color: white;
                background-color: {risk_color};
                border-radius: 4px;
                margin-bottom: 15px;
            }}
            .section {{
                margin-bottom: 25px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 5px;
            }}
            .section-title {{
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 15px;
                color: #2c3e50;
                border-bottom: 1px solid #ddd;
                padding-bottom: 5px;
            }}
            ul {{
                margin: 0;
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 5px;
            }}
            .summary {{
                font-weight: bold;
                margin-bottom: 20px;
                font-size: 16px;
            }}
            .footer {{
                margin-top: 30px;
                text-align: center;
                font-size: 12px;
                color: #7f8c8d;
                border-top: 1px solid #ddd;
                padding-top: 15px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .progress-container {{
                width: 100%;
                background-color: #e0e0e0;
                height: 12px;
                border-radius: 6px;
                margin-top: 4px;
            }}
            .progress-bar {{
                height: 12px;
                border-radius: 6px;
                background-color: #ff0000;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="logo">🛡️ SpeeDefender</div>
            <div class="report-title">Email Analysis Report</div>
            <div class="timestamp">Generated on: {timestamp}</div>
        </div>
        
        <div class="section">
            <div class="section-title">Analysis Summary</div>
            <p><strong>From:</strong> {email}</p>
            <p><strong>Subject:</strong> {subject}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge">{risk_level}</span></p>
            <p><strong>Suspicious Indicators:</strong> {results.get('suspicious_indicators', 0)}</p>
            
            {f'<p class="summary">{results.get("risk_summary", "")}</p>' if results.get("risk_summary") else ''}
        </div>
    '''
    
    # Risk Factor Breakdown
    if 'risk_factors' in results and any(results['risk_factors'].values()):
        html += '''
        <div class="section">
            <div class="section-title">Risk Factor Breakdown</div>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Score</th>
                    <th>Level</th>
                </tr>
        '''
        
        for category, score in results['risk_factors'].items():
            if score > 0:
                category_name = category.replace('_risk', '').title()
                progress_width = min(score * 10, 100)  # Scale to max 100%
                
                bar_color = "#3498db"  # default blue
                if score >= 5:
                    bar_color = "#e74c3c"  # high - red
                elif score >= 3:
                    bar_color = "#f39c12"  # medium - orange
                elif score >= 1:
                    bar_color = "#3498db"  # low - blue
                
                html += f'''
                <tr>
                    <td>{category_name}</td>
                    <td>{score} pts</td>
                    <td>
                        <div class="progress-container">
                            <div class="progress-bar" style="width: {progress_width}%; background-color: {bar_color};"></div>
                        </div>
                    </td>
                </tr>
                '''
        
        html += '''
            </table>
        </div>
        '''
    
    # Sender Analysis
    if 'sender_analysis' in results and 'findings' in results['sender_analysis']:
        html += '''
        <div class="section">
            <div class="section-title">Sender Analysis</div>
            <ul>
        '''
        
        for finding in results['sender_analysis']['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Header Analysis
    if 'header_analysis' in results and 'findings' in results['header_analysis']:
        html += '''
        <div class="section">
            <div class="section-title">Email Header Analysis</div>
            <ul>
        '''
        
        for finding in results['header_analysis']['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Content Analysis
    if 'content_analysis' in results and 'findings' in results['content_analysis']:
        html += '''
        <div class="section">
            <div class="section-title">Content Analysis</div>
            <ul>
        '''
        
        for finding in results['content_analysis']['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Subject Analysis
    if 'subject_analysis' in results and 'findings' in results['subject_analysis']:
        html += '''
        <div class="section">
            <div class="section-title">Subject Line Analysis</div>
            <ul>
        '''
        
        for finding in results['subject_analysis']['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Safety Advice
    if 'safety_advice' in results and results['safety_advice']:
        html += '''
        <div class="section">
            <div class="section-title">Safety Recommendations</div>
            <ul>
        '''
        
        for advice in results['safety_advice']:
            html += f'<li>{advice}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Add footer
    html += '''
        <div class="footer">
            <p>This report was generated by SpeeDefender - Advanced Phishing Detection Tool</p>
            <p>© 2025 SpeeDefender - All rights reserved</p>
        </div>
    </body>
    </html>
    '''
    
    return html

def generate_web_security_report_html(results):
    """
    Generate HTML for Web Security Vulnerability Scanner report
    
    Args:
        results (dict): Web security scan results
        
    Returns:
        str: HTML content
    """
    timestamp = results.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    url = results.get('url', 'Unknown URL')
    risk_level = results.get('risk_level', 'Unknown')
    risk_color = get_risk_color(risk_level)
    suspicious_count = results.get('suspicious_count', 0)
    
    # Create HTML content
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>SpeeSecure Web Security Vulnerability Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                color: #333;
                line-height: 1.5;
                margin: 0;
                padding: 20px;
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #ddd;
            }}
            .report-title {{
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 10px;
                color: #2c3e50;
            }}
            .logo {{
                font-size: 28px;
                font-weight: bold;
                color: #3498db;
                margin-bottom: 15px;
            }}
            .timestamp {{
                color: #7f8c8d;
                font-size: 14px;
                margin-bottom: 15px;
            }}
            .risk-badge {{
                display: inline-block;
                padding: 8px 16px;
                font-weight: bold;
                color: white;
                background-color: {risk_color};
                border-radius: 4px;
                margin-bottom: 15px;
            }}
            .section {{
                margin-bottom: 25px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 5px;
            }}
            .section-title {{
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 15px;
                color: #2c3e50;
                border-bottom: 1px solid #ddd;
                padding-bottom: 5px;
            }}
            .vulnerability-card {{
                border-left: 4px solid;
                margin-bottom: 15px;
                padding: 10px;
                background-color: white;
            }}
            .severity-critical {{
                border-left-color: #dc3545 !important;
                background-color: rgba(220, 53, 69, 0.1);
            }}
            .severity-high {{
                border-left-color: #fd7e14 !important;
                background-color: rgba(253, 126, 20, 0.1);
            }}
            .severity-medium {{
                border-left-color: #ffc107 !important;
                background-color: rgba(255, 193, 7, 0.1);
            }}
            .severity-low {{
                border-left-color: #17a2b8 !important;
                background-color: rgba(23, 162, 184, 0.1);
            }}
            ul {{
                margin: 0;
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 5px;
            }}
            .summary {{
                font-weight: bold;
                margin-bottom: 20px;
                font-size: 16px;
            }}
            .footer {{
                margin-top: 30px;
                text-align: center;
                font-size: 12px;
                color: #7f8c8d;
                border-top: 1px solid #ddd;
                padding-top: 15px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 15px;
            }}
            th, td {{
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .badge {{
                display: inline-block;
                padding: 4px 8px;
                font-size: 12px;
                font-weight: bold;
                color: white;
                border-radius: 3px;
            }}
            .badge-critical {{
                background-color: #dc3545;
            }}
            .badge-high {{
                background-color: #fd7e14;
            }}
            .badge-medium {{
                background-color: #ffc107;
                color: #000;
            }}
            .badge-low {{
                background-color: #17a2b8;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="logo">🛡️ SpeeSecure</div>
            <div class="report-title">Web Security Vulnerability Report</div>
            <div class="timestamp">Generated on: {timestamp}</div>
        </div>
        
        <div class="section">
            <div class="section-title">Scan Summary</div>
            <p><strong>URL:</strong> {url}</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge">{risk_level}</span></p>
            <p><strong>Suspicious Indicators:</strong> {suspicious_count}</p>
        </div>
    '''
    
    # Scan Findings
    if 'findings' in results and results['findings']:
        html += '''
        <div class="section">
            <div class="section-title">Scan Findings</div>
            <ul>
        '''
        
        for finding in results['findings']:
            html += f'<li>{finding}</li>'
        
        html += '''
            </ul>
        </div>
        '''
    
    # Detailed Vulnerability Analysis
    if 'vulnerabilities' in results and results['vulnerabilities']:
        html += '''
        <div class="section">
            <div class="section-title">Detailed Vulnerability Analysis</div>
        '''
        
        for vuln_type, vuln_data in results['vulnerabilities'].items():
            if vuln_data and isinstance(vuln_data, dict):
                severity = vuln_data.get('severity', 'Unknown')
                severity_class = f"severity-{severity.lower()}"
                badge_class = f"badge-{severity.lower()}"
                
                html += f'''
                <div class="vulnerability-card {severity_class}">
                    <h5 style="margin-top: 0; margin-bottom: 10px;">
                        {vuln_type.replace('_', ' ').title()}
                        <span class="badge {badge_class}" style="float: right;">{severity}</span>
                    </h5>
                '''
                
                if 'description' in vuln_data:
                    html += f'<p style="margin-bottom: 10px;"><strong>Description:</strong> {vuln_data["description"]}</p>'
                
                if 'patterns_found' in vuln_data and vuln_data['patterns_found']:
                    html += '<p style="margin-bottom: 5px;"><strong>Patterns Found:</strong></p><ul>'
                    for pattern in vuln_data['patterns_found'][:5]:  # Limit to 5
                        html += f'<li><code>{pattern[:50]}{"..." if len(pattern) > 50 else ""}</code></li>'
                    html += '</ul>'
                
                if 'files' in vuln_data and vuln_data['files']:
                    html += '<p style="margin-bottom: 5px;"><strong>Exposed Files:</strong></p><ul>'
                    for file in vuln_data['files']:
                        html += f'<li><code>{file}</code></li>'
                    html += '</ul>'
                
                if 'issues' in vuln_data and vuln_data['issues']:
                    html += '<p style="margin-bottom: 5px;"><strong>Issues Found:</strong></p><ul>'
                    for issue in vuln_data['issues']:
                        html += f'<li>{issue}</li>'
                    html += '</ul>'
                
                if 'methods' in vuln_data and vuln_data['methods']:
                    html += '<p style="margin-bottom: 5px;"><strong>Dangerous Methods:</strong></p>'
                    for method in vuln_data['methods']:
                        html += f'<span class="badge badge-critical" style="margin-right: 5px;">{method}</span>'
                    html += '</p>'
                
                if 'resources' in vuln_data and vuln_data['resources']:
                    html += '<p style="margin-bottom: 5px;"><strong>Mixed Content Resources:</strong></p><ul>'
                    for resource in vuln_data['resources'][:3]:  # Limit to 3
                        html += f'<li><code>{resource[:50]}{"..." if len(resource) > 50 else ""}</code></li>'
                    html += '</ul>'
                
                if 'paths' in vuln_data and vuln_data['paths']:
                    html += '<p style="margin-bottom: 5px;"><strong>Revealed Paths:</strong></p><ul>'
                    for path in vuln_data['paths']:
                        html += f'<li><code>{path}</code></li>'
                    html += '</ul>'
                
                html += '''
                </div>
                '''
        
        html += '''
        </div>
        '''
    
    # Security Recommendations
    html += '''
        <div class="section">
            <div class="section-title">Security Recommendations</div>
            <div style="display: flex; gap: 20px;">
                <div style="flex: 1;">
                    <h6 style="color: #2c3e50; margin-bottom: 10px;">Immediate Actions:</h6>
                    <ul>
                        <li>Fix any critical or high-severity vulnerabilities immediately</li>
                        <li>Remove or secure exposed sensitive files</li>
                        <li>Implement proper input validation and sanitization</li>
                        <li>Configure security headers (CSP, X-Frame-Options, etc.)</li>
                        <li>Disable dangerous HTTP methods if not needed</li>
                    </ul>
                </div>
                <div style="flex: 1;">
                    <h6 style="color: #2c3e50; margin-bottom: 10px;">Best Practices:</h6>
                    <ul>
                        <li>Use HTTPS everywhere</li>
                        <li>Regular security audits and penetration testing</li>
                        <li>Keep software and frameworks updated</li>
                        <li>Implement Web Application Firewall (WAF)</li>
                        <li>Use Content Security Policy (CSP)</li>
                        <li>Implement proper error handling</li>
                    </ul>
                </div>
            </div>
        </div>
    '''
    
    # Add footer
    html += '''
        <div class="footer">
            <p>This report was generated by SpeeSecure - Advanced Web Security Scanner</p>
            <p>© 2025 SpeeSecure - All rights reserved</p>
        </div>
    </body>
    </html>
    '''
    
    return html

def generate_report_pdf(results, report_type='url'):
    """
    Generate PDF report from analysis results
    
    Args:
        results (dict): Analysis results
        report_type (str): Type of report ('url', 'email', or 'web_security')
        
    Returns:
        tuple: (success status, file path or error message)
    """
    try:
        # Create timestamp-based filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if report_type == 'url':
            # Generate URL report
            html_content = generate_url_report_html(results)
            filename = f"url_report_{timestamp}.pdf"
        elif report_type == 'web_security':
            # Generate Web Security report
            html_content = generate_web_security_report_html(results)
            filename = f"web_security_report_{timestamp}.pdf"
        else:
            # Generate Email report
            html_content = generate_email_report_html(results)
            filename = f"email_report_{timestamp}.pdf"
        
        output_path = os.path.join('static', 'reports', filename)
        
        # Convert HTML to PDF
        success = convert_html_to_pdf(html_content, output_path)
        
        if success:
            return True, output_path
        else:
            return False, "Failed to generate PDF"
    
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        return False, f"Error generating PDF report: {str(e)}"

def get_risk_color(risk_level):
    """
    Get color for risk level
    
    Args:
        risk_level (str): Risk level
        
    Returns:
        str: Hex color code
    """
    colors = {
        'Critical': '#000000',  # black
        'High': '#e74c3c',      # red
        'Medium': '#f39c12',    # orange
        'Low': '#3498db',       # blue
        'Very Low': '#2ecc71',  # green
        'Safe': '#27ae60',      # darker green
        'Unknown': '#95a5a6'    # gray
    }
    
    return colors.get(risk_level, '#95a5a6')  # default to gray