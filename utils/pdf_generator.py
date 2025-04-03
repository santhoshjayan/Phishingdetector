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

def generate_report_pdf(results, report_type='url'):
    """
    Generate PDF report from analysis results
    
    Args:
        results (dict): Analysis results
        report_type (str): Type of report ('url' or 'email')
        
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