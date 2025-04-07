#!/usr/bin/env python
"""
Test script for SendGrid integration in SpeeDefender
"""

import os
import sys
import requests
import json

# Test configuration
recipient = input("Enter your email address to receive a test notification: ")
api_key = os.environ.get('SENDGRID_API_KEY', '')

if not api_key:
    print("\nWARNING: SENDGRID_API_KEY environment variable is not set.")
    use_key = input("Would you like to enter your SendGrid API key for testing? (y/n): ")
    if use_key.lower() == 'y':
        api_key = input("Enter your SendGrid API key: ")
    else:
        print("Continuing without API key (this will fail unless the server has SENDGRID_API_KEY set)")

# Payload for the test
payload = {
    "api_key": api_key,
    "recipient": recipient,
    "sender_email": "noreply@speedefender.com",
    "sender_name": "SpeeDefender"
}

print("\nSending test notification to", recipient)
try:
    # Make the request to the notification endpoint
    response = requests.post(
        'http://localhost:5000/api/email_automation/test_notification', 
        json=payload
    )
    
    # Display results
    result = response.json()
    if result.get('success', False):
        print("\n✅ Success:", result.get('message', 'Test email sent successfully'))
    else:
        print("\n❌ Error:", result.get('message', 'Unknown error occurred'))
        
    # Show full response for debugging
    print("\nFull Response:")
    print(json.dumps(result, indent=2))
    
except Exception as e:
    print(f"\n❌ Error making request: {str(e)}")
    print("Make sure the SpeeDefender application is running on port 5000")