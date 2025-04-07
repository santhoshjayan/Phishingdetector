#!/usr/bin/env python3
"""
Create a shell script to launch SpeeDefender on port 5001
"""

script_content = '''#!/bin/bash
# SpeeDefender Port 5001 Launcher Script

echo "==============================================="
echo "SPEEDEFENDER PORT 5001 LAUNCHER"
echo "==============================================="
echo "This script launches SpeeDefender on port 5001"
echo "to avoid conflicts with the Replit default port."
echo "==============================================="

# Check if port 5001 is already in use
if netstat -tuln | grep -q ":5001 "; then
  echo "ERROR: Port 5001 is already in use!"
  echo "Please stop any services using this port first."
  exit 1
fi

# Launch the standalone server
echo "Starting SpeeDefender on port 5001..."
echo "Access the application at: http://localhost:5001/"
echo "==============================================="
python standalone_server.py
'''

with open('start_speedefender_5001.sh', 'w') as f:
    f.write(script_content)

# Make the script executable
import os
os.chmod('start_speedefender_5001.sh', 0o755)

print("Shell script created and made executable: start_speedefender_5001.sh")
print("Run with: ./start_speedefender_5001.sh")