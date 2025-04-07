#!/bin/bash
# Start the main SpeeDefender application on port 5001

echo "====================================================="
echo "Starting SpeeDefender on port 5001"
echo "====================================================="
echo "This script starts the full SpeeDefender application"
echo "on port 5001 to avoid conflicts with Replit's default port."
echo "====================================================="

# Check if port 5001 is already in use
if netstat -tuln | grep -q ":5001 "; then
  echo "ERROR: Port 5001 is already in use!"
  echo "Please stop any services using this port first."
  exit 1
fi

# Run the application with gunicorn on port 5001
gunicorn --bind 0.0.0.0:5001 --reuse-port --reload main:app