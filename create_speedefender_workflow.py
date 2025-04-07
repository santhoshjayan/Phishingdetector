#!/usr/bin/env python3
"""
Create a new workflow for running SpeeDefender on port 5001
"""

import os

workflow_content = '''<workflow>
<name>
SpeeDefender Port 5001
</name>
<command>
python standalone_server.py
</command>
</workflow>
'''

# Check if .replit.workflow exists, create it if not
workflow_file = '.replit.workflow'
if not os.path.exists(workflow_file):
    with open(workflow_file, 'w') as f:
        f.write(workflow_content)
    print(f"Created {workflow_file} with SpeeDefender Port 5001 workflow")
else:
    # If file exists, append the workflow
    with open(workflow_file, 'a') as f:
        f.write(workflow_content)
    print(f"Added SpeeDefender Port 5001 workflow to {workflow_file}")

print("You can now restart the Replit workspace to use the new workflow.")
print("To run the workflow, use the command:")
print("    python standalone_server.py")