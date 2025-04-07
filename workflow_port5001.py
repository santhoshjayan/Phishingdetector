import json
import os

# Define the workflow configuration
workflow_config = {
    "name": "SpeeDefender Port 5001",
    "command": "python main.py",
    "restartable": True,
    "profiles": [
        {
            "name": "development",
            "primary": True
        }
    ]
}

# Save the workflow configuration
try:
    # Create .replit/workflows directory if it doesn't exist
    os.makedirs(".replit/workflows", exist_ok=True)
    
    # Write the workflow configuration to a file
    with open(".replit/workflows/port5001.json", "w") as f:
        json.dump(workflow_config, f, indent=2)
    
    print("Workflow configuration created successfully!")
    print("To start the workflow, use: 'python main.py'")
except Exception as e:
    print(f"Error creating workflow configuration: {str(e)}")