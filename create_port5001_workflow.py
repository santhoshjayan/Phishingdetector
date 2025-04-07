#!/usr/bin/env python3
import os
import json

# Define the new workflow configurations
workflows = {
    "workflows": {
        "workflow": [
            {
                "name": "Project",
                "mode": "parallel",
                "author": "agent",
                "tasks": [
                    {
                        "task": "workflow.run",
                        "args": "SpeeDefender_5001"
                    },
                    {
                        "task": "workflow.run",
                        "args": "phishing_detector"
                    }
                ]
            },
            {
                "name": "SpeeDefender_5001",
                "author": "agent",
                "metadata": {"agentRequireRestartOnSave": False},
                "tasks": [
                    {
                        "task": "packager.installForAll"
                    },
                    {
                        "task": "shell.exec",
                        "args": "python standalone_server.py",
                        "waitForPort": 5001
                    }
                ]
            },
            {
                "name": "phishing_detector",
                "author": "agent",
                "metadata": {"agentRequireRestartOnSave": False},
                "tasks": [
                    {
                        "task": "packager.installForAll"
                    },
                    {
                        "task": "shell.exec",
                        "args": "python phishing_detector.py https://google.com -v"
                    }
                ]
            }
        ]
    },
    "ports": [
        {
            "localPort": 5000,
            "externalPort": 80
        },
        {
            "localPort": 5001,
            "externalPort": 3000
        }
    ]
}

print("Created new workflow definition for port 5001")