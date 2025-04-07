#!/usr/bin/env python3
"""
SpeeDefender Launcher

This script provides a simple way to launch the SpeeDefender application
on port 5001 to avoid port conflicts with Replit's default port 5000.
"""

import os
import sys
import socket
import subprocess
import time
import signal
import atexit

def check_port_availability(port):
    """Check if the specified port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    available = True
    try:
        sock.bind(('0.0.0.0', port))
    except socket.error:
        available = False
    finally:
        sock.close()
    return available

def run_standalone_server():
    """Run the standalone server on port 5001"""
    print("Starting SpeeDefender Standalone Server on port 5001...")
    
    # Check port availability
    if not check_port_availability(5001):
        print("Error: Port 5001 is already in use!")
        print("Please stop any services using this port first.")
        return False
    
    # Initialize process variable
    process = None
    
    try:
        # Start the process
        process = subprocess.Popen(
            ["python", "standalone_server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Register cleanup function to terminate process on exit
        def cleanup():
            if process and process.poll() is None:
                print("\nTerminating SpeeDefender...")
                process.terminate()
                process.wait(timeout=5)
        
        atexit.register(cleanup)
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
        
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(2)
        
        # Print URL information
        print("\n=========================================")
        print("SpeeDefender is running on port 5001!")
        print("Access the application at: http://localhost:5001/")
        print("Press Ctrl+C to stop the server")
        print("=========================================\n")
        
        # Monitor the process output
        while process and process.stdout:
            output = process.stdout.readline() if process.stdout else None
            if output:
                print(output.strip())
            if process.poll() is not None:
                break
        
        return True
    except Exception as e:
        print(f"Error starting SpeeDefender: {e}")
        return False

def run_main_app():
    """Run the main application on port 5001"""
    print("Starting SpeeDefender Full Application on port 5001...")
    
    # Check port availability
    if not check_port_availability(5001):
        print("Error: Port 5001 is already in use!")
        print("Please stop any services using this port first.")
        return False
    
    # Initialize process variable
    process = None
    
    try:
        # Start the process
        process = subprocess.Popen(
            ["gunicorn", "--bind", "0.0.0.0:5001", "--reuse-port", "--reload", "main:app"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Register cleanup function to terminate process on exit
        def cleanup():
            if process and process.poll() is None:
                print("\nTerminating SpeeDefender...")
                process.terminate()
                process.wait(timeout=5)
        
        atexit.register(cleanup)
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
        
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(2)
        
        # Print URL information
        print("\n=========================================")
        print("SpeeDefender Full App is running on port 5001!")
        print("Access the application at: http://localhost:5001/")
        print("Press Ctrl+C to stop the server")
        print("=========================================\n")
        
        # Monitor the process output
        while process and process.stdout:
            output = process.stdout.readline() if process.stdout else None
            if output:
                print(output.strip())
            if process.poll() is not None:
                break
        
        return True
    except Exception as e:
        print(f"Error starting SpeeDefender: {e}")
        return False

def main():
    """Main function to run the launcher"""
    print("=========================================")
    print("SPEEDEFENDER PORT 5001 LAUNCHER")
    print("=========================================")
    print("This launcher helps you run SpeeDefender on port 5001")
    print("to avoid conflicts with the Replit default port 5000.")
    print("=========================================\n")
    
    while True:
        print("Please select an option:")
        print("1. Run SpeeDefender Standalone Server (Recommended)")
        print("2. Run SpeeDefender Full Application")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == "1":
            run_standalone_server()
            break
        elif choice == "2":
            run_main_app()
            break
        elif choice == "3":
            print("Exiting SpeeDefender Launcher...")
            break
        else:
            print("Invalid choice. Please try again.\n")

if __name__ == "__main__":
    main()