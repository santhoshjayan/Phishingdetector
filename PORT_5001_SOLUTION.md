# SpeeDefender Port 5001 Solution Guide

## Overview

Due to persistent port conflicts with Replit's default port 5000, SpeeDefender now includes multiple options for running on alternate ports. This document explains how to use the port 5001 solution, which provides a reliable way to run the application without port conflicts.

## Running SpeeDefender on Port 5001

### Option 1: Use the Launcher Script (Recommended)

The launcher script provides a simple interface for starting SpeeDefender on port 5001:

```bash
python run_speedefender_5001.py
```

When prompted, select option 1 to run the standalone server or option 2 to run the full application.

### Option 2: Run the Shell Script

A convenient shell script is available to directly start the standalone server on port 5001:

```bash
./start_speedefender_5001.sh
```

### Option 3: Run the Standalone Server Directly

You can also run the standalone server directly:

```bash
python standalone_server.py
```

## Standalone Server Features

The standalone server on port 5001 provides a lightweight implementation of the core SpeeDefender functionality:

- URL analysis with comprehensive phishing detection
- JSON API for programmatic access
- Clean, modern UI with Bootstrap styling
- Risk level visualization
- Consistent SpeeDefender branding

## Accessing the Application

Once running, access the application at:

```
http://localhost:5001/
```

For the REST API:

```
http://localhost:5001/api/analyze?url=https://example.com
```

## Additional Resources

- Full documentation: See README.md
- Technical documentation: See TECHNICAL.md
- API documentation: Available in the application under /api-docs
