#!/bin/bash
export FLASK_APP=main.py
export FLASK_DEBUG=1
python -m flask run --host=0.0.0.0 --port=5001
