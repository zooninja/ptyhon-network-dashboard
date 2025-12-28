#!/bin/bash

echo "============================================================"
echo "Python Network Dashboard Launcher"
echo "============================================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3 from your package manager"
    exit 1
fi

echo "Python detected. Checking dependencies..."
echo ""

# Check if required packages are installed
python3 -c "import psutil, flask, flask_cors" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required packages..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

echo ""
echo "Starting Python Network Dashboard..."
echo "Server will be available at: http://localhost:8081"
echo ""
echo "Press Ctrl+C to stop the server"
echo "============================================================"
echo ""

python3 server.py

echo ""
echo "Server stopped."
