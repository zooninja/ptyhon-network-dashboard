#!/bin/bash

echo "============================================================"
echo "Python Network Dashboard Launcher"
echo "============================================================"
echo ""

# Detect if we're in a virtual environment
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON_CMD="$VIRTUAL_ENV/bin/python"
    PIP_CMD="$VIRTUAL_ENV/bin/pip"
    echo "Virtual environment detected: $VIRTUAL_ENV"
else
    PYTHON_CMD="python3"
    PIP_CMD="pip3"

    # Check if Python is installed
    if ! command -v python3 &> /dev/null; then
        echo "ERROR: Python 3 is not installed"
        echo "Please install Python 3 from your package manager"
        exit 1
    fi
fi

echo "Python detected. Checking dependencies..."
echo ""

# Check if required packages are installed
$PYTHON_CMD -c "import psutil, flask, flask_cors" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required packages..."
    $PIP_CMD install -r requirements.txt
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
echo ""
echo "Note: For full process information, run with sudo:"
echo "  sudo $PYTHON_CMD server.py"
echo ""
echo "For remote access (Azure/SSH), use SSH port forwarding:"
echo "  ssh -L 8081:localhost:8081 user@server"
echo "  Then access: http://localhost:8081 on your local machine"
echo "============================================================"
echo ""

# Check if running as root/sudo
if [ "$EUID" -eq 0 ]; then
    # Already root, just run
    $PYTHON_CMD server.py
else
    # Not root - run normally (limited process info but works)
    $PYTHON_CMD server.py
fi

echo ""
echo "Server stopped."
