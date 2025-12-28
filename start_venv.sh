#!/bin/bash

VENV_DIR="venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "Installing dependencies..."
pip install -q -r requirements.txt

echo "Starting server..."
echo "Note: Requires sudo for process information and termination"
sudo "$VENV_DIR/bin/python3" server.py

deactivate
