@echo off
echo ============================================================
echo Python Network Dashboard Launcher
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)

echo Python detected. Checking dependencies...
echo.

REM Check if required packages are installed
python -c "import psutil, flask, flask_cors" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo Starting Python Network Dashboard...
echo Server will be available at: http://localhost:8081
echo.
echo Press Ctrl+C to stop the server
echo ============================================================
echo.

python server.py

echo.
echo Server stopped.
pause
