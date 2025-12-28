# Python Network Dashboard

Real-time web-based network monitoring dashboard with process management capabilities.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- Real-time network connection monitoring (5-second auto-refresh)
- Interactive filtering by connection state and process
- Process termination with safety confirmations
- Dark naval theme with smooth animations
- Cross-platform (Windows, Linux, macOS)

## Quick Start

**Windows:**
```batch
start.bat
```

**Linux/macOS:**
```bash
./start.sh
```

**Linux (Debian 12+/Ubuntu 23.04+):**
```bash
chmod +x start_venv.sh
./start_venv.sh
```

Open browser to `http://localhost:8081`

## Installation

```bash
pip install -r requirements.txt
python server.py
```

## Usage

### Filtering
- Click stat cards to filter by connection state
- Click processes to filter by application
- Combine filters for precise results
- Click X on tags or Clear All Filters to reset

### Process Management
- Click any connection to view details
- Terminate processes with confirmation dialogs
- Protected system processes cannot be terminated
- May require administrator/sudo privileges

## API Endpoints

### GET /api/connections
Returns active connections (max 50).

### GET /api/stats
Returns connection statistics and top 10 processes.

### GET /api/connection/\<local_port\>/\<remote_port\>
Returns detailed connection and process information.

### DELETE /api/connection/\<local_port\>/\<remote_port\>
Terminates the process associated with a connection.

## Configuration

Port can be changed in `server.py` line 249:
```python
app.run(host='localhost', port=8081, debug=False)
```

## Requirements

- Python 3.7+
- psutil 5.9.0+
- Flask 2.3.0+
- flask-cors 4.0.0+

## License

MIT License - see LICENSE file for details.
