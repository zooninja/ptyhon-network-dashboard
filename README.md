# Python Network Dashboard

Real-time web-based network monitoring dashboard with process management capabilities.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- Real-time network connection monitoring with 5-second auto-refresh
- Interactive filtering by connection state and process name
- Process termination with safety confirmations and rate limiting
- System hostname and IP display for multi-machine monitoring
- **Safe-by-default**: Local-only mode requires no authentication
- **Token-based authentication**: Required for network-exposed deployments
- **Critical process protection**: Prevents termination of essential system processes
- Dark naval theme with smooth animations
- Cross-platform support (Windows, Linux, macOS)

## Quick Start

### Local Mode (Recommended)

```bash
python server.py
```

Access at `http://localhost:8081`

- No authentication required
- Bind to `127.0.0.1` (localhost only)
- Process termination enabled by default

### Remote/Exposed Mode

For remote access from other machines:

```bash
# Generate a strong token
export DASHBOARD_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Start in exposed mode
python server.py --expose
```

Access at `http://<server-ip>:8081`

**Required for exposed mode:**
- `DASHBOARD_TOKEN` environment variable must be set
- Process termination disabled by default (enable with `ALLOW_TERMINATE=true`)

### Remote Mode with Termination

```bash
export DASHBOARD_TOKEN='your-secret-token'
ALLOW_TERMINATE=true python server.py --expose
```

**Warning:** Only enable process termination on trusted networks.

## Installation

### Standard Installation
```bash
pip install -r requirements.txt
python server.py
```

### Virtual Environment (Recommended for Linux)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_TOKEN` | *(none)* | Authentication token (required for exposed mode) |
| `EXPOSE` | `false` | Enable exposed mode |
| `ALLOW_TERMINATE` | `true` (local)<br>`false` (exposed) | Enable process termination |
| `HOST` | `127.0.0.1` | Host to bind to |
| `PORT` | `8081` | Port to bind to |
| `DEBUG` | `false` | Enable Flask debug mode |

### Command Line Arguments

```bash
python server.py --help
```

Options:
- `--host HOST`: Host to bind to (default: 127.0.0.1)
- `--port PORT`: Port to bind to (default: 8081)
- `--expose`: Enable exposed mode (bind to 0.0.0.0)
- `--debug`: Enable debug mode

### Configuration File

Create `config.py` for persistent settings:

```python
HOST = 'localhost'
PORT = 8081
DEBUG = False
```

## Usage

### Filtering Connections
- Click stat cards (Total, Established, Listening, etc.) to filter by connection state
- Click process names in "Top Processes" to filter by application
- Combine state and process filters for precise results
- Remove individual filters by clicking X on filter tags
- Clear all filters with "Clear All Filters" button

### Process Management
- Click any connection row to view detailed process information
- View CPU usage, memory, threads, start time, and executable path
- Terminate processes with confirmation dialogs
- **Protected processes**: Critical system processes cannot be terminated
- **Rate limiting**: Maximum 10 terminate requests per minute per IP
- **Linux/macOS:** Requires sudo for process information and termination

### System Information
- Hostname and IP address displayed under dashboard title
- Useful for monitoring multiple machines in one browser session

### Authentication

When `DASHBOARD_TOKEN` is set, all API requests must include:

```bash
Authorization: Bearer your-token-here
```

Example with curl:

```bash
# Get connections
curl -H "Authorization: Bearer $DASHBOARD_TOKEN" \
     http://localhost:8081/api/connections

# Terminate a process
curl -X DELETE \
     -H "Authorization: Bearer $DASHBOARD_TOKEN" \
     http://localhost:8081/api/connection/8081/443
```

The web UI automatically prompts for the token and stores it in localStorage.

## API Reference

All endpoints require authentication when `DASHBOARD_TOKEN` is set.

### GET /api/config
Returns dashboard configuration.

**Response:**
```json
{
  "auth_required": true,
  "terminate_enabled": false
}
```

### GET /api/connections
Returns network connections with pagination and filtering.

**Parameters:**
- `limit` (int, optional): Max results (default: 50, max: 500)
- `offset` (int, optional): Starting offset (default: 0)
- `state` (string, optional): Filter by state (e.g., "ESTABLISHED", "LISTEN")
- `process` (string, optional): Filter by process name (substring match)

**Response:**
```json
{
  "connections": [...],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

**Examples:**
```bash
# Get first 100 connections
curl "http://localhost:8081/api/connections?limit=100"

# Get established connections only
curl "http://localhost:8081/api/connections?state=ESTABLISHED"

# Filter by process name
curl "http://localhost:8081/api/connections?process=python"
```

### GET /api/stats
Returns connection statistics and top 10 processes.

### GET /api/system
Returns hostname and IP address.

### GET /api/connection/\<local_port\>/\<remote_port\>
Returns detailed connection and process information.

### DELETE /api/connection/\<local_port\>/\<remote_port\>
Terminates the process associated with a connection.

**Requires:** `ALLOW_TERMINATE=true`

**Rate Limit:** 10 requests per minute per IP

**Protected:** Cannot terminate critical system processes or PID 1

## Security Considerations

### Safe by Default

- **Local mode**: No authentication required, safe for localhost use
- **Exposed mode**: Requires `DASHBOARD_TOKEN` to start
- **Process termination**: Disabled by default in exposed mode

### Critical Process Protection

The following processes cannot be terminated:

**Windows:**
- System, csrss.exe, lsass.exe, services.exe, svchost.exe, winlogon.exe, smss.exe, dwm.exe, wininit.exe

**Linux/Unix:**
- systemd, init, launchd, kernel_task, sshd, dbus-daemon, NetworkManager, systemd-logind, systemd-udevd

**Additional Protection:**
- PID 1 cannot be terminated (init/systemd on Linux)

### Rate Limiting

- Terminate endpoint: 10 requests per minute per IP
- Simple in-memory implementation (resets on server restart)

### Best Practices for Production

1. **Use strong tokens**: Generate with `secrets.token_urlsafe(32)`
2. **Firewall rules**: Limit access to trusted IPs only
3. **VPN or SSH tunnel**: Preferred for remote access
4. **Reverse proxy**: Use nginx/caddy with HTTPS/TLS
5. **Disable terminate**: Set `ALLOW_TERMINATE=false` for exposed instances
6. **Monitor logs**: Review server output for unauthorized attempts

See [SECURITY.md](SECURITY.md) for detailed security information.

## Platform-Specific Notes

### Windows
- Run as Administrator for full process information
- Uses batch script launcher (`start.bat`)

### Linux
- Requires sudo for process details and termination
- Debian 12+/Ubuntu 23.04+ need virtual environment
- Uses shell script launchers (`start.sh`, `start_venv.sh`)

### macOS
- May require sudo for process operations
- Uses shell script launcher (`start.sh`)

## Requirements

- Python 3.7+
- psutil 5.9.0+
- Flask 2.3.0+
- flask-cors 4.0.0+

## Troubleshooting

### Port Already in Use
Change port: `python server.py --port 8082`

### No Process Information (Linux)
Run with sudo: `sudo python server.py`

### Permission Denied (Linux Scripts)
Make executable: `chmod +x start.sh start_venv.sh`

### Debian/Ubuntu pip Error
Use virtual environment launcher: `bash start_venv.sh`

### Token Required Error
Set token before starting in exposed mode:
```bash
export DASHBOARD_TOKEN='your-token'
python server.py --expose
```

### 401 Unauthorized
- Check token is set correctly
- Token is stored in browser localStorage
- Clear browser data and re-enter token

## Development

### Running Tests
```bash
# Import check
python -c "import server; print('OK')"

# Lint with ruff
pip install ruff
ruff check server.py
```

### GitHub Actions
CI workflow runs automatically on push/PR:
- Linting with ruff
- Import checks
- Basic validation

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security best practices.
