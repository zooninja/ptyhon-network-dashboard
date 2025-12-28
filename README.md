# Python Network Dashboard

Real-time web-based network monitoring dashboard with process management capabilities.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Screenshots

### Dashboard Overview
![Dashboard Overview](https://github.com/zooninja/python-network-dashboard/raw/main/screenshots/dashboard-overview.png)
*Real-time network connection monitoring with 484 active connections across multiple processes*

### Connection Filtering
![Connection Filtering](https://github.com/zooninja/python-network-dashboard/raw/main/screenshots/connection-filtering.png)
*Filter connections by state (ESTABLISHED, LISTENING, etc.) with live statistics*

### Process Termination
![Process Termination](https://github.com/zooninja/python-network-dashboard/raw/main/screenshots/process-termination.png)
*Safely terminate processes with detailed confirmation dialogs and warnings*

## Quick Start

### The Easiest Way

**Windows:**
```bash
start.bat
```

**Linux/macOS:**
```bash
./start.sh
```

Then open your browser to **http://localhost:8081** - that's it!

The start scripts automatically:
- Create a virtual environment if needed
- Install all dependencies
- Launch the dashboard

### Manual Start (If you prefer)

```bash
python server.py
```

Access at `http://localhost:8081` - no authentication required for local use.

---

## Features

- 🔄 Real-time network connection monitoring (auto-refresh every 5s)
- 🔍 Filter by connection state (ESTABLISHED, LISTENING, etc.) and process
- ⚡ Terminate processes with safety confirmations
- 🔒 Safe-by-default: localhost-only mode needs no authentication
- 🌐 Remote access mode with token authentication
- 🛡️ Critical process protection (can't terminate system processes)
- 🎨 Modern dark theme with smooth animations
- 💻 Cross-platform (Windows, Linux, macOS)

---

## Advanced Usage

### Remote Access (Access from other computers)

When you need to access the dashboard from another machine on your network:

**1. Generate a secure token:**
```bash
# Linux/macOS
export DASHBOARD_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Windows PowerShell
$env:DASHBOARD_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**2. Start in exposed mode:**
```bash
python server.py --expose
```

**3. Access from any device on your network:**
```
http://<your-server-ip>:8081
```

You'll be prompted for the token when you open the dashboard.

### Enable Process Termination in Remote Mode

By default, remote mode disables process termination for safety. To enable it:

```bash
# Linux/macOS
export DASHBOARD_TOKEN='your-secret-token'
export ALLOW_TERMINATE=true
python server.py --expose

# Windows PowerShell
$env:DASHBOARD_TOKEN='your-secret-token'
$env:ALLOW_TERMINATE='true'
python server.py --expose
```

⚠️ **Warning:** Only enable on trusted networks!

---

## Installation Details

### Requirements
- Python 3.7 or higher
- Dependencies listed in `requirements.txt`

### First-Time Setup

The start scripts (`start.bat` or `start.sh`) handle everything automatically, but if you want to set up manually:

**1. Install dependencies:**
```bash
pip install -r requirements.txt
```

**2. Run the server:**
```bash
python server.py
```

### Using a Virtual Environment (Optional)

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run server
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

When `DASHBOARD_TOKEN` is set, the web UI uses secure httpOnly cookies for authentication:

1. **Login**: Enter your token when prompted - it's sent to `/api/login`
2. **Cookie**: Server sets a secure, httpOnly cookie (protected from JavaScript/XSS)
3. **Auto-auth**: Cookie is included automatically in all API requests
4. **Logout**: Use `window.dashboardAuth.logout()` in browser console

**For API access with curl (use login endpoint):**

```bash
# Login and save cookies
curl -c cookies.txt -X POST \
     -H "Content-Type: application/json" \
     -d '{"token":"your-token-here"}' \
     http://localhost:8081/api/login

# Make authenticated requests
curl -b cookies.txt http://localhost:8081/api/connections

# Logout
curl -b cookies.txt -X POST http://localhost:8081/api/logout
```

**Legacy Bearer token auth** (for backward compatibility):
```bash
curl -H "Authorization: Bearer $DASHBOARD_TOKEN" \
     http://localhost:8081/api/connections
```

## API Reference

All endpoints (except `/api/config` and `/api/login`) require authentication when `DASHBOARD_TOKEN` is set.

### POST /api/login
Authenticate and receive httpOnly cookie.

**Request:**
```json
{
  "token": "your-token-here"
}
```

**Response:**
```json
{
  "status": "authenticated"
}
```

Sets `auth_token` httpOnly cookie (24-hour expiration).

### POST /api/logout
Clear authentication cookie.

**Response:**
```json
{
  "status": "logged out"
}
```

### GET /api/config
Returns dashboard configuration (no auth required).

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
- `limit` (int, optional): Max results (default: 50, max: 500, validated)
- `offset` (int, optional): Starting offset (default: 0, must be >= 0)
- `state` (string, optional): Filter by state - must be valid TCP state (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
- `process` (string, optional): Filter by process name (max 100 chars, substring match)

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

**Logging:** All termination attempts are logged with IP address and process details

## Security Considerations

### Safe by Default

- **Local mode**: No authentication required, safe for localhost use
- **Exposed mode**: Requires `DASHBOARD_TOKEN` to start
- **Process termination**: Disabled by default in exposed mode

### Security Hardening Features

#### 1. **httpOnly Cookie Authentication (XSS Protection)**
- Tokens stored in httpOnly cookies (inaccessible to JavaScript)
- Prevents XSS attacks from stealing authentication tokens
- Secure flag enabled when using HTTPS
- SameSite=Strict to prevent CSRF attacks
- 24-hour cookie expiration

#### 2. **Input Validation**
- All query parameters validated and sanitized
- Limit capped at 500, offset must be >= 0
- State filters validated against known TCP states
- Process filter limited to 100 characters
- Invalid inputs return 400 Bad Request with error message

#### 3. **CORS Protection**
- Whitelist-only origins: `http://localhost:8081` and `http://127.0.0.1:8081`
- Credentials support enabled for cookie-based auth
- Prevents unauthorized cross-origin requests

#### 4. **Comprehensive Logging**
- Authentication attempts (success and failure) logged with IP
- Process termination requests logged with full details
- Rate limit violations logged
- Helps detect and investigate unauthorized access

#### 5. **Docker Security**
- Runs as non-root user (UID 1000)
- Minimal attack surface with slim Python image
- Health checks for container monitoring

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
2. **Enable HTTPS**: Use reverse proxy (nginx/caddy) with TLS certificates
3. **Firewall rules**: Limit access to trusted IPs only
4. **VPN or SSH tunnel**: Preferred for remote access over public internet
5. **Disable terminate**: Set `ALLOW_TERMINATE=false` for exposed instances
6. **Monitor logs**: Review server output for unauthorized attempts
7. **Regular updates**: Keep dependencies updated (`pip install -U -r requirements.txt`)
8. **Docker deployment**: Use containerized deployment for isolation

### Process Termination Risks

⚠️ **Warning:** Process termination can disrupt system stability. Only use this feature when:
- You understand which process you're terminating
- You're on a development/testing machine
- You've verified it's not a critical system service
- You have proper backups and can recover from issues

**Never terminate processes in production without understanding the impact!**

See [SECURITY.md](SECURITY.md) for detailed security information and vulnerability reporting.

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
- Ensure cookies are enabled in your browser
- Try logging out and logging in again: `window.dashboardAuth.logout()`
- Clear browser cookies and re-enter token

---

## Docker Deployment (Advanced)

For containerized deployments, Docker support is available. See [DOCKER.md](DOCKER.md) for comprehensive documentation.

### Quick Docker Start

**Local mode:**
```bash
docker-compose --profile local up -d
```
Access at `http://localhost:8081` (token: `local-docker-no-auth`)

**⚠️ Note:** Docker on Windows/Mac cannot access host network connections due to virtualization. For full functionality, use the native Python installation (`start.bat` or `start.sh`).

### Docker Profiles

- `local` - Localhost access, port 8081 bound to 127.0.0.1
- `exposed` - Network access (requires `DASHBOARD_TOKEN` environment variable)
- `production` - HTTPS with nginx reverse proxy

For production Docker deployments, SSL certificates, and advanced configurations, see [DOCKER.md](DOCKER.md).

---

## Development

### Running Tests
```bash
# Install test dependencies
pip install pytest bandit

# Run pytest tests
pytest test_server.py -v

# Run security scan
bandit -r server.py

# Lint with ruff
pip install ruff
ruff check server.py

# Import check
python -c "import server; print('OK')"
```

### GitHub Actions
CI workflow runs automatically on push/PR:
- Linting with ruff
- Import checks
- Unit tests with pytest
- Security scanning with Bandit
- Generates security report artifact

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security best practices.
