import os
import sys
import argparse
import time
from functools import wraps
from collections import defaultdict
from flask import Flask, jsonify, send_file, request
from flask_cors import CORS
import psutil
import socket
from datetime import datetime
from collections import Counter

# Configuration from environment variables and CLI args
DASHBOARD_TOKEN = os.getenv('DASHBOARD_TOKEN', '')
EXPOSE = os.getenv('EXPOSE', 'false').lower() in ('true', '1', 'yes')
ALLOW_TERMINATE = os.getenv('ALLOW_TERMINATE', 'true').lower() in ('true', '1', 'yes')

try:
    from config import HOST, PORT, DEBUG
except ImportError:
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', '8081'))
    DEBUG = os.getenv('DEBUG', 'false').lower() in ('true', '1', 'yes')

app = Flask(__name__)
CORS(app)

# Critical process denylist - prevents termination of essential system processes
CRITICAL_PROCESSES = [
    # Windows
    'System', 'csrss.exe', 'lsass.exe', 'services.exe', 'svchost.exe',
    'winlogon.exe', 'smss.exe', 'dwm.exe', 'wininit.exe',
    # Linux/Unix
    'systemd', 'init', 'launchd', 'kernel_task', 'sshd', 'dbus-daemon',
    'NetworkManager', 'systemd-logind', 'systemd-udevd'
]

# Rate limiting for terminate endpoint (simple in-memory implementation)
class RateLimiter:
    def __init__(self, max_requests=10, window=60):
        self.max_requests = max_requests
        self.window = window  # seconds
        self.requests = defaultdict(list)

    def is_allowed(self, ip):
        now = time.time()
        # Clean old entries
        self.requests[ip] = [ts for ts in self.requests[ip] if now - ts < self.window]

        if len(self.requests[ip]) >= self.max_requests:
            return False

        self.requests[ip].append(now)
        return True

terminate_limiter = RateLimiter(max_requests=10, window=60)

def require_auth(f):
    """Decorator to require token authentication when in exposed mode"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip auth if not in exposed mode and no token is set
        if not EXPOSE and not DASHBOARD_TOKEN:
            return f(*args, **kwargs)

        # If token is set (local or exposed), enforce it
        if DASHBOARD_TOKEN:
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401

            token = auth_header[7:]  # Remove 'Bearer ' prefix
            if token != DASHBOARD_TOKEN:
                return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated_function

def is_localhost(ip):
    return ip.startswith('127.') or ip == '::1' or ip.startswith('::ffff:127.')

def get_process_details(pid):
    try:
        proc = psutil.Process(pid)

        try:
            process_path = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            process_path = "Access Denied"

        try:
            cpu = round(proc.cpu_percent(interval=0.1), 2)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            cpu = 0.0

        try:
            mem_info = proc.memory_info()
            memory_mb = round(mem_info.rss / 1024 / 1024, 2)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            memory_mb = 0.0

        try:
            threads = proc.num_threads()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            threads = 0

        try:
            start_time = datetime.fromtimestamp(proc.create_time()).isoformat()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            start_time = "Unknown"

        return {
            'ProcessName': proc.name(),
            'ProcessId': proc.pid,
            'ProcessPath': process_path,
            'ProcessCPU': cpu,
            'ProcessMemory': memory_mb,
            'ProcessThreads': threads,
            'ProcessStartTime': start_time
        }
    except psutil.NoSuchProcess:
        return None

@app.route('/')
def index():
    return send_file('dashboard.html')

@app.route('/api/config')
def get_config():
    """Return frontend configuration (auth status, terminate status)"""
    return jsonify({
        'auth_required': bool(DASHBOARD_TOKEN),
        'terminate_enabled': ALLOW_TERMINATE
    })

@app.route('/api/connections')
@require_auth
def get_connections():
    try:
        # Pagination parameters
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))

        # Filter parameters
        state_filter = request.args.get('state', '').upper()
        process_filter = request.args.get('process', '').lower()

        connections = []
        all_connections = psutil.net_connections(kind='inet')

        for conn in all_connections:
            include_connection = False
            if conn.status == 'LISTEN' and conn.laddr and not is_localhost(conn.laddr.ip):
                include_connection = True
            elif conn.raddr and not is_localhost(conn.raddr.ip):
                include_connection = True

            if include_connection:
                try:
                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    # Apply filters
                    if state_filter and conn.status != state_filter:
                        continue
                    if process_filter and process_filter not in process_name.lower():
                        continue

                    connections.append({
                        'LocalPort': conn.laddr.port if conn.laddr else 0,
                        'RemoteAddress': conn.raddr.ip if conn.raddr else 'N/A',
                        'RemotePort': conn.raddr.port if conn.raddr else 0,
                        'State': conn.status,
                        'ProcessName': process_name,
                        'ProcessId': conn.pid if conn.pid else 0
                    })
                except Exception:
                    continue

        # Apply pagination
        total = len(connections)
        paginated = connections[offset:offset + limit]

        return jsonify({
            'connections': paginated,
            'total': total,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system')
@require_auth
def get_system_info():
    try:
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except OSError:
            ip_address = '127.0.0.1'

        return jsonify({
            'hostname': hostname,
            'ip': ip_address
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@require_auth
def get_stats():
    try:
        all_connections = psutil.net_connections(kind='inet')
        state_counts = Counter()
        process_counts = Counter()

        for conn in all_connections:
            state_counts[conn.status] += 1

            if conn.raddr and not is_localhost(conn.raddr.ip) and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_counts[f"{proc.name()}|{conn.pid}"] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        top_processes = []
        for proc_key, count in process_counts.most_common(10):
            proc_name, proc_pid = proc_key.split('|')
            top_processes.append({
                'ProcessName': proc_name,
                'ProcessId': int(proc_pid),
                'ConnectionCount': count
            })

        stats = {
            'Stats': {
                'Total': sum(state_counts.values()),
                'Established': state_counts.get('ESTABLISHED', 0),
                'Listening': state_counts.get('LISTEN', 0),
                'TimeWait': state_counts.get('TIME_WAIT', 0),
                'CloseWait': state_counts.get('CLOSE_WAIT', 0)
            },
            'TopProcesses': top_processes,
            'Timestamp': datetime.now().isoformat()
        }

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/connection/<int:local_port>/<int:remote_port>')
@require_auth
def get_connection_details(local_port, remote_port):
    try:
        all_connections = psutil.net_connections(kind='inet')

        for conn in all_connections:
            if (conn.laddr and conn.laddr.port == local_port and
                conn.raddr and conn.raddr.port == remote_port):

                if not conn.pid:
                    return jsonify({'error': 'No process associated with connection'}), 404

                details = get_process_details(conn.pid)
                if not details:
                    return jsonify({'error': 'Process not found'}), 404

                details.update({
                    'LocalPort': local_port,
                    'RemoteAddress': conn.raddr.ip,
                    'RemotePort': remote_port,
                    'State': conn.status
                })

                return jsonify(details)

        return jsonify({'error': 'Connection not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/connection/<int:local_port>/<int:remote_port>', methods=['DELETE'])
@require_auth
def kill_connection(local_port, remote_port):
    # Check if terminate is allowed
    if not ALLOW_TERMINATE:
        return jsonify({
            'success': False,
            'message': 'Process termination is disabled. Set ALLOW_TERMINATE=true to enable.'
        }), 403

    # Rate limiting
    client_ip = request.remote_addr
    if not terminate_limiter.is_allowed(client_ip):
        return jsonify({
            'success': False,
            'message': 'Rate limit exceeded. Maximum 10 terminate requests per minute.'
        }), 429

    try:
        all_connections = psutil.net_connections(kind='inet')

        for conn in all_connections:
            if (conn.laddr and conn.laddr.port == local_port and
                conn.raddr and conn.raddr.port == remote_port):

                if not conn.pid:
                    return jsonify({
                        'success': False,
                        'message': 'No process associated with connection'
                    }), 400

                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    proc_id = proc.pid

                    # Prevent terminating PID 1 on Linux (init/systemd)
                    if proc_id == 1:
                        return jsonify({
                            'success': False,
                            'message': 'Cannot terminate init process (PID 1)',
                            'processName': proc_name,
                            'processId': proc_id
                        }), 403

                    # Check critical process denylist
                    if proc_name in CRITICAL_PROCESSES:
                        return jsonify({
                            'success': False,
                            'message': f'Cannot terminate critical system process: {proc_name}',
                            'processName': proc_name,
                            'processId': proc_id
                        }), 403

                    proc.terminate()

                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()

                    return jsonify({
                        'success': True,
                        'message': 'Process terminated successfully',
                        'processName': proc_name,
                        'processId': proc_id
                    })

                except psutil.NoSuchProcess:
                    return jsonify({
                        'success': False,
                        'message': 'Process no longer exists'
                    }), 404

                except psutil.AccessDenied:
                    return jsonify({
                        'success': False,
                        'message': 'Access denied - run as administrator/sudo'
                    }), 403

        return jsonify({
            'success': False,
            'message': 'Connection not found'
        }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def parse_args():
    parser = argparse.ArgumentParser(description='Python Network Dashboard Server')
    parser.add_argument('--host', default=HOST, help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=PORT, help='Port to bind to (default: 8081)')
    parser.add_argument('--expose', action='store_true', help='Enable exposed mode (bind to 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', default=DEBUG, help='Enable debug mode')
    return parser.parse_args()

def validate_config(host, expose_flag):
    """Validate configuration before starting server"""
    global EXPOSE, ALLOW_TERMINATE

    # Update EXPOSE based on CLI flag or host setting
    if expose_flag or host == '0.0.0.0':
        EXPOSE = True

    # Check if binding to non-localhost
    is_local = host in ('127.0.0.1', 'localhost', '::1')

    if EXPOSE or not is_local:
        if not DASHBOARD_TOKEN:
            print("\n" + "=" * 60)
            print("ERROR: Security violation!")
            print("=" * 60)
            print("Exposed mode requires DASHBOARD_TOKEN to be set.")
            print("\nTo start in exposed mode:")
            print("  export DASHBOARD_TOKEN='your-secret-token'")
            print("  python server.py --expose")
            print("\nOr for local-only mode:")
            print("  python server.py")
            print("=" * 60)
            sys.exit(1)

        # In exposed mode, default ALLOW_TERMINATE to false unless explicitly enabled
        if os.getenv('ALLOW_TERMINATE') is None:
            ALLOW_TERMINATE = False

if __name__ == '__main__':
    args = parse_args()

    # Apply CLI overrides
    host = args.host
    port = args.port
    debug = args.debug

    # Validate configuration
    validate_config(host, args.expose)

    # Print startup banner
    print("=" * 60)
    print("Python Network Dashboard Server")
    print("=" * 60)
    mode = "Exposed" if EXPOSE or host not in ('127.0.0.1', 'localhost') else "Local"
    print(f"Mode: {mode}")
    print(f"Bind: {host}:{port}")

    if EXPOSE or host == '0.0.0.0':
        print(f"Access: http://<server-ip>:{port}")
    else:
        print(f"Access: http://localhost:{port}")

    print(f"Auth: {'Enabled' if DASHBOARD_TOKEN else 'Disabled'}")
    print(f"Terminate: {'Enabled' if ALLOW_TERMINATE else 'Disabled'}")

    if DASHBOARD_TOKEN:
        print("\nAuthorization Header:")
        print(f"  Authorization: Bearer {DASHBOARD_TOKEN}")

    print("\nPress Ctrl+C to stop the server")
    print("=" * 60 + "\n")

    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\nServer stopped")
    except OSError as e:
        if "address already in use" in str(e).lower():
            print(f"\nError: Port {port} is already in use.")
            print(f"Please close the application using port {port} or use a different port.")
        else:
            print(f"\nError: {e}")
