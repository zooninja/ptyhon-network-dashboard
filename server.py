from flask import Flask, jsonify, send_file
from flask_cors import CORS
import psutil
import socket
from datetime import datetime
from collections import Counter

app = Flask(__name__)
CORS(app)

PROTECTED_NAMES = ['System', 'csrss.exe', 'lsass.exe', 'services.exe',
                   'svchost.exe', 'winlogon.exe', 'smss.exe', 'dwm.exe',
                   'systemd', 'init', 'launchd', 'kernel_task']

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

@app.route('/api/connections')
def get_connections():
    try:
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

        connections = connections[:50]
        return jsonify(connections)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system')
def get_system_info():
    try:
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = '127.0.0.1'

        return jsonify({
            'hostname': hostname,
            'ip': ip_address
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
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
def kill_connection(local_port, remote_port):
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

                    if proc_name in PROTECTED_NAMES:
                        return jsonify({
                            'success': False,
                            'message': f'Cannot kill system process: {proc_name}',
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
                        'message': f'Process terminated successfully',
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

if __name__ == '__main__':
    print("=" * 60)
    print("Python Network Dashboard Server")
    print("=" * 60)
    print(f"Starting server on http://localhost:8081")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)

    try:
        app.run(host='localhost', port=8081, debug=False)
    except KeyboardInterrupt:
        print("\nServer stopped")
    except OSError as e:
        if "address already in use" in str(e).lower():
            print("\nError: Port 8081 is already in use.")
            print("Please close the application using port 8081 or use a different port.")
        else:
            print(f"\nError: {e}")
