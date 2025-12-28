# Remote Access Guide: SSH Tunneling for Restricted Networks

This guide covers how to monitor remote machines that have limited ports open (firewalls, cloud VMs, corporate networks) using SSH port forwarding.

## Use Cases

### When to Use SSH Tunneling

Use SSH tunneling when you need to monitor a remote machine that:
- **Has firewall restrictions** (only SSH port 22 open)
- **Is on a cloud platform** (Azure, AWS, GCP with default firewall rules)
- **Is behind a corporate firewall** (only SSH allowed)
- **Is on a home network** (don't want to expose additional ports)
- **Needs secure access** (encrypt dashboard traffic through SSH)

### Real-World Scenarios

1. **Cloud VMs** (Azure, AWS, GCP)
   - Student/free tier accounts often restrict ports
   - Only SSH (port 22) accessible by default
   - Opening additional ports may cost money or violate policies

2. **Corporate Servers**
   - IT policies restrict open ports
   - VPN required for internal access
   - SSH is the only approved remote access method

3. **Home Servers / Raspberry Pi**
   - Don't want to expose multiple ports to internet
   - Router port forwarding limited to SSH only
   - Security-conscious setup

4. **Development/Staging Environments**
   - Temporary access needed without permanent firewall changes
   - Multiple developers need isolated access
   - Quick troubleshooting without reconfiguring network

---

## How SSH Port Forwarding Works

SSH tunneling creates a secure encrypted tunnel that forwards traffic from your local machine to the remote server.

```
Your Computer          SSH Tunnel           Remote Server
┌─────────────┐       (Encrypted)          ┌──────────────┐
│             │                            │              │
│ Browser     │                            │  Dashboard   │
│ localhost:  │◄──────────────────────────►│  localhost:  │
│ 8081        │    SSH Port Forwarding     │  8081        │
│             │                            │              │
└─────────────┘                            └──────────────┘
```

**What happens:**
1. Dashboard runs on remote server at `localhost:8081`
2. SSH creates a tunnel: `local:8081` → `remote:8081`
3. You access `http://localhost:8081` on your computer
4. Traffic is encrypted and forwarded through SSH to the remote dashboard
5. Only port 22 (SSH) needs to be open on the remote server

---

## Basic Setup: Monitor One Remote Machine

### Step 1: Deploy Dashboard on Remote Server

**SSH into your remote server:**
```bash
ssh user@remote-server-ip
```

**Install and start the dashboard:**
```bash
# Clone the repository
git clone https://github.com/zooninja/python-network-dashboard.git
cd python-network-dashboard

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies and start
./start.sh
```

The dashboard is now running on the remote server at `localhost:8081`.

### Step 2: Create SSH Tunnel from Your Computer

**On your local machine** (Windows, Mac, or Linux):

**Windows (PowerShell/CMD):**
```cmd
ssh -L 8081:localhost:8081 user@remote-server-ip
```

**Linux/macOS:**
```bash
ssh -L 8081:localhost:8081 user@remote-server-ip
```

**If using SSH key:**
```bash
ssh -i /path/to/private-key.pem -L 8081:localhost:8081 user@remote-server-ip
```

### Step 3: Access the Dashboard

Open your browser and go to: **http://localhost:8081**

You're now viewing the network connections of your **remote server**, not your local machine!

**Important:** Keep the SSH session open. If you close it, the tunnel disconnects and you lose access.

---

## Advanced: Monitor Multiple Remote Machines

You can monitor several remote servers simultaneously by using different local ports for each tunnel.

### Scenario: Monitor 3 Servers

Let's say you have:
- **Production Server** (prod.example.com)
- **Staging Server** (staging.example.com)
- **Development Server** (dev.example.com)

### Step 1: Configure Different Ports on Each Server

On each remote server, start the dashboard on a **unique port**:

**Production Server:**
```bash
cd ~/python-network-dashboard
source venv/bin/activate
python server.py --port 8081
```

**Staging Server:**
```bash
cd ~/python-network-dashboard
source venv/bin/activate
python server.py --port 8082
```

**Development Server:**
```bash
cd ~/python-network-dashboard
source venv/bin/activate
python server.py --port 8083
```

**Note:** You can use the same port (8081) on all servers since they're isolated. The important part is mapping them to **different local ports** on your computer.

### Step 2: Create Multiple SSH Tunnels

**Option A: Map to different local ports (recommended)**

Open **three separate terminal windows/tabs** on your local machine:

**Terminal 1 - Production:**
```bash
ssh -L 8081:localhost:8081 user@prod.example.com
```

**Terminal 2 - Staging:**
```bash
ssh -L 8082:localhost:8081 user@staging.example.com
```

**Terminal 3 - Development:**
```bash
ssh -L 8083:localhost:8081 user@dev.example.com
```

Notice: All remote servers run on port 8081, but we map them to different **local** ports (8081, 8082, 8083).

### Step 3: Access All Dashboards in Your Browser

Now open multiple browser tabs:

- **Production:** http://localhost:8081
- **Staging:** http://localhost:8082
- **Development:** http://localhost:8083

Each tab shows a different server's network connections!

### Visual Example

```
Your Local Machine                 Remote Servers
┌─────────────────────┐
│                     │
│ Browser Tab 1       │──8081──►  Production (8081)
│ localhost:8081      │
│                     │
│ Browser Tab 2       │──8082──►  Staging (8081)
│ localhost:8082      │
│                     │
│ Browser Tab 3       │──8083──►  Development (8081)
│ localhost:8083      │
│                     │
└─────────────────────┘
```

---

## Helper Scripts for Easy Access

### Windows: Create Connection Scripts

Create `.bat` files for each server:

**`connect-production.bat`:**
```batch
@echo off
echo Connecting to Production Server...
echo Dashboard available at: http://localhost:8081
echo Press Ctrl+C to disconnect
ssh -i C:\path\to\key.pem -L 8081:localhost:8081 user@prod.example.com
```

**`connect-staging.bat`:**
```batch
@echo off
echo Connecting to Staging Server...
echo Dashboard available at: http://localhost:8082
echo Press Ctrl+C to disconnect
ssh -i C:\path\to\key.pem -L 8082:localhost:8081 user@staging.example.com
```

**`connect-development.bat`:**
```batch
@echo off
echo Connecting to Development Server...
echo Dashboard available at: http://localhost:8083
echo Press Ctrl+C to disconnect
ssh -i C:\path\to\key.pem -L 8083:localhost:8081 user@dev.example.com
```

Double-click the `.bat` file to connect!

### Linux/macOS: Create Connection Scripts

**`connect-production.sh`:**
```bash
#!/bin/bash
echo "Connecting to Production Server..."
echo "Dashboard available at: http://localhost:8081"
echo "Press Ctrl+C to disconnect"
ssh -i ~/.ssh/prod-key.pem -L 8081:localhost:8081 user@prod.example.com
```

Make it executable:
```bash
chmod +x connect-production.sh
./connect-production.sh
```

---

## Port Mapping Strategies

### Strategy 1: Sequential Local Ports (Simple)

Map each server to consecutive local ports:
- Server 1: `localhost:8081`
- Server 2: `localhost:8082`
- Server 3: `localhost:8083`

**Pro:** Easy to remember
**Con:** Need to remember which port is which server

### Strategy 2: Meaningful Port Numbers

Use port numbers that mean something:
- Production: `localhost:8001` (80 = HTTP, 01 = prod)
- Staging: `localhost:8002` (02 = staging)
- Development: `localhost:8003` (03 = dev)

### Strategy 3: Same Remote Port, Different Local Ports

All servers run on port 8081 (remote), but map to different local ports:
```bash
ssh -L 9001:localhost:8081 user@server1
ssh -L 9002:localhost:8081 user@server2
ssh -L 9003:localhost:8081 user@server3
```

Access at: `localhost:9001`, `localhost:9002`, `localhost:9003`

---

## Configuration Tips

### Run Dashboard on Custom Port

You can configure the dashboard to run on any port:

**Using command line:**
```bash
python server.py --port 9000
```

**Using environment variable:**
```bash
export PORT=9000
python server.py
```

**Using config file:**

Create `config.py`:
```python
HOST = 'localhost'
PORT = 9000
DEBUG = False
```

Then start normally:
```bash
python server.py
```

### Keep Dashboards Running After SSH Disconnect

Use `tmux` or `screen` to keep the dashboard running even after you log out:

**Using tmux:**
```bash
# SSH into server
ssh user@remote-server

# Start tmux session
tmux new -s dashboard

# Start dashboard
cd ~/python-network-dashboard
source venv/bin/activate
./start.sh

# Detach from tmux (press Ctrl+B, then D)
# Dashboard keeps running

# Later, reattach
tmux attach -s dashboard
```

**Using systemd (permanent service):**

See [AZURE.md](AZURE.md) for complete systemd setup instructions.

---

## Troubleshooting

### "Port already in use" on Local Machine

**Problem:** Another application is using the local port.

**Solution:** Use a different local port:
```bash
ssh -L 8082:localhost:8081 user@remote-server
```
Then access at `http://localhost:8082`

### "Connection refused" When Accessing localhost:8081

**Possible causes:**
1. Dashboard not running on remote server
2. SSH tunnel not established
3. Wrong port number

**Check:**
```bash
# On remote server - verify dashboard is running
ps aux | grep python

# On local machine - verify SSH tunnel is active
netstat -an | grep 8081  # Windows
netstat -an | grep 8081  # Linux/Mac
```

### Can't SSH with Password (Public Key Required)

Some servers (like Azure VMs) require SSH keys instead of passwords.

**Solution:** Use `-i` flag with your private key:
```bash
ssh -i /path/to/private-key.pem -L 8081:localhost:8081 user@server
```

**Windows:** Use forward slashes or double backslashes:
```cmd
ssh -i C:/Users/Name/key.pem -L 8081:localhost:8081 user@server
```

### SSH Tunnel Disconnects Randomly

**Problem:** Network timeout or SSH keepalive not configured.

**Solution:** Add keepalive to SSH config.

**Linux/macOS** - Edit `~/.ssh/config`:
```
Host remote-server
    HostName remote-server-ip
    User username
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

**Windows** - Create `%USERPROFILE%\.ssh\config`:
```
Host remote-server
    HostName remote-server-ip
    User username
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Then connect with:
```bash
ssh -L 8081:localhost:8081 remote-server
```

### Dashboard Shows Local Machine Connections Instead of Remote

**Problem:** You're accessing a dashboard running on your local machine, not the remote one.

**Solution:**
1. Stop any local dashboard instances
2. Verify SSH tunnel is active
3. Check that remote dashboard is running
4. Look at the hostname shown in the dashboard (should be remote server name)

---

## Security Best Practices

### 1. Use Strong SSH Keys

Generate a strong SSH key pair:
```bash
ssh-keygen -t ed25519 -C "dashboard-access"
```

### 2. Restrict SSH Key Permissions

**Linux/macOS:**
```bash
chmod 600 ~/.ssh/id_ed25519
```

**Windows:** Right-click key file → Properties → Security → Advanced → Disable inheritance → Remove all users except yourself

### 3. Use SSH Key with Passphrase

Always protect your SSH key with a strong passphrase.

### 4. Enable Dashboard Authentication

For extra security, require token authentication:

**On remote server:**
```bash
export DASHBOARD_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "Your token: $DASHBOARD_TOKEN"
python server.py
```

When you access the dashboard, you'll be prompted for the token.

### 5. Disable Process Termination

If you don't need to kill processes remotely:
```bash
export ALLOW_TERMINATE=false
python server.py
```

### 6. Bind to Localhost Only

Ensure the dashboard only listens on localhost (default):
```bash
python server.py --host 127.0.0.1
```

Never use `--host 0.0.0.0` when combined with SSH tunneling.

---

## Cloud Platform Examples

### Azure VMs

See [AZURE.md](AZURE.md) for complete Azure-specific guide including:
- SSH key setup
- systemd service configuration
- Azure firewall rules (if needed)

**Quick start:**
```bash
ssh -i azure-key.pem -L 8081:localhost:8081 azureuser@vm-ip-address
```

### AWS EC2

**Connect with EC2 key:**
```bash
ssh -i ec2-keypair.pem -L 8081:localhost:8081 ec2-user@ec2-instance-ip
```

**Note:** Default usernames:
- Amazon Linux: `ec2-user`
- Ubuntu: `ubuntu`
- Debian: `admin`

### Google Cloud Platform (GCP)

**Using gcloud SDK:**
```bash
gcloud compute ssh instance-name \
  --zone=us-central1-a \
  -- -L 8081:localhost:8081
```

**Using standard SSH:**
```bash
ssh -i gcp-key -L 8081:localhost:8081 username@gcp-instance-ip
```

### DigitalOcean Droplets

```bash
ssh -L 8081:localhost:8081 root@droplet-ip
```

### Oracle Cloud

```bash
ssh -i oracle-key.pem -L 8081:localhost:8081 ubuntu@oracle-instance-ip
```

---

## Alternative: Reverse SSH Tunnel

If you can't directly SSH to the remote server (behind NAT, restrictive firewall), but the remote server can SSH to you:

**On your local machine (with public IP or port forwarding):**
```bash
# Start SSH server if not running
# Linux: sudo systemctl start sshd
# Windows: Enable OpenSSH Server in Settings
```

**On remote server:**
```bash
# Create reverse tunnel
ssh -R 8081:localhost:8081 your-username@your-public-ip

# Start dashboard
cd ~/python-network-dashboard
source venv/bin/activate
./start.sh
```

Now access on your local machine: `http://localhost:8081`

---

## Comparison: Direct Access vs SSH Tunneling

| Aspect | Direct Access (Exposed) | SSH Tunnel |
|--------|------------------------|------------|
| **Firewall ports needed** | 22 (SSH) + 8081 (Dashboard) | 22 (SSH) only |
| **Security** | Requires authentication token | Encrypted through SSH |
| **Setup complexity** | Firewall config + token | Just SSH command |
| **Connection** | Direct HTTP | Encrypted tunnel |
| **Persistent access** | Yes | Only while SSH connected |
| **Best for** | Production monitoring | Development/troubleshooting |

---

## Quick Reference

### Single Server
```bash
ssh -L 8081:localhost:8081 user@server-ip
# Access: http://localhost:8081
```

### Multiple Servers
```bash
# Terminal 1
ssh -L 8081:localhost:8081 user@server1

# Terminal 2
ssh -L 8082:localhost:8081 user@server2

# Terminal 3
ssh -L 8083:localhost:8081 user@server3

# Access:
# http://localhost:8081 (server1)
# http://localhost:8082 (server2)
# http://localhost:8083 (server3)
```

### With SSH Key
```bash
ssh -i /path/to/key.pem -L 8081:localhost:8081 user@server
```

### With Custom Remote Port
```bash
ssh -L 8081:localhost:9000 user@server
# Remote dashboard on port 9000
# Access locally on port 8081
```

---

## Summary

SSH tunneling is the **secure, simple, and recommended** way to monitor remote machines with restricted network access. You only need:

1. SSH access (port 22)
2. Dashboard running on remote machine
3. One SSH command to create the tunnel

No firewall changes, no exposed ports, no security risks. Perfect for cloud VMs, corporate servers, and security-conscious deployments.

For platform-specific guides, see:
- [AZURE.md](AZURE.md) - Azure VM complete setup
- [SECURITY.md](SECURITY.md) - Security best practices
- [README.md](README.md) - General usage and features
