# Running on Azure VM

Guide for running Python Network Dashboard on Azure VMs with firewall restrictions.

## The Problem

Azure Student VMs typically only allow port 22 (SSH) through the firewall. The dashboard runs on port 8081, which isn't accessible externally.

## The Solution: SSH Port Forwarding

Use SSH to create a tunnel from your local machine to the Azure VM, forwarding port 8081.

## Quick Start

### On Azure VM

1. **SSH into your VM:**
   ```bash
   ssh azureuser@your-vm-ip
   ```

2. **Clone and setup:**
   ```bash
   git clone https://github.com/zooninja/python-network-dashboard.git
   cd python-network-dashboard
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Start the dashboard:**
   ```bash
   ./start.sh
   ```

   The dashboard is now running on the VM at localhost:8081

### On Your Local Machine

**Open a NEW terminal/command prompt** and create SSH tunnel:

**Windows (PowerShell/CMD):**
```cmd
ssh -L 8081:localhost:8081 azureuser@your-vm-ip
```

**Linux/macOS:**
```bash
ssh -L 8081:localhost:8081 azureuser@your-vm-ip
```

**What this does:**
- `-L 8081:localhost:8081` - Forward local port 8081 to VM's localhost:8081
- Keep this SSH session open while using the dashboard
- Port 8081 on your local machine now connects to the dashboard on the VM

### Access the Dashboard

Open your browser: **http://localhost:8081**

You're now accessing the dashboard running on the Azure VM!

## Alternative: Background Service with systemd

For permanent deployment that survives reboots:

### 1. Create systemd service file

```bash
sudo nano /etc/systemd/system/network-dashboard.service
```

**Add this content:**
```ini
[Unit]
Description=Python Network Dashboard
After=network.target

[Service]
Type=simple
User=azureuser
WorkingDirectory=/home/azureuser/python-network-dashboard
Environment="PATH=/home/azureuser/python-network-dashboard/venv/bin"
ExecStart=/home/azureuser/python-network-dashboard/venv/bin/python server.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. Enable and start service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start the service
sudo systemctl start network-dashboard

# Enable auto-start on boot
sudo systemctl enable network-dashboard

# Check status
sudo systemctl status network-dashboard
```

### 3. Manage the service

```bash
# View logs
sudo journalctl -u network-dashboard -f

# Stop service
sudo systemctl stop network-dashboard

# Restart service
sudo systemctl restart network-dashboard

# Disable auto-start
sudo systemctl disable network-dashboard
```

## Opening Azure Firewall (Optional)

If you want direct access without SSH tunneling:

### Azure Portal Method

1. Go to Azure Portal → Your VM → Networking
2. Click "Add inbound port rule"
3. Configure:
   - **Destination port ranges:** 8081
   - **Protocol:** TCP
   - **Action:** Allow
   - **Priority:** 1000
   - **Name:** Allow-Dashboard-8081
4. Click "Add"

### Azure CLI Method

```bash
az vm open-port \
  --resource-group your-resource-group \
  --name your-vm-name \
  --port 8081 \
  --priority 1000
```

### Important Security Notes

**WARNING:** Opening port 8081 to the internet is risky!

If you open the port:
1. **MUST set authentication:**
   ```bash
   export DASHBOARD_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
   export ALLOW_TERMINATE=false  # Disable termination for security
   python3 server.py --expose
   ```

2. **Better approach:** Use Azure NSG to restrict source IPs:
   - Only allow your home/office IP
   - Or use a VPN and only allow VPN subnet

3. **Best practice:** Keep port 22 only and use SSH tunneling (most secure)

## SSH Tunnel Helper Script

Create a local helper script for easy connection:

**`connect-azure-dashboard.bat` (Windows):**
```batch
@echo off
echo Connecting to Azure VM Dashboard...
echo Dashboard will be available at: http://localhost:8081
echo Press Ctrl+C to disconnect
ssh -L 8081:localhost:8081 azureuser@YOUR-VM-IP
```

**`connect-azure-dashboard.sh` (Linux/macOS):**
```bash
#!/bin/bash
echo "Connecting to Azure VM Dashboard..."
echo "Dashboard will be available at: http://localhost:8081"
echo "Press Ctrl+C to disconnect"
ssh -L 8081:localhost:8081 azureuser@YOUR-VM-IP
```

Replace `YOUR-VM-IP` with your actual VM IP address.

## Troubleshooting

### "Permission denied" when installing packages

Make sure you're in the virtual environment:
```bash
source venv/bin/activate
```

### "Module not found" after installing in venv

The `start.sh` script now auto-detects venv. Just run:
```bash
source venv/bin/activate
./start.sh
```

### SSH tunnel not working

1. Make sure the dashboard is running on the VM
2. Check SSH connection: `ssh azureuser@your-vm-ip`
3. Try different local port: `ssh -L 8082:localhost:8081 azureuser@your-vm-ip`
   Then access: http://localhost:8082

### Can't terminate processes

Normal behavior when not running as root. To enable:
```bash
sudo /home/azureuser/python-network-dashboard/venv/bin/python server.py
```

### Dashboard stops when SSH session ends

Use systemd service (see above) or `tmux`/`screen`:

```bash
# Install tmux
sudo apt install tmux

# Start tmux session
tmux new -s dashboard

# Inside tmux, start dashboard
cd ~/python-network-dashboard
source venv/bin/activate
./start.sh

# Detach from tmux: Press Ctrl+B, then D
# Dashboard keeps running

# Reattach later
tmux attach -t dashboard
```

## Cost Optimization

Azure Student VMs cost money when running. Consider:

1. **Auto-shutdown:** Configure in Azure Portal → VM → Auto-shutdown
2. **Stop when not needed:**
   ```bash
   az vm deallocate --resource-group RG --name VM-NAME
   ```
3. **B-series burstable VMs:** Cheaper for intermittent workloads
4. **Scheduled start/stop:** Use Azure Automation

## Network Monitoring on Azure

The dashboard shows network connections on the VM itself, useful for:
- Monitoring Azure services connecting to your VM
- Checking SSH connections
- Viewing outbound connections to Azure resources
- Debugging network issues

It does NOT show:
- Azure-level network traffic (use Azure Monitor for that)
- Traffic between Azure resources (use Network Watcher)
- Detailed packet analysis (use tcpdump/wireshark)
