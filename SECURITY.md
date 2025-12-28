# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Python Network Dashboard, please report it by sending an email to the repository maintainers. **Do not open a public issue.**

### What to Include

When reporting a vulnerability, please provide:

1. **Description**: Clear description of the vulnerability
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Impact**: What an attacker could achieve
4. **Affected Versions**: Which versions are affected
5. **Suggested Fix**: If you have ideas for fixing it

### Response Time

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity (critical issues prioritized)

## Security Best Practices

### For Local Use

- Default configuration is safe for local-only use
- No authentication required when binding to `127.0.0.1`

### For Exposed/Remote Use

When exposing the dashboard over the network:

1. **Always set DASHBOARD_TOKEN**: Never run in exposed mode without a strong token
   ```bash
   export DASHBOARD_TOKEN='your-strong-random-token-here'
   ```

2. **Use strong tokens**: Minimum 32 characters, random alphanumeric
   ```bash
   # Generate a strong token
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Firewall rules**: Limit access to trusted IPs only
   ```bash
   # Example: ufw allow from 192.168.1.0/24 to any port 8081
   ```

4. **VPN or SSH tunnel**: Preferred for production access
   ```bash
   # SSH tunnel example
   ssh -L 8081:localhost:8081 user@remote-server
   ```

5. **Disable terminate in production**: Set `ALLOW_TERMINATE=false` for exposed instances

6. **HTTPS/TLS**: Use a reverse proxy (nginx/caddy) with TLS for encrypted traffic

### Process Termination Safety

The dashboard includes several safety mechanisms:

- **Critical Process Denylist**: Prevents termination of essential system processes
- **PID 1 Protection**: Cannot terminate init/systemd
- **Rate Limiting**: 10 terminate requests per minute per IP
- **Confirmation Required**: UI requires user confirmation before terminating

However, process termination is inherently dangerous. Use with caution.

## Known Limitations

1. **No user management**: Single token for all users
2. **No audit logging**: Process terminations are not logged
3. **In-memory rate limiting**: Resets on server restart
4. **No HTTPS built-in**: Requires reverse proxy for encrypted traffic

## Secure Deployment Example

```bash
# Generate strong token
export DASHBOARD_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Run in exposed mode with terminate disabled
EXPOSE=true ALLOW_TERMINATE=false python server.py --host 0.0.0.0 --port 8081
```

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

We only support the latest version. Please update to the latest release for security fixes.
