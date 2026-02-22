% Filename: 06-red-teaming/infrastructure/redirectors.md
% Display name: Redirectors
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1090.002 (Proxy: External Proxy)
% Authors: @TristanInSec

# Redirectors

## Overview

Redirectors sit between the target network and the team server, forwarding C2 traffic while hiding the real infrastructure. If a redirector is burned (detected and blocked), the team server remains safe — deploy a new redirector and continue the operation. Redirectors can also filter traffic, serving a decoy website to scanners and analysts while forwarding valid C2 traffic to the team server.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Technique:** T1090.002 - Proxy: External Proxy

## Techniques

### Apache mod_rewrite Redirector

Use Apache's mod_rewrite to inspect incoming requests and forward only valid C2 traffic:

```bash
# Install Apache on the redirector VPS
sudo apt install -y apache2
sudo a2enmod rewrite proxy proxy_http ssl

# /etc/apache2/sites-available/redirector.conf
# Redirect valid C2 requests to team server
# Serve decoy site for everything else
```

Example Apache configuration:

```apache
<VirtualHost *:443>
    ServerName <c2_domain>
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/<c2_domain>/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/<c2_domain>/privkey.pem

    # Redirect valid C2 URIs to team server
    RewriteEngine On

    # Match C2 URI patterns (adjust to match your C2 profile)
    RewriteCond %{REQUEST_URI} ^/api/update [OR]
    RewriteCond %{REQUEST_URI} ^/api/status
    RewriteRule ^(.*)$ https://<team_server_ip>:443$1 [P,L]

    # Block known scanner user agents
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scanner) [NC]
    RewriteRule .* - [F,L]

    # Everything else gets the decoy site
    DocumentRoot /var/www/html/decoy
</VirtualHost>
```

### socat Redirector (Simple)

Quick redirector for testing — no filtering:

```bash
# socat
# http://www.dest-unreach.org/socat/

# Forward HTTPS from redirector to team server
socat TCP-LISTEN:443,fork,reuseaddr TCP:<team_server_ip>:443
```

### iptables Redirector

Kernel-level forwarding — fast, transparent, no application overhead:

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Forward port 443 to team server
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination <team_server_ip>:443
iptables -t nat -A POSTROUTING -j MASQUERADE

# Allow only traffic from redirector to team server (on team server)
iptables -A INPUT -s <redirector_ip> -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP
```

### Nginx Redirector

```nginx
# /etc/nginx/sites-available/redirector
server {
    listen 443 ssl;
    server_name <c2_domain>;

    ssl_certificate /etc/letsencrypt/live/<c2_domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<c2_domain>/privkey.pem;

    # Valid C2 paths — proxy to team server
    location /api/ {
        proxy_pass https://<team_server_ip>:443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Everything else — decoy site
    location / {
        root /var/www/html/decoy;
        index index.html;
    }
}
```

### SSH Reverse Tunnel Redirector

If the redirector VPS doesn't need complex filtering:

```bash
# From the team server, create a reverse tunnel to the redirector
ssh -R 0.0.0.0:443:127.0.0.1:443 user@<redirector_ip> -N -f

# Traffic hitting redirector:443 tunnels to team server:443
# Requires GatewayPorts yes in redirector's sshd_config
```

### CDN as Redirector

Use a CDN (Cloudflare, AWS CloudFront) as an implicit redirector:

```text
1. Register domain and point DNS to Cloudflare
2. Set Cloudflare origin to team server IP
3. Enable "Full" SSL mode
4. C2 traffic routes through Cloudflare's IP space
5. Investigators see Cloudflare IPs, not the team server

Advantages:
  - Legitimate Cloudflare IPs (hard to block)
  - Free SSL termination
  - DDoS protection on the redirector

Disadvantages:
  - Cloudflare may inspect/block certain traffic patterns
  - Terms of service concerns
  - SSL decryption at the CDN edge
```

### Multiple Redirector Architecture

```text
                         ┌─ [HTTPS Redirector 1] ─┐
Target ──── Internet ────┤                         ├──── [Team Server]
                         ├─ [HTTPS Redirector 2] ─┤
                         └─ [DNS Redirector]     ──┘

- Use different redirectors for different phases
- If one gets burned, switch traffic to another
- DNS redirector for backup C2 channel
- Each redirector in a different cloud provider/region
```

## Detection Methods

### Network-Based Detection

- Certificate Transparency logs revealing redirector domains
- DNS records pointing to cloud VPS IPs
- HTTP response inconsistencies between the decoy site and C2 responses
- Repeated connections to the same cloud IP from internal hosts

### Host-Based Detection

- Firewall logs showing outbound HTTPS to uncategorized or newly registered domains
- Proxy logs with unusual URI patterns matching C2 profiles

## Mitigation Strategies

- **Domain reputation checking** — block traffic to newly registered or uncategorized domains
- **SSL inspection** — decrypt and inspect outbound HTTPS traffic
- **Cloud IP blocking** — restrict outbound connections to known-good cloud services
- **Threat intelligence feeds** — subscribe to feeds that track C2 infrastructure

## References

### MITRE ATT&CK

- [T1090.002 - Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002/)
