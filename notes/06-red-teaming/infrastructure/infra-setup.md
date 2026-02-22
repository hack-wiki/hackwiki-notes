% Filename: 06-red-teaming/infrastructure/infra-setup.md
% Display name: Infrastructure Setup
% Last update: 2026-02-11
% ATT&CK Tactics: TA0042 (Resource Development)
% ATT&CK Techniques: T1583 (Acquire Infrastructure), T1587.001 (Develop Capabilities: Malware)
% Authors: @TristanInSec

# Infrastructure Setup

## Overview

Red team infrastructure consists of team servers (C2), redirectors, phishing servers, payload hosting, and supporting services. The architecture should separate concerns — compromising one component should not expose the others. All infrastructure should be disposable, documented, and automatable.

## ATT&CK Mapping

- **Tactic:** TA0042 - Resource Development
- **Techniques:**
  - T1583 - Acquire Infrastructure
  - T1587.001 - Develop Capabilities: Malware

## Techniques

### Architecture Overview

```text
Target Network
      |
  [Internet]
      |
  [Redirector]  ←  Cloud VPS (DigitalOcean, Linode, AWS)
      |                Filters traffic, forwards valid C2 to team server
      |                Decoy website for non-C2 requests
      |
  [Team Server]  ←  Private VPS or on-prem (never exposed directly)
      |                Runs C2 framework (Sliver, Cobalt Strike, etc.)
      |
  [Red Team Operators]  ←  Connect to team server via VPN/SSH
```

### Domain Acquisition

```text
Domain selection:
  - Match the target's industry or IT vendors
  - Examples: "cloud-update-service.com", "ms365-auth.net"
  - Avoid obvious red team domains ("evil-hacker-c2.xyz")
  - Check domain reputation before buying (VirusTotal, urlscan.io)

Domain aging:
  - Register domains 2-4 weeks before the engagement
  - Set up a benign website (WordPress, static page) to build reputation
  - Categorize with web proxies (Bluecoat Site Review, McAfee TrustedSource)
  - Target categories: "Technology", "Business", "Cloud Services"

Providers:
  - Namecheap, GoDaddy, Cloudflare Registrar, Porkbun
  - Use privacy protection (WHOIS guard)
  - Pay with methods that don't link to the red team
```

### SSL/TLS Certificates

```bash
# Let's Encrypt — free, automated certificates
# Certbot
# https://github.com/certbot/certbot
sudo apt install -y certbot
sudo certbot certonly --standalone -d <domain>

# Certificates stored at:
# /etc/letsencrypt/live/<domain>/fullchain.pem
# /etc/letsencrypt/live/<domain>/privkey.pem
```

### Cloud VPS Deployment

```bash
# Example: DigitalOcean droplet for redirector
# Use cloud provider CLI or Terraform

# Minimal redirector setup (Ubuntu)
apt update && apt install -y apache2 certbot

# Minimal team server setup
apt update && apt install -y tmux wireguard

# Lock down the team server
# Only allow SSH from operator IPs and redirector
ufw default deny incoming
ufw allow from <operator_ip> to any port 22
ufw allow from <redirector_ip> to any port 443
ufw enable
```

### VPN Between Team Server and Operators

```bash
# WireGuard VPN for operator access to team server
# WireGuard
# https://www.wireguard.com/

# On team server — generate keys
wg genkey | tee server_private.key | wg pubkey > server_public.key

# On team server — /etc/wireguard/wg0.conf
# [Interface]
# PrivateKey = <server_private_key>
# Address = 10.100.0.1/24
# ListenPort = 51820
#
# [Peer]
# PublicKey = <operator_public_key>
# AllowedIPs = 10.100.0.2/32

# Start WireGuard
sudo wg-quick up wg0
```

### Infrastructure Automation

Automate infrastructure deployment for repeatability:

```bash
# Terraform example structure
# infrastructure/
# ├── main.tf         # Provider config
# ├── redirector.tf   # Redirector VPS
# ├── teamserver.tf   # Team server VPS
# ├── dns.tf          # DNS records
# └── variables.tf    # Engagement-specific variables

# Deploy
terraform init
terraform plan
terraform apply

# Tear down after engagement
terraform destroy
```

### Infrastructure Logging

```text
Log everything for the report:
  - All domains purchased (registrar, date, categorization status)
  - All IPs provisioned (provider, region, firewall rules)
  - All certificates issued (domain, method, expiry)
  - C2 profile used (hash of the profile file)
  - SSH keys used for access
  - Deployment timestamps

This becomes part of the IOC appendix in the final report.
```

### Teardown

After the engagement:

```text
1. Export all C2 logs and session data
2. Destroy cloud VPS instances (terraform destroy)
3. Revoke SSL certificates if needed
4. Do NOT release domains immediately (hold for 30-90 days
   to prevent adversary registration)
5. Securely delete all engagement data per client agreement
6. Provide full IOC list to the client for retroactive hunting
```

## Detection Methods

### How Blue Teams Detect Infrastructure

- New domain registrations matching organizational keywords (brand monitoring)
- Certificate Transparency log monitoring for suspicious domain names
- Domain reputation scoring (newly registered, uncategorized domains)
- IP reputation lookups against known cloud VPS ranges

## Mitigation Strategies

- **Certificate Transparency monitoring** — alert on certs issued for similar domains
- **Brand monitoring** — detect lookalike domain registrations
- **DNS sinkholing** — redirect known-bad domains to controlled servers
- **Cloud IP blocking** — block traffic from known VPS providers to sensitive systems (aggressive)

## References

### MITRE ATT&CK

- [T1583 - Acquire Infrastructure](https://attack.mitre.org/techniques/T1583/)
- [T1587.001 - Develop Capabilities: Malware](https://attack.mitre.org/techniques/T1587/001/)
