% Filename: 03-social-engineering/phishing/email-phishing.md
% Display name: Email Phishing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)
% Authors: @TristanInSec

# Email Phishing

## Overview

Email phishing sends crafted messages to targets to harvest credentials, deliver
payloads, or measure security awareness. In authorized assessments, phishing
campaigns provide metrics on click rates, credential submission rates, and
incident reporting response times.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1566.001 - Spearphishing Attachment
- **Technique:** T1566.002 - Spearphishing Link

## Prerequisites

- Written authorization explicitly covering phishing tests
- Agreed target list or targeting criteria
- Phishing infrastructure (domain, mail server, landing page)
- Data handling agreement for captured credentials

> **Rules of engagement:** Before launching any phishing campaign, confirm:
> (1) targets are within scope, (2) pretexts are pre-approved, (3) payloads
> are non-destructive, (4) a data handling plan exists for captured credentials,
> (5) the client has an emergency stop procedure if needed.

## Campaign Infrastructure

### Domain Setup

Register a domain that resembles the target organization. Common techniques:

- Typosquatting — transposed or substituted characters (e.g., examp1e.com)
- TLD variation — different top-level domain (e.g., example.net vs example.com)
- Subdomain abuse — legitimate-looking subdomain (e.g., login.example-corp.com)

Configure SPF, DKIM, and DMARC on the phishing domain to improve email
deliverability and avoid spam filters.

### GoPhish Setup

GoPhish is an open-source phishing framework for managing campaigns, tracking
results, and hosting landing pages.

```bash
# GoPhish
# https://github.com/gophish/gophish

# Start GoPhish service
sudo systemctl start gophish

# Admin interface: https://127.0.0.1:3333
# Default credentials: admin / kali-gophish
# Phish server (landing pages): http://0.0.0.0:80
```

GoPhish configuration at `/etc/gophish/config.json`:

```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "/var/lib/gophish/gophish_admin.crt",
    "key_path": "/var/lib/gophish/gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:80",
    "use_tls": false
  },
  "db_name": "sqlite3",
  "db_path": "/var/lib/gophish/gophish.db"
}
```

GoPhish campaign workflow (via web UI):

1. **Sending Profiles** — configure SMTP server for outbound email
2. **Landing Pages** — import or clone target login pages
3. **Email Templates** — craft phishing emails with tracking (use `{{.URL}}` for tracked links)
4. **Users & Groups** — import target email addresses
5. **Campaigns** — combine all components and launch

GoPhish tracks: emails sent, emails opened (tracking pixel), links clicked,
and credentials submitted. Results are available in the dashboard and exportable
as CSV.

### SET Credential Harvester

The Social-Engineer Toolkit includes a credential harvester that clones
websites and captures submitted credentials.

```bash
# Social-Engineer Toolkit (SET)
# https://github.com/trustedsec/social-engineer-toolkit
# Requires root

sudo setoolkit

# Navigate menus:
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner
# Enter the IP to host on (your attack machine IP)
# Enter the URL to clone (e.g., https://login.target.com)
```

SET clones the target page and serves it locally. When a victim submits
credentials, SET captures and displays them in the terminal. The original site
loads after submission so the victim experiences a normal login flow.

SET main attack categories:

| Menu Option | Description |
|---|---|
| Spear-Phishing Attack Vectors | Mass email with malicious attachments |
| Website Attack Vectors | Credential harvester, tabnabbing, web cloning |
| Infectious Media Generator | Autorun payloads for USB/CD |
| Mass Mailer Attack | Bulk email sending |
| QRCode Generator Attack Vector | Malicious QR codes |
| Powershell Attack Vectors | PowerShell-based payloads |

## Email Crafting

### Test Email with swaks

swaks (Swiss Army Knife SMTP) sends test emails for verifying deliverability
and testing mail server configurations.

```bash
# swaks
# https://www.jetmore.org/john/code/swaks/

# Send a basic test email
swaks --to target@example.com --from it-support@example-corp.com \
  --server mail.example-corp.com \
  --header "Subject: Password Expiry Notice" \
  --body "Your password expires in 24 hours. Click here to reset."

# Send with authentication
swaks --to target@example.com --from it-support@example-corp.com \
  --server mail.example-corp.com \
  --auth LOGIN --auth-user phish@example-corp.com \
  --auth-password 'password' \
  --header "Subject: Action Required"

# Send with HTML body from file
swaks --to target@example.com --from it-support@example-corp.com \
  --server mail.example-corp.com \
  --header "Subject: Security Alert" \
  --attach-type text/html --attach-body @/path/to/email-body.html

# Send with attachment
swaks --to target@example.com --from it-support@example-corp.com \
  --server mail.example-corp.com \
  --header "Subject: Q4 Report" \
  --attach @/path/to/document.pdf
```

### Email Header Analysis

Before sending, verify your phishing domain passes email security checks:

```bash
# Check SPF record
dig TXT example-corp.com +short

# Check DMARC record
dig TXT _dmarc.example-corp.com +short

# Check DKIM record (selector varies)
dig TXT default._domainkey.example-corp.com +short
```

## Email Security Bypass Indicators

During authorized testing, note which security controls the phishing email
must pass:

| Control | What It Checks | Impact on Phishing |
|---|---|---|
| SPF | Sender IP authorized for domain | Fails without proper DNS setup |
| DKIM | Email signature integrity | Fails without signing key |
| DMARC | SPF/DKIM alignment policy | May quarantine or reject |
| Spam filters | Content analysis, reputation | May block suspicious patterns |
| Link scanning | URL reputation and sandbox detonation | May flag unknown domains |
| Attachment scanning | File analysis, macro detection | May block payload attachments |

## Campaign Metrics

Track these metrics for the assessment report:

- **Delivery rate** — emails that reached inboxes (not bounced/filtered)
- **Open rate** — emails opened (tracking pixel loaded)
- **Click rate** — targets who clicked the phishing link
- **Submission rate** — targets who entered credentials
- **Report rate** — targets who reported the email to IT/security
- **Time to first click** — how quickly the first target engaged
- **Time to first report** — how quickly the first report reached security team

Report rate is the most valuable defensive metric — it measures whether
security awareness training translates into actual incident reporting behavior.

## Detection Methods

- Email gateway analysis of sender reputation, SPF/DKIM/DMARC alignment
- URL sandboxing and reputation checking on embedded links
- User-reported phishing through report buttons (e.g., Outlook phish report add-in)
- Network monitoring for connections to recently registered domains

## Mitigation Strategies

- Implement SPF, DKIM, and DMARC with enforcement policies (p=quarantine or p=reject)
- Deploy email gateway with link rewriting and sandboxing
- Conduct regular phishing simulations to maintain awareness
- Provide a one-click phishing report button in email clients
- Measure and reward reporting behavior, not just click avoidance

## References

### Tools

- [GoPhish — Open-Source Phishing Toolkit](https://github.com/gophish/gophish)
- [SET — Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
- [swaks — Swiss Army Knife SMTP](https://www.jetmore.org/john/code/swaks/)

### MITRE ATT&CK

- [T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1204.001 — User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
