% Filename: 03-social-engineering/phishing/spear-phishing.md
% Display name: Spear Phishing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0043 (Reconnaissance)
% ATT&CK Techniques: T1566.002 (Spearphishing Link), T1598.003 (Phishing for Information: Spearphishing Link)
% Authors: @TristanInSec

# Spear Phishing

## Overview

Spear phishing targets specific individuals or roles with tailored messages
based on prior reconnaissance. Unlike bulk phishing, spear phishing invests
time in research to craft pretexts that are relevant and believable to the
specific target — referencing their projects, colleagues, or business
processes.

In authorized testing, spear phishing assesses whether high-value targets
(executives, finance, IT admins) can be compromised despite heightened
security awareness.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1598.003 - Phishing for Information: Spearphishing Link
- **Tactic:** TA0001 - Initial Access
- **Technique:** T1566.002 - Spearphishing Link

## Prerequisites

- Written authorization explicitly naming high-value target roles or individuals
- Pre-approved pretexts (spear phishing pretexts should be reviewed by the client to avoid sensitive topics)
- OSINT already gathered on the target organization
- Phishing infrastructure with look-alike domain

> **Rules of engagement:** Spear phishing targets specific people by name.
> Confirm each individual is in scope. Some organizations exclude C-suite,
> HR, or employees on leave. Pretexts must be pre-approved — never improvise
> pretexts involving personal information, health, or family matters.

## Target Reconnaissance

### OSINT Gathering with theHarvester

theHarvester collects email addresses, names, and subdomains from public
sources. This information helps identify targets and craft realistic pretexts.

```bash
# theHarvester
# https://github.com/laramies/theHarvester

# Search multiple sources for target domain
theHarvester -d example.com -b all -l 200

# Search specific sources
theHarvester -d example.com -b crtsh,dnsdumpster,duckduckgo -l 100

# Save results to file
theHarvester -d example.com -b all -l 200 -f harvest_results
```

Key flags:
- `-d` — target domain
- `-b` — data source (crtsh, dnsdumpster, duckduckgo, yahoo, certspotter, or `all`)
- `-l` — limit number of results
- `-f` — output filename (creates XML and JSON files)
- `-s` — use Shodan for additional data

### SMTP User Enumeration

Verify email addresses are valid before sending phishing emails:

```bash
# smtp-user-enum
# https://github.com/pentestmonkey/smtp-user-enum

# Verify usernames via VRFY method
smtp-user-enum -M VRFY -U users.txt -t mail.example.com

# Verify via RCPT TO method (more commonly allowed)
smtp-user-enum -M RCPT -U users.txt -t mail.example.com

# Verify single user
smtp-user-enum -M VRFY -u admin -t mail.example.com
```

Methods: VRFY (ask server to verify), RCPT (attempt delivery to address),
EXPN (expand mailing list). RCPT is the most reliable — VRFY is often
disabled on production mail servers.

### Manual OSINT Sources

Gather information for pretext development from:

- **LinkedIn** — job titles, reporting structure, technology stack, recent hires
- **Company website** — executive bios, press releases, org charts
- **Job postings** — technologies used, team structure, upcoming projects
- **SEC filings / annual reports** — for publicly traded companies
- **Conference presentations** — speaker bios, project details
- **GitHub / GitLab** — developer names, email addresses in commit history
- **Google Dorks** — `site:example.com filetype:pdf` for internal documents

## Pretext Development

Effective spear phishing pretexts reference real organizational context:

| Pretext Category | Example Scenario |
|---|---|
| IT/Security | "Your VPN certificate expires Friday — renew here" |
| HR/Benefits | "Open enrollment changes require your review" |
| Finance | "Updated wire transfer instructions from vendor" |
| Executive | "Document requires your signature before EOD" |
| Vendor | "Your support ticket #4821 has been updated" |

Pretext quality indicators:
- References real internal systems or processes
- Creates urgency without being threatening
- Comes from a plausible sender (internal or known vendor)
- Requests an action the target would normally perform

## Credential Harvesting with evilginx2

> **Authorization note:** evilginx2 performs real-time credential interception
> including MFA tokens. Use only with explicit authorization that covers MFA
> bypass testing. Captured session tokens grant full account access — handle
> with extreme care per the data handling agreement.

evilginx2 is a man-in-the-middle framework that proxies the real login page,
capturing credentials and session cookies in real time. Unlike static cloned
pages, evilginx2 defeats MFA by relaying the authentication session.

```bash
# evilginx2
# https://github.com/kgretzky/evilginx2

# Start evilginx2 (requires root for port 443)
sudo evilginx2 -p /usr/share/evilginx2/phishlets

# Developer mode (self-signed certs, for lab testing)
sudo evilginx2 -developer -p /usr/share/evilginx2/phishlets
```

Key flags:
- `-p` — phishlets directory path
- `-c` — configuration directory path
- `-t` — HTML redirector pages directory path
- `-developer` — self-signed certificates (lab use only)
- `-debug` — enable debug output

evilginx2 uses "phishlets" — YAML configuration files that define how to
proxy a specific web application. Phishlets specify the target domain,
subdomains to proxy, authentication cookie names, and credential field
selectors.

evilginx2 interactive commands (once running):

```bash
# Configure the phishing domain
config domain example-phish.com
config ipv4 external <your-server-ip>

# Enable a phishlet
phishlets hostname <phishlet-name> example-phish.com
phishlets enable <phishlet-name>

# Create a phishing URL (lure)
lures create <phishlet-name>
lures get-url <lure-id>

# View captured sessions
sessions
sessions <session-id>
```

When a target visits the lure URL, evilginx2 proxies the real login page.
The target sees a legitimate-looking page, enters credentials, completes MFA,
and evilginx2 captures both the credentials and the authenticated session
cookie.

## Payload Delivery

For authorized tests that include payload execution (beyond credential
harvesting):

- **Document payloads** — macro-enabled Office documents (requires user to enable macros)
- **HTML attachments** — HTML files with embedded JavaScript that redirect to phishing pages
- **Link-only** — URL to credential harvesting page (lowest suspicion, easiest to click)

> **Payload restrictions:** In most authorized assessments, payloads should be
> non-destructive and non-persistent. Use callback beacons or benign markers
> to prove execution without installing actual malware. Confirm payload
> restrictions in the rules of engagement.

## Detection Methods

- Sender reputation analysis and email authentication (SPF/DKIM/DMARC)
- URL analysis for look-alike domains and recently registered domains
- Behavioral analysis for unusual email patterns to specific individuals
- Endpoint detection for credential submission to untrusted domains
- User reporting of suspicious targeted communications

## Mitigation Strategies

- Deploy anti-phishing solutions with real-time URL analysis
- Enforce MFA that is resistant to real-time proxy attacks (FIDO2/WebAuthn hardware keys)
- Implement conditional access policies (geo-fencing, device compliance)
- Train high-value targets on spear phishing indicators
- Monitor for look-alike domain registrations targeting the organization

## References

### Tools

- [theHarvester](https://github.com/laramies/theHarvester)
- [smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)
- [evilginx2](https://github.com/kgretzky/evilginx2)

### MITRE ATT&CK

- [T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1598.003 — Phishing for Information: Spearphishing Link](https://attack.mitre.org/techniques/T1598/003/)
- [T1598 — Phishing for Information](https://attack.mitre.org/techniques/T1598/)
