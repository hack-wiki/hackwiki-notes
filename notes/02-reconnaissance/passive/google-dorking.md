% Filename: 02-reconnaissance/passive/google-dorking.md
% Display name: Google Dorking
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1593.002 (Search Open Websites/Domains: Search Engines)
% Authors: @TristanInSec

# Google Dorking

## Overview

Google dorking uses advanced search operators to find content that is indexed by Google but not intended to be publicly accessible — exposed admin panels, configuration files, login portals, directory listings, database dumps, and error messages. None of this involves interacting with the target directly. Google already crawled and indexed the content; dorking simply queries Google's index.

This is one of the highest-value passive recon techniques. A few well-crafted queries can reveal more about a target's attack surface than hours of active scanning.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1593.002 - Search Open Websites/Domains: Search Engines

## Prerequisites

- Web browser
- Google account (for consistent result quality, not required)
- Understanding of target scope (authorized domains only)

## Core Operators

Google recognizes specific operators that filter search results. These can be combined to create precise queries.

### Site Restriction

```text
site:example.com
```

Limits results to a specific domain. Combine with other operators to search within a target's indexed content only.

```text
site:example.com filetype:pdf
site:*.example.com -www
```

The second query finds subdomains indexed by Google while excluding the main `www` subdomain — useful for discovering forgotten or staging subdomains.

### File Type

```text
filetype:pdf
filetype:xlsx
filetype:docx
filetype:sql
filetype:log
filetype:env
filetype:config
filetype:xml
filetype:bak
```

Searches for specific file extensions indexed by Google. Particularly valuable for finding database backups (`.sql`, `.bak`), environment files (`.env`), and configuration files (`.config`, `.xml`).

### Inurl and Intitle

```text
inurl:admin
inurl:login
inurl:dashboard
inurl:wp-admin
inurl:phpmyadmin
intitle:"Index of /"
intitle:"Dashboard" site:example.com
```

`inurl:` matches keywords in the URL path. `intitle:` matches keywords in the page title. Both are effective for finding admin interfaces and directory listings.

### Intext

```text
intext:"sql syntax" site:example.com
intext:"error in your SQL" site:example.com
intext:"Warning: mysql_" site:example.com
intext:"Fatal error" site:example.com
```

`intext:` matches keywords in the page body. SQL errors and stack traces indexed by Google expose backend technology, database structure, and file paths.

### Exclusion

```text
site:example.com -inurl:blog -inurl:news
```

The `-` operator excludes results matching a term. Useful for filtering out noise (blogs, press releases) to focus on infrastructure.

## Reconnaissance Dork Patterns

### Exposed Admin Panels

```text
site:example.com inurl:admin
site:example.com inurl:login
site:example.com inurl:wp-login.php
site:example.com intitle:"admin" inurl:admin
site:example.com inurl:cpanel
site:example.com inurl:webmail
```

### Directory Listings

```text
site:example.com intitle:"Index of /"
site:example.com intitle:"Index of" "parent directory"
site:example.com intitle:"Index of" ".git"
site:example.com intitle:"Index of" "backup"
site:example.com intitle:"Index of" "wp-content"
```

Open directory listings are one of the most common findings in web recon. They expose file structures, backup archives, configuration files, and sometimes source code.

### Sensitive Files

```text
site:example.com filetype:env
site:example.com filetype:sql
site:example.com filetype:bak
site:example.com filetype:log
site:example.com filetype:conf
site:example.com filetype:cfg
site:example.com "DB_PASSWORD" filetype:env
site:example.com ext:xml inurl:sitemap
```

Environment files (`.env`) frequently contain database credentials, API keys, and secret tokens. SQL dumps may include full database schemas and data.

### Error Messages and Debug Pages

```text
site:example.com "Warning:" "on line"
site:example.com "Parse error:" "on line"
site:example.com "Fatal error:" filetype:php
site:example.com "stack trace" OR "traceback"
site:example.com "Debug Mode" OR "debug=true"
site:example.com inurl:phpinfo
```

Exposed `phpinfo()` pages reveal PHP version, loaded modules, server paths, and environment variables — significant for targeting exploits.

### Credential Exposure

```text
site:example.com "password" filetype:log
site:example.com "password" filetype:txt
site:example.com "api_key" OR "apikey" OR "api-key"
site:example.com "BEGIN RSA PRIVATE KEY"
site:example.com "jdbc:mysql://"
```

### Exposed Documents with Metadata

```text
site:example.com filetype:pdf
site:example.com filetype:docx
site:example.com filetype:xlsx
site:example.com filetype:pptx
```

Public documents often contain author names, internal paths, software versions, and printer names in their metadata. Download and analyze with metadata extraction tools.

### Subdomains via Google

```text
site:*.example.com -www
site:*.example.com -www -mail -blog
```

Google indexes subdomains that DNS enumeration tools might miss, particularly those with web content but no DNS brute-force wordlist match.

### Cloud Storage Exposure

```text
site:s3.amazonaws.com "example"
site:blob.core.windows.net "example"
site:storage.googleapis.com "example"
inurl:".s3.amazonaws.com" "example"
```

Misconfigured cloud storage buckets often allow public listing or file access. These dorks identify indexed buckets associated with the target.

## Google Dorking Databases

Pre-built dork collections save time and cover patterns you might not think of.

- **Google Hacking Database (GHDB)** — maintained by Exploit-DB, categorized by type (files, directories, error messages, credentials). Access at `exploit-db.com/google-hacking-database`.
- **DorkSearch.com** — searchable dork catalog with Google-style query builder.

## Automation

### Manual Workflow

For targeted engagements, manually crafting dorks produces better results than automated spraying. Work through these categories in order:

1. Subdomains: `site:*.example.com -www`
2. File types: cycle through `pdf`, `doc`, `xls`, `sql`, `env`, `log`, `bak`
3. Admin panels: `inurl:admin`, `inurl:login`, `inurl:dashboard`
4. Directory listings: `intitle:"Index of"`
5. Error messages: `intext:"Warning:"`, `intext:"Fatal error:"`
6. Cloud storage: `site:s3.amazonaws.com "example"`

### Scripted Dorking

```bash
# Simple dorking script using Google Custom Search API
# (standard Google search blocks automated queries)
# Requires Google Custom Search Engine ID and API key

DOMAIN="example.com"
DORKS=(
  "site:${DOMAIN} filetype:env"
  "site:${DOMAIN} filetype:sql"
  "site:${DOMAIN} filetype:log"
  "site:${DOMAIN} intitle:\"Index of\""
  "site:${DOMAIN} inurl:admin"
  "site:${DOMAIN} inurl:login"
)

for dork in "${DORKS[@]}"; do
  echo "[*] Dorking: ${dork}"
  curl -s "https://www.googleapis.com/customsearch/v1?key=<API_KEY>&cx=<CSE_ID>&q=$(echo $dork | sed 's/ /+/g')" \
    | python3 -c "import sys,json; [print(i['link']) for i in json.load(sys.stdin).get('items',[])]"
  sleep 2
done
```

The Google Custom Search API allows 100 queries/day on the free tier. For larger engagements, use SerpAPI or similar services.

## Operational Notes

- **Rate limiting:** Google will temporarily block queries if you send too many too fast. Use pauses between queries and avoid running hundreds of dorks in rapid succession from one IP.
- **Regional results:** Google results vary by location. Use `&gl=us` parameter or a VPN to control which regional index you query.
- **Archived pages:** Google removed the "Cached" link from search results in early 2024. To view historical versions of a page, use the Wayback Machine (`web.archive.org`).
- **Other search engines:** Bing (`site:example.com`), DuckDuckGo, and Yandex support similar operators and may index pages Google does not.
- **Legal scope:** Only dork against domains you are authorized to test. Viewing indexed content is legal; exploiting findings requires authorization.

## References

### OSINT Resources

- [Google Hacking Database — Exploit-DB](https://www.exploit-db.com/google-hacking-database)
- [Google Search Operators — Google Search Help](https://support.google.com/websearch/answer/2466433)
- [DorkSearch — Google Dorking Tool](https://dorksearch.com/)

### MITRE ATT&CK

- [T1593.002 - Search Open Websites/Domains: Search Engines](https://attack.mitre.org/techniques/T1593/002/)
