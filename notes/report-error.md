% Filename: report-error.md
% Display name: Report an Error
% Last update: 2026-02-22
% Authors: @TristanInSec

# Report an Error

HackWiki prioritizes accuracy above all else. If you spot an error — a wrong
flag, an outdated command, or a broken link — please report it before it
misleads someone in a real engagement.

## What Counts as an Error

- **Wrong or outdated command** — a flag that doesn't exist, was renamed, or
  behaves differently than described
- **Incorrect tool behavior** — a technique that no longer works as documented
- **Broken or wrong URL** — an external link that 404s or points to the wrong page
- **Inaccurate CVE details** — wrong CVSS score, affected versions, or
  exploitation method
- **Outdated technique** — a method patched or deprecated in a recent update
- **Missing attribution** — a command block without its tool credit and URL

## How to Report

Open an issue on the GitHub repository:

**[github.com/hack-wiki/hackwiki-notes/issues](https://github.com/hack-wiki/hackwiki-notes/issues)**

Use the **Bug / Error report** issue template if available, otherwise open a
blank issue.

### What to Include

1. **Page** — the section and file path where the error appears (e.g.,
   `02-reconnaissance/enum-network/nmap.md`)
2. **The error** — quote the exact line or command that is wrong
3. **Why it's wrong** — what the correct behavior is, or what you observed
   instead (tool version, OS, error message)
4. **Source** — a reference if you have one (man page, official docs, GitHub
   commit, tool `--help` output)

### Example Issue

```
Page: 02-reconnaissance/enum-network/nmap.md

Error: nmap --script-updatedb is listed as running automatically during a scan.

Correct: --script-updatedb is a standalone command, requires root, and must be
run separately: sudo nmap --script-updatedb

Source: nmap man page, nmap 7.94
```

## What Happens Next

1. A maintainer reviews and verifies the report against the source
2. If confirmed, the fix is committed to the `beta` branch
3. Once reviewed, it is merged into `main` and logged in the changelog

Reports with a verifiable source are prioritized. Anonymous reports without
a reference are still welcome — they will be verified before any change lands.

## Prefer Not to Use GitHub?

You can also reach us through the [contact page](contact.html). Select
**Bug/Error Report** as the topic and include the same details listed above.
This is useful if you don't have a GitHub account or simply prefer a quick
message.
