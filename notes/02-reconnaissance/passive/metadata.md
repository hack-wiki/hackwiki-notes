% Filename: 02-reconnaissance/passive/metadata.md
% Display name: Metadata Extraction
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1592.004 (Gather Victim Host Information: Client Configurations)
% Authors: @TristanInSec

# Metadata Extraction

## Overview

Every document, image, and file created by modern software embeds metadata — author names, software versions, creation dates, GPS coordinates, internal file paths, printer names, email addresses, and operating system details. When organizations publish documents on their websites (PDFs, DOCX, XLSX, PPTX, images), this metadata becomes publicly accessible.

Metadata extraction is passive reconnaissance at its most subtle. The target published the files voluntarily; extracting embedded data requires no interaction with target systems beyond downloading publicly available documents.

Metadata has exposed internal Active Directory usernames from PDF author fields, revealed internal network paths from document properties (`\\fileserver\shared\hr\`), identified software versions for exploit targeting (Microsoft Office 2016, Adobe Acrobat 11.0), and leaked GPS coordinates from photos posted by employees.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1592.004 - Gather Victim Host Information: Client Configurations

## Prerequisites

- Internet access for downloading public documents
- ExifTool installed (`sudo apt install libimage-exiftool-perl` on Kali)
- FOCA or metagoofil for automated collection (optional)
- `python3` for scripting

## Finding Documents

Before extracting metadata, locate publicly available documents on the target's domain.

```bash
# Google dorking for documents
# site:example.com filetype:pdf
# site:example.com filetype:docx
# site:example.com filetype:xlsx
# site:example.com filetype:pptx
# site:example.com filetype:jpg
```

```bash
# metagoofil (available in Kali: sudo apt install metagoofil)
# https://github.com/opsdisk/metagoofil
# On non-Kali: git clone https://github.com/opsdisk/metagoofil.git && cd metagoofil && pip install -r requirements.txt --break-system-packages
metagoofil -d example.com -t pdf,docx,xlsx,pptx -l 100 -o ./harvested/
```

The `-t` flag specifies file types, `-l` limits search results, and `-o` sets the output directory. The opsdisk fork of metagoofil searches Google and downloads documents only — it does not extract metadata. Use ExifTool separately on the downloaded files for metadata analysis.

```bash
# Manual download with wget
wget -r -l 1 -A "*.pdf,*.docx,*.xlsx,*.pptx" --no-parent https://example.com/documents/
```

## ExifTool

ExifTool is the standard tool for reading metadata from virtually any file format. It supports hundreds of file types and extracts all embedded metadata fields.

```bash
# ExifTool
# https://exiftool.org/
# Read all metadata from a single file
exiftool document.pdf
```

Example output:
```text
ExifTool Version Number         : 12.76
File Name                       : document.pdf
File Size                       : 2.4 MB
File Type                       : PDF
MIME Type                        : application/pdf
PDF Version                     : 1.7
Creator                         : John.Smith
Author                          : John Smith
Create Date                     : 2024:03:15 09:23:45+01:00
Modify Date                     : 2024:03:15 09:30:12+01:00
Producer                        : Microsoft® Word 2019
Creator Tool                    : Microsoft® Word 2019
```

Key fields: `Creator`, `Author`, `Producer`, `Creator Tool`, `Create Date`, `Modify Date`.

```bash
# ExifTool
# https://exiftool.org/
# Extract metadata from all files in a directory
exiftool -r ./harvested/

# Extract specific fields only
exiftool -Author -Creator -Producer -CreateDate -ModifyDate ./harvested/*.pdf

# CSV output for analysis
exiftool -csv -Author -Creator -Producer -Software -CreateDate ./harvested/ > metadata.csv
```

### Extracting Usernames

Author and creator fields often contain Active Directory usernames, full names, or email addresses.

```bash
# ExifTool
# https://exiftool.org/
# Extract unique author/creator names from all PDFs
exiftool -Author -Creator ./harvested/*.pdf 2>/dev/null | \
  grep -oP ':\s+\K.+' | sort -u > authors.txt
```

Common patterns in author fields:
- `jsmith` — AD username
- `John Smith` — full name (generate AD username candidates)
- `john.smith@example.com` — email address
- `DOMAIN\jsmith` — domain-qualified username
- `Administrator` — default/generic account

### Extracting Software Versions

```bash
# ExifTool
# https://exiftool.org/
# Extract software information
exiftool -Producer -CreatorTool -Software ./harvested/*.pdf 2>/dev/null | \
  grep -oP ':\s+\K.+' | sort -u > software.txt
```

Common findings: `Microsoft® Word 2019`, `Adobe Acrobat 11.0.23`, `LibreOffice 7.4`, `wkhtmltopdf 0.12.6`. Specific versions enable targeted exploit research.

### Extracting Internal Paths

Some document formats embed file paths in metadata or internal XML structures.

```bash
# Search for internal paths in Office documents (OOXML format)
# DOCX, XLSX, PPTX are ZIP archives containing XML files
unzip -p document.docx word/document.xml | grep -oP '\\\\[^"<]+' | sort -u
```

```bash
# ExifTool
# https://exiftool.org/
# Search PDF metadata for file paths
exiftool -all document.pdf | grep -iE '\\\\|/home/|/Users/|C:\\|file://'
```

Internal paths reveal: file server names (`\\FS01\shared\`), directory structures, operating systems (Windows paths vs Unix paths), and username directories (`C:\Users\jsmith\Documents\`).

## Image Metadata (EXIF)

Images taken with phones and cameras embed EXIF data including GPS coordinates, device model, timestamps, and camera settings.

```bash
# ExifTool
# https://exiftool.org/
# Extract GPS coordinates from images
exiftool -GPSLatitude -GPSLongitude -GPSPosition *.jpg

# Extract all EXIF data
exiftool -EXIF:all photo.jpg

# Extract device information
exiftool -Make -Model -Software photo.jpg
```

GPS coordinates from employee photos (corporate events, facility tours, social media) can reveal office locations, data center locations, and employee home addresses (if personal photos are found).

```bash
# ExifTool
# https://exiftool.org/
# Convert GPS coordinates to decimal format for mapping
exiftool -n -GPSLatitude -GPSLongitude photo.jpg
```

The `-n` flag outputs numeric values instead of degrees/minutes/seconds, directly usable in mapping applications.

### Bulk EXIF Processing

```bash
# ExifTool
# https://exiftool.org/
# Extract GPS data from all images and output as CSV
exiftool -csv -GPSLatitude -GPSLongitude -GPSDateTime -Make -Model -r ./images/ > exif_data.csv

# Find all images with GPS data
exiftool -if '$GPSLatitude' -GPSLatitude -GPSLongitude -FileName -r ./images/
```

## Office Document Deep Analysis

Microsoft Office files (DOCX, XLSX, PPTX) are ZIP archives containing XML files. Metadata lives in multiple locations within the archive.

```bash
# Extract core properties
unzip -p document.docx docProps/core.xml | python3 -c "
import sys
from xml.etree import ElementTree as ET
tree = ET.parse(sys.stdin)
ns = {
    'dc': 'http://purl.org/dc/elements/1.1/',
    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'dcterms': 'http://purl.org/dc/terms/'
}
for tag in ['dc:creator', 'cp:lastModifiedBy', 'dc:title', 'dc:subject']:
    prefix, name = tag.split(':')
    elem = tree.find(tag, ns)
    if elem is not None and elem.text:
        print(f'{name}: {elem.text}')
"
```

```bash
# Extract app properties (software version, company name)
unzip -p document.docx docProps/app.xml | python3 -c "
import sys
from xml.etree import ElementTree as ET
tree = ET.parse(sys.stdin)
ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
for field in ['Application', 'AppVersion', 'Company', 'Template']:
    elem = tree.find(f'ep:{field}', ns)
    if elem is not None and elem.text:
        print(f'{field}: {elem.text}')
"
```

The `Company` field in app.xml often contains the organization's internal name as configured in their Office deployment — sometimes different from the public-facing name.

### Revision History and Comments

```bash
# Check for embedded comments
unzip -p document.docx word/comments.xml 2>/dev/null | python3 -m xml.dom.minidom

# List all XML files in the archive for analysis
unzip -l document.docx | grep xml
```

Comments and revision marks sometimes contain internal discussions, reviewer names, and content that was removed from the final version but persists in the file.

## PDF Deep Analysis

```bash
# Poppler (pdfinfo)
# https://poppler.freedesktop.org/
# Extract PDF metadata with pdfinfo
pdfinfo document.pdf

# Extract embedded files and streams
# Poppler utilities
pdfdetach -list document.pdf
pdfdetach -saveall document.pdf

# Extract text (may contain internal references)
pdftotext document.pdf - | grep -iE '\\\\|internal|confidential|draft'
```

## Automation Script

```bash
#!/bin/bash
# Custom script created for this guide
# Metadata extraction workflow for pentest engagements

TARGET_DIR="$1"
OUTPUT_DIR="$2"

if [ -z "$TARGET_DIR" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <documents_dir> <output_dir>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Extracting authors and creators..."
exiftool -Author -Creator -r "$TARGET_DIR" 2>/dev/null | \
  grep -oP ':\s+\K.+' | sort -u > "$OUTPUT_DIR/authors.txt"

echo "[+] Extracting software versions..."
exiftool -Producer -CreatorTool -Software -r "$TARGET_DIR" 2>/dev/null | \
  grep -oP ':\s+\K.+' | sort -u > "$OUTPUT_DIR/software.txt"

echo "[+] Extracting GPS coordinates..."
exiftool -if '$GPSLatitude' -csv -GPSLatitude -GPSLongitude -FileName -r "$TARGET_DIR" 2>/dev/null \
  > "$OUTPUT_DIR/gps_data.csv"

echo "[+] Full metadata dump..."
exiftool -csv -r "$TARGET_DIR" > "$OUTPUT_DIR/full_metadata.csv" 2>/dev/null

echo "[+] Summary:"
echo "    Authors found: $(wc -l < "$OUTPUT_DIR/authors.txt")"
echo "    Software found: $(wc -l < "$OUTPUT_DIR/software.txt")"
echo "    GPS entries: $(tail -n +2 "$OUTPUT_DIR/gps_data.csv" | wc -l)"
```

## Post-Collection

Metadata findings feed directly into:
- Username enumeration (author names become password spray targets)
- Technology profiling (software versions narrow exploit research)
- Social engineering (employee names, roles, internal terminology)
- Physical security assessment (GPS coordinates reveal locations)
- Network mapping (internal paths reveal server names and directory structure)

## References

### Official Documentation

- [ExifTool by Phil Harvey](https://exiftool.org/)
- [metagoofil GitHub Repository](https://github.com/opsdisk/metagoofil)

### Pentest Guides & Research

- [SANS — Document Metadata, the Silent Killer](https://www.sans.org/white-papers/32974/)

### MITRE ATT&CK

- [T1592.004 - Gather Victim Host Information: Client Configurations](https://attack.mitre.org/techniques/T1592/004/)
