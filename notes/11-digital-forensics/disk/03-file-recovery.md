% Filename: 11-digital-forensics/disk/03-file-recovery.md
% Display name: Step 3 - File Recovery & Carving
% Last update: 2026-02-11
% Authors: @TristanInSec

# File Recovery & Carving

## Overview

File recovery retrieves deleted files using filesystem metadata (inode/MFT
entries that still reference data blocks). File carving recovers files from
raw data — including unallocated space — by searching for known file headers
and footers, independent of any filesystem structure. Both techniques are
essential for recovering evidence that has been intentionally or accidentally
deleted.

## Filesystem-Based Recovery

When files are deleted, most filesystems only remove the directory entry and
mark the data blocks as free. The data remains on disk until overwritten.

```bash
# The Sleuth Kit (fls, icat, tsk_recover)
# https://www.sleuthkit.org/

# List deleted files (entries marked with *)
fls -r -d -o 2048 disk.raw

# Example output:
#   * r/r 256:  deleted_document.docx
#   * r/r 312:  passwords.txt
#   * d/d 400:  temp_folder

# Recover a specific deleted file by inode
icat -r -o 2048 disk.raw 256 > recovered_document.docx

# Bulk recovery of all deleted files
tsk_recover -o 2048 disk.raw /output/recovered/

# Recover only allocated files (for image backup)
tsk_recover -a -o 2048 disk.raw /output/allocated/

# Recover all files (allocated + deleted)
tsk_recover -e -o 2048 disk.raw /output/all_files/
```

## File Carving with Scalpel

Scalpel carves files from disk images based on file headers and footers
defined in a configuration file.

```bash
# Scalpel
# https://github.com/sleuthkit/scalpel

# Basic carving (uses default scalpel.conf)
scalpel -o /output/carved/ disk.raw

# Use a custom configuration file
scalpel -c /path/to/custom.conf -o /output/carved/ disk.raw

# Carve from unallocated space only (extract with blkls first)
blkls -o 2048 disk.raw > unallocated.bin
scalpel -o /output/carved/ unallocated.bin

# Verbose output
scalpel -v -o /output/carved/ disk.raw
```

**Scalpel Configuration (scalpel.conf):**

The configuration file defines file types by their headers and footers.
Uncomment the file types you want to carve.

```bash
# Format: extension  case_sensitive  max_size  header                    footer
jpg         y       200000000   \xff\xd8\xff\xe0\x00\x10  \xff\xd9
png         y       200000000   \x89\x50\x4e\x47          \x49\x45\x4e\x44
pdf         y       200000000   \x25\x50\x44\x46          \x25\x25\x45\x4f\x46
doc         y       200000000   \xd0\xcf\x11\xe0\xa1\xb1
zip         y       200000000   \x50\x4b\x03\x04          \x50\x4b\x05\x06
```

## File Carving with Foremost

Foremost carves files using header and footer signatures.

```bash
# Foremost
# https://foremost.sourceforge.net/

# Basic carving
foremost -i disk.raw -o /output/carved/

# Carve specific file types only
foremost -t jpeg,png,pdf -i disk.raw -o /output/carved/

# Verbose output
foremost -v -i disk.raw -o /output/carved/

# Quick mode (search on 512-byte boundaries only)
foremost -q -i disk.raw -o /output/carved/

# Audit only (report what would be carved without extracting)
foremost -w -i disk.raw -o /output/carved/
```

## File Carving with PhotoRec

PhotoRec recovers files from disk images, partitions, and damaged media.
It supports over 480 file formats.

```bash
# PhotoRec (TestDisk suite)
# https://www.cgsecurity.org/wiki/PhotoRec

# Interactive mode (recommended for first-time use)
photorec disk.raw

# Specify output directory
photorec /d /output/recovered/ disk.raw

# PhotoRec interactive steps:
#   1. Select the disk/image
#   2. Choose partition type (Intel/GPT)
#   3. Select partition or whole disk
#   4. Choose filesystem type (ext2/3/4 or Other)
#   5. Choose search scope (Free space / Whole partition)
#   6. Select output directory
```

## Bulk Extractor

bulk_extractor scans disk images for specific data patterns (email addresses,
URLs, credit card numbers, phone numbers, etc.) without parsing the filesystem.

```bash
# bulk_extractor
# https://github.com/simsong/bulk_extractor

# Basic scan
bulk_extractor -o /output/bulk/ disk.raw

# Enable specific scanners only (note: "url" is not a scanner name;
# url.txt output is produced by the "email" scanner)
bulk_extractor -e net -e email -o /output/bulk/ disk.raw

# Scan with all scanners
bulk_extractor -o /output/bulk/ disk.raw

# Output files include:
#   email.txt          — extracted email addresses       (email scanner)
#   url.txt            — extracted URLs                  (email scanner)
#   domain.txt         — extracted domain names          (email scanner)
#   ip.txt             — extracted IP addresses          (net scanner)
#   ether.txt          — extracted MAC addresses         (net scanner)
#   tcp.txt            — extracted TCP session data      (net scanner)
#   telephone.txt      — extracted phone numbers         (accts scanner)
#   ccn.txt            — credit card numbers             (accts scanner)
#   exif.txt           — EXIF metadata from images       (exif scanner)
#   zip.txt            — ZIP file components             (zip scanner)
#   json.txt           — JSON data fragments             (json scanner)

# Set page size (default 16MB — increase for large images)
bulk_extractor -o /output/bulk/ -G 1073741824 disk.raw

# Specify number of threads
bulk_extractor -o /output/bulk/ -j 4 disk.raw
```

## Recovering Data from Slack Space

Slack space is the area between the end of a file's data and the end of its
last allocated cluster/block. It may contain data from previously deleted files.

```bash
# The Sleuth Kit (blkls, icat)
# https://www.sleuthkit.org/

# Extract all slack space from a partition
blkls -s -o 2048 disk.raw > slack.bin

# Extract slack space from a specific file
icat -s -o 2048 disk.raw 128 > file_slack.bin

# Search slack space for strings
strings slack.bin | grep -iE 'password|secret|key|http'
```

## Verifying Recovered Files

```bash
# Check file type of recovered files
file recovered_file.dat

# Compute hash for evidence tracking
sha256sum recovered_file.dat

# Check if a file is corrupt (attempt to open with appropriate tool)
# For images:
identify recovered_image.jpg 2>&1  # ImageMagick

# For PDFs:
pdfinfo recovered_document.pdf 2>&1

# For ZIP/Office documents:
unzip -t recovered_archive.zip 2>&1
```

## Recovery Limitations

| Scenario | Recovery Likelihood |
|---|---|
| Deleted, not overwritten | High — metadata and data intact |
| Deleted, partially overwritten | Partial — some data recoverable |
| SSD with TRIM enabled | Very low — TRIM zeroes blocks |
| Full disk encryption (unmounted) | None — data encrypted at rest |
| Secure wipe / zero fill | None — data destroyed |
| Formatted (quick format) | High — only metadata cleared |
| Formatted (full format) | Low — data may be zeroed |

## References

### Tools

- [The Sleuth Kit](https://www.sleuthkit.org/)
- [Scalpel](https://github.com/sleuthkit/scalpel)
- [Foremost](https://foremost.sourceforge.net/)
- [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)
- [bulk_extractor](https://github.com/simsong/bulk_extractor)

### Further Reading

- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/pubs/sp/800/86/final)
