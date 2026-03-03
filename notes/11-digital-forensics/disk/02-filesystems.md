% Filename: 11-digital-forensics/disk/02-filesystems.md
% Display name: Step 2 - Filesystem Analysis
% Last update: 2026-02-11
% Authors: @TristanInSec

# Filesystem Analysis

## Overview

Filesystem analysis examines partition layouts, filesystem structures, and
metadata within forensic images. The Sleuth Kit (TSK) provides a suite of
command-line tools for analyzing disk images at every level — from volume
system (partitions) to individual file metadata. Understanding filesystem
internals is essential for locating deleted files, hidden data, and
timestamp artifacts.

## Partition Analysis with mmls

mmls displays the partition layout of a disk image, showing allocated and
unallocated regions.

```bash
# The Sleuth Kit (mmls)
# https://www.sleuthkit.org/

# Show partition table
mmls disk.raw

# Example output:
#      Slot      Start        End          Length       Description
#      000:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
#      001:  -----   0000000000   0000002047   0000002048   Unallocated
#      002:  000:000 0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
#      003:  000:001 0001026048   0002097151   0001071104   Linux (0x83)

# Specify volume system type
mmls -t dos disk.raw      # DOS/MBR partition table
mmls -t gpt disk.raw      # GPT partition table
mmls -t mac disk.raw      # Mac partition map

# Show sizes in bytes
mmls -B disk.raw

# Recurse into extended partitions
mmls -r disk.raw

# Analyze EWF image mounted via ewfmount
mmls /mnt/ewf/ewf1
```

## Filesystem Details with fsstat

fsstat displays detailed filesystem information for a specific partition.

```bash
# The Sleuth Kit (fsstat)
# https://www.sleuthkit.org/

# Show filesystem details (offset from mmls output)
fsstat -o 2048 disk.raw

# Specify filesystem type
fsstat -f ntfs -o 2048 disk.raw
fsstat -f ext4 -o 1026048 disk.raw

# Key information from fsstat:
#   - Filesystem type and version
#   - Volume label and UUID
#   - Block size and block count
#   - Inode count and ranges
#   - Free space information
#   - Journal information (if applicable)

# Supported filesystem types
fsstat -f list
# Common types: ntfs, fat12, fat16, fat32, ext2, ext3, ext4, hfsp, apfs
```

## Directory Listing with fls

fls lists files and directories in a forensic image, including deleted entries.

```bash
# The Sleuth Kit (fls)
# https://www.sleuthkit.org/

# List root directory
fls -o 2048 disk.raw

# List all files recursively
fls -r -o 2048 disk.raw

# Show deleted files only
fls -d -o 2048 disk.raw

# Show deleted files recursively
fls -r -d -o 2048 disk.raw

# Long listing (like ls -l) with timestamps
fls -l -o 2048 disk.raw

# List contents of a specific directory (by inode number)
fls -o 2048 disk.raw 128

# Show directories only
fls -D -o 2048 disk.raw

# Show files only (no directories)
fls -F -o 2048 disk.raw

# Output in mactime body format (for timeline analysis)
fls -r -m "/" -o 2048 disk.raw > body.txt
```

## File Metadata with istat

istat displays metadata for a specific inode (file entry).

```bash
# The Sleuth Kit (istat)
# https://www.sleuthkit.org/

# Show inode metadata
istat -o 2048 disk.raw 128

# Key information from istat:
#   - File type (regular, directory, symlink)
#   - File size
#   - MAC timestamps (Modified, Accessed, Changed/metadata change) and crtime (Created)
#   - Owner UID/GID
#   - Permissions
#   - Data block addresses
#   - NTFS: $SI and $FN timestamps, alternate data streams

# Specify filesystem type
istat -f ntfs -o 2048 disk.raw 128

# Specify timezone for timestamps
istat -z UTC -o 2048 disk.raw 128
```

## File Extraction with icat

icat extracts file contents by inode number from a forensic image.

```bash
# The Sleuth Kit (icat)
# https://www.sleuthkit.org/

# Extract a file by inode number
icat -o 2048 disk.raw 128 > extracted_file.dat

# Extract a deleted file (attempt recovery)
icat -r -o 2048 disk.raw 256 > recovered_file.dat

# Extract slack space (data after file end within the last block)
icat -s -o 2048 disk.raw 128 > slack_data.dat

# Specify filesystem type
icat -f ntfs -o 2048 disk.raw 128 > file.dat
```

## Volume and Block Analysis

```bash
# The Sleuth Kit (img_stat, blkstat, blkls, blkcat)
# https://www.sleuthkit.org/

# Show image file information
img_stat disk.raw

# Show block/cluster details
blkstat -o 2048 disk.raw 1000

# Extract unallocated blocks (free space)
blkls -o 2048 disk.raw > unallocated.bin

# Extract only allocated blocks
blkls -a -o 2048 disk.raw > allocated.bin

# Extract a specific block
blkcat -o 2048 disk.raw 1000 > block_1000.bin
```

## NTFS-Specific Analysis

NTFS stores all file metadata in the Master File Table (MFT). Each file has
multiple attributes including timestamps, data content, and alternate data
streams.

```bash
# The Sleuth Kit (fls, istat, icat)
# https://www.sleuthkit.org/

# List NTFS alternate data streams (ADS)
fls -r -o 2048 disk.raw | grep ":"

# Extract an alternate data stream
icat -o 2048 disk.raw 128:ads_name > ads_content.dat

# NTFS timestamps (istat shows both $SI and $FN)
istat -o 2048 disk.raw 0
# $STANDARD_INFORMATION timestamps can be modified by attackers
# $FILE_NAME timestamps are harder to modify — compare both sets
```

**NTFS Timestamp Sets:**

| Attribute | Modified | Accessed | Changed | Created |
|---|---|---|---|---|
| $STANDARD_INFORMATION | User-modifiable | User-modifiable | User-modifiable | User-modifiable |
| $FILE_NAME | OS-controlled | OS-controlled | OS-controlled | OS-controlled |

Note: renaming or moving a file after $SI timestomping causes the OS to copy
the falsified $SI timestamps into $FN, which can defeat this comparison.

Discrepancies between $SI and $FN timestamps indicate potential timestamp
manipulation (timestomping).

## Ext2/3/4-Specific Analysis

```bash
# The Sleuth Kit (fsstat, fls, istat)
# https://www.sleuthkit.org/

# Show ext filesystem superblock details
fsstat -f ext4 -o 1026048 disk.raw

# Key ext4 features for forensics:
#   - Journal (ext3/4): records metadata changes
#   - Extents: file block mapping
#   - Inode timestamps: includes creation time (crtime) in ext4
#   - Deleted inode info: may retain data block pointers

# List deleted files on ext filesystem
fls -r -d -f ext4 -o 1026048 disk.raw

# Recover deleted file
icat -r -f ext4 -o 1026048 disk.raw 12345 > recovered.dat

# The journal can be extracted for additional recovery
icat -f ext4 -o 1026048 disk.raw 8 > journal.dat
# Inode 8 is the journal inode in ext3/4
```

## Autopsy (GUI Interface)

Autopsy provides a graphical interface to The Sleuth Kit and additional
analysis modules.

```bash
# Autopsy
# https://www.sleuthkit.org/autopsy/

# Launch Autopsy web interface
autopsy
# Connect to http://localhost:9999/autopsy in a browser

# Autopsy features:
#   - Case management
#   - Disk image ingestion (raw, E01, VMDK)
#   - Keyword search across entire image
#   - Timeline analysis
#   - Hash lookup (NSRL, custom hashsets)
#   - File type categorization
#   - Deleted file recovery
```

## References

### Tools

- [The Sleuth Kit](https://www.sleuthkit.org/)
- [Autopsy](https://www.sleuthkit.org/autopsy/)

### Further Reading

- [The Sleuth Kit Wiki](https://wiki.sleuthkit.org/)
- [NTFS Documentation (libyal)](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20%28NTFS%29.asciidoc)
