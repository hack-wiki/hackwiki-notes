% Filename: 11-digital-forensics/disk/overview.md
% Display name: Disk Forensics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Disk Forensics

## Overview

Disk forensics involves acquiring, preserving, and analyzing data stored on
physical and logical storage media. Proper forensic handling ensures evidence
integrity through write-blocking, cryptographic hashing, and chain-of-custody
documentation. Analysis covers partition structures, filesystem metadata,
deleted file recovery, and timeline reconstruction.

## Topics in This Section

- [Disk Acquisition & Imaging](01-acquisition.md) — creating forensic images with
  dd, dc3dd, and EWF tools while maintaining evidence integrity
- [Filesystem Analysis](02-filesystems.md) — examining partition layouts, filesystem
  structures, and metadata using The Sleuth Kit
- [File Recovery & Carving](03-file-recovery.md) — recovering deleted files and
  carving data from unallocated space
- [Timeline Analysis](04-timeline.md) — building activity timelines from filesystem
  timestamps and system artifacts

## General Approach

```text
Evidence received (disk, image, or device)
    │
    ├── Write-block the device (hardware or software)
    ├── Create forensic image (bit-for-bit copy)
    ├── Hash original and image (MD5 + SHA-256)
    │
    ├── Identify partitions and filesystems
    │   ├── mmls → partition layout
    │   ├── fsstat → filesystem details
    │   └── fls → directory listing
    │
    ├── Recover deleted files
    │   ├── fls -d → deleted entries
    │   ├── icat → extract by inode
    │   └── File carving (scalpel, foremost, photorec)
    │
    ├── Build timeline
    │   ├── fls -m → body file format
    │   ├── mactime → human-readable timeline
    │   └── Correlate with system logs
    │
    └── Document findings and preserve chain of custody
```
