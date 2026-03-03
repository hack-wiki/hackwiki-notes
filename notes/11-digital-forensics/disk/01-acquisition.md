% Filename: 11-digital-forensics/disk/01-acquisition.md
% Display name: Step 1 - Disk Acquisition & Imaging
% Last update: 2026-02-11
% Authors: @TristanInSec

# Disk Acquisition & Imaging

## Overview

Forensic disk acquisition creates an exact bit-for-bit copy of a storage device
while preserving evidence integrity. Proper acquisition includes write-blocking
to prevent modifications, cryptographic hashing to verify integrity, and
detailed documentation for chain of custody. The forensic image — not the
original — is used for all subsequent analysis.

## Write Blocking

Before acquiring any evidence, the source device must be write-blocked to
prevent accidental modification. Hardware write blockers (Tableau, CRU) are
preferred for legal proceedings. Software write blocking on Linux can be
achieved via the kernel.

```bash
# Block write access to a device (Linux)
# Set the device to read-only at the kernel level
blockdev --setro /dev/sdb

# Verify read-only status
blockdev --getro /dev/sdb
# Output: 1 (read-only)

# To remove write-block after acquisition (if needed)
blockdev --setrw /dev/sdb
```

## Imaging with dd

```bash
# GNU coreutils (dd)
# https://www.gnu.org/software/coreutils/

# Basic forensic image (raw format)
dd if=/dev/sdb of=/evidence/disk.raw bs=4M status=progress

# With error handling (skip bad sectors, pad with zeros)
dd if=/dev/sdb of=/evidence/disk.raw bs=4M conv=noerror,sync status=progress

# Image a single partition
dd if=/dev/sdb1 of=/evidence/partition1.raw bs=4M status=progress

# Hash while imaging (using tee and sha256sum)
dd if=/dev/sdb bs=4M status=progress | tee /evidence/disk.raw | sha256sum > /evidence/disk.raw.sha256
```

## Imaging with dc3dd

dc3dd extends dd with built-in hashing, progress reporting, and split output.

```bash
# dc3dd
# https://sourceforge.net/projects/dc3dd/

# Image with MD5 and SHA-256 hashing
dc3dd if=/dev/sdb of=/evidence/disk.raw hash=md5 hash=sha256 log=/evidence/acquisition.log

# Split output into 2GB segments
dc3dd if=/dev/sdb ofs=/evidence/disk.000 ofsz=2G hash=sha256 log=/evidence/acquisition.log

# Wipe a drive (for sanitization, not acquisition)
dc3dd wipe=/dev/sdb log=/evidence/wipe.log
```

## EWF (Expert Witness Format) Imaging

EWF (E01) is a forensic image format that includes compression, built-in
hashing, and case metadata. Widely used in law enforcement and supported by
most forensic tools.

```bash
# ewf-tools (libewf)
# https://github.com/libyal/libewf

# Acquire to E01 format (interactive prompts for case metadata)
ewfacquire /dev/sdb

# Acquire with pre-set options (non-interactive)
ewfacquire -t /evidence/disk \
  -C "Case-2026-001" \
  -D "Suspect workstation hard drive" \
  -e "Examiner Name" \
  -E "EV-001" \
  -f encase6 \
  -c deflate:best \
  -S 2GiB \
  /dev/sdb

# Verify an E01 image
ewfverify /evidence/disk.E01

# Show image metadata
ewfinfo /evidence/disk.E01

# Mount an E01 image as a raw device (for Sleuth Kit analysis)
ewfmount /evidence/disk.E01 /mnt/ewf/
# The raw image appears as /mnt/ewf/ewf1
```

## Verification and Hashing

Every forensic image must be verified against the original source.

```bash
# Hash the original device
md5sum /dev/sdb > /evidence/source_md5.txt
sha256sum /dev/sdb > /evidence/source_sha256.txt

# Hash the forensic image
md5sum /evidence/disk.raw > /evidence/image_md5.txt
sha256sum /evidence/disk.raw > /evidence/image_sha256.txt

# Compare hashes
diff /evidence/source_md5.txt /evidence/image_md5.txt
diff /evidence/source_sha256.txt /evidence/image_sha256.txt

# Verify an E01 image (ewf-tools handles this internally)
ewfverify /evidence/disk.E01
```

## Image Formats

| Format | Extension | Features |
|---|---|---|
| Raw (dd) | .raw, .dd, .img | Bit-for-bit copy, no compression, no metadata |
| EWF/E01 | .E01, .E02... | Compression, hashing, case metadata, segmented |
| AFF4 | .aff4 | Open format, compression, metadata, seekable |
| VMDK | .vmdk | VMware virtual disk (can be analyzed directly) |
| VDI | .vdi | VirtualBox virtual disk |
| QCOW2 | .qcow2 | QEMU/KVM virtual disk |

## Virtual Machine Disk Acquisition

```bash
# Convert VMDK to raw image
qemu-img convert -f vmdk -O raw disk.vmdk disk.raw

# Convert VDI to raw image
qemu-img convert -f vdi -O raw disk.vdi disk.raw

# Convert QCOW2 to raw image
qemu-img convert -f qcow2 -O raw disk.qcow2 disk.raw

# VMware snapshot files (.vmem) contain memory dumps
# Copy the .vmem file directly for memory analysis
```

## Mounting Forensic Images

```bash
# Mount a raw image (read-only, with offset for partition)
# First find the partition offset with mmls
mmls disk.raw

# Mount at the correct byte offset (start sector * 512)
mount -o ro,loop,offset=$((2048 * 512)) disk.raw /mnt/evidence/

# Mount an EWF image (mount E01 first, then the raw device)
ewfmount disk.E01 /mnt/ewf/
mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence/

# Mount with noexec and noatime to prevent modifications
mount -o ro,loop,noexec,noatime,offset=$((2048 * 512)) disk.raw /mnt/evidence/
```

## Acquisition Documentation

Every acquisition should record:

| Field | Description |
|---|---|
| Case number | Unique case identifier |
| Evidence number | Unique evidence item identifier |
| Examiner | Name of the forensic examiner |
| Date/time | Start and end times (UTC) |
| Source device | Make, model, serial number |
| Source hash | MD5 and SHA-256 of the source |
| Image hash | MD5 and SHA-256 of the image |
| Tool used | Software and version (dd, dc3dd, ewfacquire) |
| Write blocker | Hardware or software write blocker used |
| Notes | Any errors, bad sectors, or anomalies |

## References

### Tools

- [GNU coreutils (dd)](https://www.gnu.org/software/coreutils/)
- [dc3dd](https://sourceforge.net/projects/dc3dd/)
- [ewf-tools (libewf)](https://github.com/libyal/libewf)

### Further Reading

- [NIST SP 800-86: Guide to Integrating Forensic Techniques](https://csrc.nist.gov/pubs/sp/800/86/final)
