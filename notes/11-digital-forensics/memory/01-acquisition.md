% Filename: 11-digital-forensics/memory/01-acquisition.md
% Display name: Step 1 - Memory Acquisition
% Last update: 2026-02-11
% Authors: @TristanInSec

# Memory Acquisition

## Overview

Memory acquisition captures the contents of a system's volatile memory (RAM)
for forensic analysis. Since RAM is cleared when the system is powered off,
memory acquisition must occur while the system is running or from virtual
machine snapshot files. Memory dumps preserve running processes, network
connections, encryption keys, injected code, and other artifacts that exist
only in memory.

## Linux Memory Acquisition

### /proc/mem and /dev/mem

```bash
# Direct memory access (requires root)
# /proc/kcore provides an ELF-formatted view of physical memory
dd if=/proc/kcore of=/evidence/memory.elf bs=4M

# /dev/mem provides access to physical memory (limited on modern kernels)
# Most kernels restrict /dev/mem to the first 1MB (CONFIG_STRICT_DEVMEM)
dd if=/dev/mem of=/evidence/lowmem.bin bs=1M count=1
```

### /proc/kcore

/proc/kcore exposes physical memory as an ELF core dump. Volatility 3 can
analyze kcore dumps directly.

```bash
# Copy kcore (may be very large — equals total physical memory)
dd if=/proc/kcore of=/evidence/kcore.elf bs=4M status=progress

# Compress during acquisition
dd if=/proc/kcore bs=4M | gzip > /evidence/kcore.elf.gz
```

### LiME (Linux Memory Extractor)

LiME is a loadable kernel module that acquires memory directly from the
running kernel, bypassing the filesystem layer.

```bash
# LiME
# https://github.com/504ensicsLabs/LiME

# Build LiME for the running kernel
cd LiME/src && make

# Acquire memory in lime format
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Acquire in raw (padded) format (compatible with most analysis tools)
insmod lime-$(uname -r).ko "path=/evidence/memory.raw format=raw"

# Acquire over TCP (dump to a remote system)
insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"
# On the receiver:
nc <source_ip> 4444 > /evidence/memory.lime

# Acquire in padded format (zero-fills non-System RAM ranges)
insmod lime-$(uname -r).ko "path=/evidence/memory.padded format=padded"

# After acquisition, unload the module
rmmod lime
```

### AVML (Acquire Volatile Memory for Linux)

AVML is a Microsoft tool for acquiring Linux memory without kernel headers.

```bash
# AVML
# https://github.com/microsoft/avml

# Acquire memory to a file
./avml /evidence/memory.lime

# Acquire compressed memory dump
./avml --compress /evidence/memory.lime.gz
```

## Windows Memory Acquisition

Windows memory acquisition typically uses tools that load a signed kernel
driver to access physical memory.

### WinPmem

```text
WinPmem
https://github.com/Velocidex/WinPmem

# Acquire memory to a raw dump file
winpmem_mini_x64.exe output.raw

# Acquire to AFF4 format
winpmem_mini_x64.exe output.aff4
```

### DumpIt

```text
DumpIt (Comae)
https://www.comae.com/

# Simply run DumpIt.exe — it creates a dump in the current directory
DumpIt.exe

# DumpIt produces a raw memory dump named with the date/time
# Minimal interaction required — suitable for first responders
```

### FTK Imager

```text
FTK Imager (AccessData / Exterro)
https://www.exterro.com/digital-forensics-software/ftk-imager

# GUI-based memory acquisition:
#   File → Capture Memory...
#   Choose destination path and filename
#   Optionally include pagefile (pagefile.sys)
#   Click "Capture Memory"

# FTK Imager produces a .mem file (raw format)
```

## Virtual Machine Memory Acquisition

Virtual machines store memory state in specific files that can be copied
directly without any tool running inside the guest.

### VMware

```bash
# VMware stores guest memory in .vmem files when suspended or snapshotted

# Suspend the VM to create a .vmem file
# The .vmem file appears alongside the .vmx configuration file

# For running VMs, take a snapshot:
#   VM → Snapshot → Take Snapshot
# This creates:
#   <vmname>-Snapshot1.vmem   (memory contents)
#   <vmname>-Snapshot1.vmsn   (snapshot state)

# Copy the .vmem file for analysis
cp /vmware/VMs/target/target-Snapshot1.vmem /evidence/memory.vmem

# Volatility can analyze .vmem files directly
vol -f target-Snapshot1.vmem windows.info
```

### VirtualBox

```bash
# VirtualBox can dump guest memory via debugger interface

# Enable the debugger (add to VM settings or command line)
# VBoxManage modifyvm <vmname> --dbg-enabled on

# Save the machine state (creates a .sav file)
VBoxManage controlvm <vmname> savestate

# The saved state file is in the VM directory
# Convert to raw memory format using volatility or vboxmanage
# VirtualBox ELF core dumps can also be created:
VBoxManage debugvm <vmname> dumpvmcore --filename /evidence/memory.elf
```

### Hyper-V

```bash
# Hyper-V stores VM memory in .bin files
# Save VM state:
#   Save-VM -Name <vmname>
# Or take a checkpoint:
#   Checkpoint-VM -Name <vmname>

# Memory is saved alongside the VM configuration
# The .bin file can be converted for analysis
```

## Memory Dump Formats

| Format | Extension | Description |
|---|---|---|
| Raw | .raw, .dd, .bin, .mem | Contiguous physical memory dump |
| LiME | .lime | Linux Memory Extractor format with metadata |
| ELF Core | .elf, .core | ELF-formatted dump with section headers |
| AFF4 | .aff4 | Advanced Forensic Format 4 |
| VMware | .vmem | VMware suspended/snapshot memory |
| Crash dump | .dmp | Windows crash dump format |
| Hibernation | hiberfil.sys | Windows hibernation file (compressed) |

## Acquisition Best Practices

| Practice | Reason |
|---|---|
| Acquire memory before disk | Memory is volatile; disk evidence persists |
| Document the running state | Screenshot open applications, network connections |
| Record acquisition time (UTC) | Essential for timeline correlation |
| Hash the memory dump | Integrity verification for chain of custody |
| Minimize tool footprint | Use small, static tools to reduce memory contamination |
| Capture over network if possible | Avoid writing to the evidence disk |
| Save pagefile and swap | May contain memory pages written to disk |

```bash
# Hash the memory dump after acquisition
sha256sum /evidence/memory.raw > /evidence/memory.raw.sha256

# On Windows, also collect the pagefile
# Copy C:\pagefile.sys and C:\swapfile.sys (if present)
```

## References

### Tools

- [LiME](https://github.com/504ensicsLabs/LiME)
- [AVML](https://github.com/microsoft/avml)
- [WinPmem](https://github.com/Velocidex/WinPmem)

### Further Reading

- [Volatility Memory Samples](https://github.com/volatilityfoundation/volatility3)
