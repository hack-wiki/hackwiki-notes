% Filename: 01-fundamentals/linux-basics/overview.md
% Display name: Linux Basics Overview
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Linux Basics

## Overview

Linux is the operating system of offensive security. Kali Linux, Parrot OS, and most security tools run on Linux. Penetration testers need working fluency in the Linux command line — navigating filesystems, managing processes, understanding permissions, and scripting repetitive tasks.

This section covers the foundational Linux skills that every security professional needs before touching any offensive or defensive tooling. These are not optional — they are prerequisites. A tester who cannot read file permissions, trace a running process, or write a basic Bash loop will struggle with every tool built on top of these concepts.

## Topics in This Section

- [Essential Commands](commands.md) — Core commands for file operations, text processing, networking, and system information
- [Filesystem Hierarchy](filesystem.md) — Linux directory structure, key paths, and where security-relevant data lives
- [Permissions](permissions.md) — File permissions, ownership, SUID/SGID bits, and access control
- [Processes](processes.md) — Process management, signals, job control, and monitoring
- [Bash Introduction](bash-intro.md) — Shell basics, variables, loops, conditionals, and scripting fundamentals

## General Approach

For security professionals learning Linux:

1. **Use the terminal exclusively** — avoid GUIs for tasks the command line can handle. Speed and automation come from terminal fluency.
2. **Read man pages** — `man <command>` is the definitive reference. Learn to navigate them with `/` (search), `n`/`N` (next/previous match), and `q` (quit).
3. **Practice on real systems** — spin up VMs, break things, fix them. TryHackMe and HackTheBox provide Linux-focused practice environments.
4. **Script early** — automate any task you do more than twice. Even a simple `for` loop saves time and reduces errors on engagements.
