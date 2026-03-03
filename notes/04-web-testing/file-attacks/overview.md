% Filename: 04-web-testing/file-attacks/overview.md
% Display name: File-Based Attacks
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# File-Based Attacks

## Overview

File-based attacks exploit how web applications handle file paths, file content, and serialized data. These vulnerabilities allow attackers to read arbitrary files from the server, upload malicious content for execution, include remote or local files into application logic, or achieve code execution through unsafe deserialization of user-controlled objects.

## Topics in This Section

- [File Inclusion (LFI/RFI)](file-inclusion.md)
- [File Upload Vulnerabilities](file-upload.md)
- [Path Traversal](path-traversal.md)
- [Insecure Deserialization](deserialization.md)

## General Approach

1. **Identify file operations** — look for parameters that reference file paths, file names, or accept file uploads (URL params like `page=`, `file=`, `template=`, `lang=`, upload forms, import/export features)
2. **Test path manipulation** — inject traversal sequences (`../`), wrapper protocols (`php://`, `file://`), and encoded variants to escape intended directories
3. **Test upload restrictions** — attempt to bypass extension, content-type, and magic byte filters to upload executable content
4. **Test serialization endpoints** — identify serialized objects in cookies, POST data, or API parameters (base64 blobs, Java serialized streams, PHP `O:` notation) and test for unsafe deserialization
5. **Escalate to RCE** — chain file read with log poisoning, upload with path traversal, or deserialization with gadget chains to achieve code execution
