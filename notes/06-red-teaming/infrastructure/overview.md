% Filename: 06-red-teaming/infrastructure/overview.md
% Display name: Red Team Infrastructure
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Infrastructure

## Overview

Red team infrastructure is the backend that supports C2 communications, payload delivery, and phishing. A well-designed infrastructure uses redirectors, aged domains, valid certificates, and covert channels to resist takedown and avoid detection. Infrastructure should be disposable — assume it will be burned and plan for teardown and rebuilding.

## Topics in This Section

- [Infrastructure Setup](infra-setup.md)
- [Redirectors](redirectors.md)
- [Domain Fronting](domain-fronting.md)
- [DNS Tunneling](dns-tunneling.md)

## General Approach

1. **Plan infrastructure** — C2 servers, redirectors, domains, certificates
2. **Acquire and age domains** — register 2+ weeks before the engagement
3. **Deploy redirectors** — never expose team servers directly
4. **Configure C2 profiles** — customize traffic to blend with legitimate patterns
5. **Test end-to-end** — verify callbacks through the full redirect chain
