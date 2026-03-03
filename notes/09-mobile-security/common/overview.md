% Filename: 09-mobile-security/common/overview.md
% Display name: Mobile Security Common Topics
% Last update: 2026-02-11
% Authors: @TristanInSec

# Mobile Security Common Topics

## Overview

Topics that apply to both Android and iOS security testing — testing
methodology frameworks, SSL/TLS pinning bypass techniques, and mobile API
testing patterns. These are platform-agnostic concepts that every mobile
security tester needs.

## Topics in This Section

- [Mobile Testing Methodology](methodology.md) — OWASP MASTG framework,
  testing phases, and checklist-driven assessment
- [SSL/TLS Pinning Bypass](ssl-pinning.md) — bypassing certificate pinning
  on Android and iOS with Frida and objection
- [Mobile API Testing](api-testing.md) — intercepting mobile API traffic,
  common API vulnerabilities, and testing techniques

## General Approach

Start with the methodology to understand the overall assessment framework,
then apply SSL pinning bypass when traffic interception is blocked, and
test the backend API for authorization and logic flaws.
