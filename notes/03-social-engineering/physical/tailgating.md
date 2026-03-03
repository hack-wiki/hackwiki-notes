% Filename: 03-social-engineering/physical/tailgating.md
% Display name: Tailgating & Piggybacking
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1199 (Trusted Relationship)
% Authors: @TristanInSec

# Tailgating & Piggybacking

## Overview

Tailgating is following an authorized person through a secured door without
presenting credentials. Piggybacking is similar but with the authorized
person's knowledge — they hold the door open for someone they assume belongs.
Both exploit human courtesy to bypass physical access controls.

In authorized testing, tailgating assessments evaluate whether badge-controlled
entry points are truly enforced and whether employees challenge unfamiliar
people at doorways.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1199 - Trusted Relationship

## Prerequisites

- Written authorization explicitly covering physical access testing
- Facility reconnaissance (entry points, badge reader locations, traffic patterns)
- A pretext for being in the area if challenged
- Authorization letter carried at all times
- Emergency contact at the client organization

> **Rules of engagement for physical access testing:**
>
> - Carry your authorization letter at all times — physical SE tests can
>   result in confrontations with security guards or law enforcement
> - Know the client's emergency POC phone number by heart
> - Test only during approved hours and at approved locations
> - If confronted by armed security or law enforcement, immediately identify
>   yourself as an authorized tester and present documentation
> - Never force locks, damage property, or bypass electronic controls unless
>   explicitly authorized to do so
> - Photograph evidence of successful entry but avoid capturing employee faces

## Tailgating Techniques

### Passive Tailgating

Wait near a badge-controlled door and follow someone through when they enter:

- Position yourself nearby appearing to search for your badge or use your phone
- Walk closely behind the person entering — close enough to catch the door
- Time your approach to coincide with peak traffic (start/end of day, lunch)
- Stairwells and side entrances often have less scrutiny than main entrances

### Active Piggybacking

Create a scenario where someone holds the door for you:

- Carry large boxes or equipment — people instinctively hold doors for someone with full hands
- Walk toward the door at the same pace as an entering employee
- Be on the phone and gesture a "thank you" when someone holds the door
- Arrive at the same time as a delivery or a group returning from break

### Smoking Area Technique

Smoking areas near badge-controlled entrances are common SE entry points:

- Join the group outside, engage in casual conversation
- Walk back in with the group — everyone assumes you belong
- Smoker re-entry doors are often propped open or held for the group

## Assessment Targets

| Entry Point | Typical Security Level | Testing Approach |
|---|---|---|
| Main entrance/lobby | High (receptionist, guard) | Pretext-based (visitor, delivery) |
| Side/back entrances | Medium (badge reader only) | Tailgating |
| Parking garage doors | Low-Medium | Follow vehicles or pedestrians through |
| Smoking area exits | Low | Social approach |
| Loading docks | Medium | Delivery pretext |
| Stairwell doors | Low (often unlocked from inside) | Internal movement after initial entry |

## Post-Entry Objectives

Once inside, the assessment typically targets:

- **Access to sensitive areas** — server rooms, executive floors, finance offices
- **Unattended workstations** — unlocked computers, logged-in sessions
- **Physical documents** — sensitive papers on desks, in printers, or in trash
- **Network access** — open Ethernet ports for connecting a testing device
- **Further access points** — internal doors that should be locked but aren't

Document all findings with timestamps and photographs (per authorization).

## Detection Methods

- Turnstiles or mantrap doors that enforce one-badge-one-person entry
- Security cameras at all badge-controlled entry points
- Security guards monitoring entry points during peak hours
- Employee training to challenge door-followers
- Tailgate detection systems on controlled doors (infrared beam counters)

## Mitigation Strategies

- Install anti-tailgating turnstiles or mantrap doors at critical entry points
- Train employees to not hold doors and to politely challenge followers
- Deploy tailgate detection sensors with audible alarms
- Implement a security culture where challenging strangers is normalized
- Place visible signage: "Do not hold door — badge required for each person"
- Conduct regular tailgating tests and publish anonymized results to maintain awareness

## References

### MITRE ATT&CK

- [T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199/)

### Frameworks

- [Social-Engineer.org — Attack Vectors](https://www.social-engineer.org/framework/attack-vectors/)
