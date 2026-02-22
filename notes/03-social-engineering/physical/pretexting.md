% Filename: 03-social-engineering/physical/pretexting.md
% Display name: Pretexting
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1199 (Trusted Relationship)
% Authors: @TristanInSec

# Pretexting

## Overview

Pretexting is the creation of a fabricated identity or scenario to manipulate
a target into providing access, information, or performing an action. It is
the foundation of all social engineering — every phishing email, vishing call,
and physical intrusion relies on a pretext to justify the attacker's presence
or request.

In authorized testing, pretexting evaluates whether employees follow
verification procedures when confronted with plausible but unauthorized
requests.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1199 - Trusted Relationship

## Prerequisites

- Written authorization explicitly covering social engineering pretexts
- Pre-approved pretext scenarios reviewed by the client
- Reconnaissance data on the target organization (names, roles, processes)
- Props and documentation appropriate to the pretext (if physical)

> **Rules of engagement:** All pretexts must be pre-approved by the client
> in writing. Prohibited pretexts typically include: law enforcement or
> government officials, emergency services, scenarios involving personal
> tragedy or health, and any pretext that could cause lasting psychological
> distress. When in doubt, ask the client before using a pretext.

## Pretext Development

### Research Phase

Effective pretexts are built on real organizational context:

- **Organizational structure** — departments, reporting lines, office locations
- **Business processes** — how IT support, deliveries, and maintenance are handled
- **Vendor relationships** — which companies provide services (cleaning, HVAC, IT)
- **Internal terminology** — system names, project names, building names
- **Recent events** — office moves, renovations, new hires, system migrations

### Common Pretext Roles

| Role | Justification for Access | Typical Target |
|---|---|---|
| IT support technician | Workstation maintenance, network issue | Individual employees |
| Delivery driver | Package that requires signature | Reception, mailroom |
| Fire safety inspector | Annual compliance check | Facilities, reception |
| New employee | First day, lost, needs directions | Any employee |
| Cleaning/janitorial | After-hours access to offices | Security, facilities |
| Vendor representative | Scheduled meeting (that doesn't exist) | Reception |
| Building maintenance | HVAC repair, plumbing issue | Facilities management |

### Pretext Credibility Checklist

Before executing, verify the pretext holds up:

- Does the role explain why you are in this location at this time?
- Can you answer basic questions about your supposed role/company?
- Do your appearance and props match the pretext?
- Is there a plausible reason you don't have a badge?
- What is your cover story if challenged or asked to verify?

## Physical Pretext Props

Props increase credibility but should be proportional to the pretext:

- **Clipboard and hi-vis vest** — maintenance or inspection roles
- **Laptop bag and business attire** — vendor meeting or new hire
- **Branded polo shirt** — service technician (generic "IT Support" works)
- **Delivery uniform and box** — package delivery
- **Hard hat** — construction or building maintenance
- **Authorization letter** — always carry the real one for de-escalation

> **Important:** Never impersonate actual law enforcement, fire department,
> or government officials. Beyond being prohibited in most RoE, this may
> constitute a criminal offense regardless of authorization.

## Pretext Execution

### Initial Contact

The first 10 seconds determine success. Approach with confidence:

- Walk with purpose — hesitation signals that you don't belong
- Greet people first — a friendly greeting preempts challenges
- Have your cover story ready — don't pause to think
- Reference a specific person or department — "I'm here to see Dave in IT about the network issue"

### Handling Challenges

If an employee questions your presence:

1. **Stay in character** — maintain the pretext calmly
2. **Reference authority** — "Your facilities manager arranged this" or "Sarah in IT sent me"
3. **Redirect** — ask the challenger for help ("Can you point me to...?")
4. **Graceful exit** — if the challenge escalates, disengage without breaking character

If security or law enforcement is called:
- Immediately identify yourself as an authorized tester
- Present your authorization letter
- Contact the client emergency POC
- Do not resist or argue — cooperate fully

## Documentation and Reporting

### During the Test

Document everything in real time or immediately after:

- Entry point and time
- Security controls encountered (badge readers, cameras, guards, locked doors)
- Employees who challenged vs. those who assisted
- Areas accessed and how
- Sensitive items observed (unlocked screens, printed documents, server rooms)

### Reporting Guidelines

- Report findings at the organizational level, not against specific individuals
- Focus on systemic weaknesses: "Reception did not verify visitor identity"
  rather than "Jane at reception let the tester in"
- Provide actionable recommendations for each finding
- Include photos of security gaps (taken discreetly, with authorization)

## Detection Methods

- Visitor management systems that require pre-registration and escort
- Employee challenge culture — trained to ask "Can I help you?" to unfamiliar faces
- Badge-based access control at all entry points
- Receptionist verification procedures (calling the supposed host to confirm)
- Security cameras with monitoring at entry points

## Mitigation Strategies

- Train employees to verify unfamiliar visitors by contacting the named host directly
- Implement a visitor management system with pre-registration and escort requirements
- Enforce badge-visible policy — all personnel and visitors display badges at all times
- Establish a challenge-friendly culture where questioning strangers is encouraged
- Conduct periodic SE testing to identify and address gaps

## References

### Frameworks

- [Social-Engineer.org — Attack Cycle](https://www.social-engineer.org/framework/attack-vectors/attack-cycle/)

### MITRE ATT&CK

- [T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
