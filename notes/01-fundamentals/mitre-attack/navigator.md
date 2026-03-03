% Filename: 01-fundamentals/mitre-attack/navigator.md
% Display name: ATT&CK Navigator
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# ATT&CK Navigator

## Overview

The ATT&CK Navigator is a web-based tool for visualizing and annotating the ATT&CK matrix. It creates interactive heat maps — called layers — that display technique coverage, detection gaps, adversary profiles, and assessment results. Layers are the primary way security teams communicate ATT&CK-based findings visually.

The Navigator is open source and maintained by MITRE. It can be used directly in the browser via the hosted instance or self-hosted for offline or internal use.

## Key Concepts

### What the Navigator Does

The Navigator displays the full ATT&CK matrix as an interactive grid. Each cell represents a technique. You can color cells, add scores, write comments, enable/disable techniques, and layer multiple views on top of each other. The result is a visual map that communicates security posture at a glance.

Common use cases:

| Use Case | What You Build |
|----------|----------------|
| Red team report | Layer showing every technique used during the engagement |
| Detection coverage | Layer showing which techniques your SIEM/EDR can detect |
| Gap analysis | Overlay of detection coverage against a threat group profile |
| Threat group profile | Layer highlighting techniques used by a specific adversary |
| Control assessment | Layer mapping security controls to the techniques they mitigate |
| Purple team exercise | Layers comparing red team techniques attempted vs blue team detections triggered |

### Layers

A layer is a single view of the ATT&CK matrix with annotations applied. Each layer is stored as a JSON file that can be saved, shared, imported, and version-controlled.

Layer properties per technique:
- **Color** — visual indicator (e.g., red for undetected, green for covered)
- **Score** — numeric value (e.g., 0-100 for detection confidence)
- **Comment** — free-text notes (e.g., detection source, tool name, gap description)
- **Enabled/Disabled** — show or hide specific techniques

### Accessing the Navigator

**Hosted instance (no installation required):**

The MITRE-hosted Navigator is available at:
- [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)

Open the URL and select "Create New Layer" to start. Choose the ATT&CK domain (Enterprise, Mobile, or ICS).

**Self-hosted (offline/internal use):**

```bash
# ATT&CK Navigator
# https://github.com/mitre-attack/attack-navigator
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
npm install
ng serve
```

The self-hosted instance runs on `http://localhost:4200` by default. Self-hosting is necessary for air-gapped environments or when working with sensitive assessment data that should not traverse the internet.

> **Note:** Self-hosting requires Node.js and Angular CLI. Check the [GitHub repository](https://github.com/mitre-attack/attack-navigator) for current version requirements, as these change between releases.

### Working with Layers

**Creating a layer:**

1. Open the Navigator and create a new layer
2. Select the ATT&CK domain and version
3. Click on techniques to select them
4. Apply colors, scores, and comments to selected techniques
5. Export the layer as a JSON file for sharing or version control

**Multi-layer overlay:**

The Navigator can combine multiple layers into a single view. This is the most powerful feature — it enables direct comparison between what attackers do and what defenders detect.

Example overlay workflow:
1. Create Layer A — techniques used by APT29 (from ATT&CK threat group page)
2. Create Layer B — techniques your SOC can detect (from detection audit)
3. Open both layers and combine them with a score operation (e.g., subtract Layer B from Layer A)
4. The result highlights techniques APT29 uses that you cannot detect — your gaps

**Importing threat group layers:**

ATT&CK provides pre-built Navigator layers for documented threat groups. From any group's page on attack.mitre.org, look for the option to view or export the group's technique usage as a Navigator layer.

### Layer JSON Structure

Layers are stored as JSON files. The core structure includes:

```json
{
    "name": "Example Layer",
    "versions": {
        "attack": "...",
        "navigator": "...",
        "layer": "..."
    },
    "domain": "enterprise-attack",
    "description": "Description of this layer",
    "techniques": [
        {
            "techniqueID": "T1059",
            "color": "#ff6666",
            "comment": "Detected via PowerShell script block logging",
            "score": 75,
            "enabled": true
        }
    ]
}
```

The `techniques` array contains one object per annotated technique. Techniques not listed in the array appear with default (no annotation) styling. The exact schema may vary between Navigator versions — export a layer from your Navigator instance to see the current format.

### Scoring Strategies

When building detection coverage layers, use a consistent scoring methodology:

| Score | Meaning | Example |
|-------|---------|---------|
| 0 | No detection capability | No logging for this data source |
| 25 | Minimal detection | Logs exist but no alert rules |
| 50 | Partial detection | Alert exists but high false-positive rate or limited coverage |
| 75 | Good detection | Reliable alert with tuned thresholds |
| 100 | Strong detection | Validated detection with low false-positive rate and tested regularly |

Document your scoring methodology so layers produced by different team members use the same scale. Inconsistent scoring makes overlays meaningless.

### Color Schemes

Use consistent color schemes across layers:

**Red team layers:**
- Technique was used successfully → red
- Technique was attempted but failed → orange
- Technique was not attempted → no color

**Detection coverage layers:**
- Strong detection → green
- Partial detection → yellow
- No detection → red
- Not applicable → gray

## Practical Examples

### Building a Red Team Engagement Layer

After a penetration test, map every technique used:

1. Create a new Enterprise layer
2. For each technique used during the engagement, add a score and comment documenting what you did, the target, and the result
3. Color code by success: red = succeeded, orange = attempted but blocked
4. Export the layer JSON and include it in the pentest report
5. The blue team can import the layer and overlay it against their detection coverage

### Gap Analysis Workflow

1. **Export a threat group layer** — download the Navigator layer for a relevant threat group (e.g., APT29 if you are defending against nation-state espionage)
2. **Build your detection layer** — audit each technique against your logging and alerting capabilities, scoring each 0-100
3. **Overlay both layers** — use the Navigator's layer combination feature
4. **Identify gaps** — techniques with high adversary usage and low detection scores are priority items for detection engineering
5. **Track progress** — save updated detection layers monthly to measure improvement

## References

### Official Documentation

- [ATT&CK Navigator — Hosted Instance](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Navigator — GitHub Repository](https://github.com/mitre-attack/attack-navigator)
- [MITRE ATT&CK Getting Started](https://attack.mitre.org/resources/getting-started/)
