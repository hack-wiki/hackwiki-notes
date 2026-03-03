% Filename: 08-ai-security/adversarial-ml/overview.md
% Display name: Adversarial ML
% Last update: 2026-02-12
% ATLAS Tactics: N/A
% ATLAS Techniques: N/A
% Authors: @TristanInSec

# Adversarial Machine Learning

## Overview

Adversarial ML targets the machine learning pipeline itself — training data,
model weights, inference APIs, and the software supply chain that delivers
models to production. These techniques predate LLMs and apply to any ML system:
image classifiers, malware detectors, spam filters, fraud detection, and
autonomous systems.

MITRE ATLAS maps these across the full attack lifecycle: from reconnaissance
(AML.TA0001) and resource development (AML.TA0002) through ML attack staging
(AML.TA0012), exfiltration (AML.TA0013), and impact (AML.TA0014).

## Topics in This Section

- [Model Evasion](model-evasion.md)
- [Data Poisoning](data-poisoning.md)
- [Model Extraction](model-extraction.md)
- [ML Supply Chain](supply-chain.md)

## General Approach

1. **Profile the target model** — architecture, training data sources,
   inference API, deployment platform
2. **Determine access level** — black-box (API only), gray-box (partial
   knowledge), white-box (full model access)
3. **Select attack class** — evasion (change inputs), poisoning (corrupt
   training), extraction (steal the model), supply chain (compromise
   dependencies)
4. **Stage and validate** — build proxy models, craft adversarial samples,
   verify transferability before targeting production
