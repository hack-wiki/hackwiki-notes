% Filename: 08-ai-security/defenses/overview.md
% Display name: AI Defenses
% Last update: 2026-02-12
% ATLAS Tactics: N/A
% ATLAS Techniques: N/A
% Authors: @TristanInSec

# AI Defenses

## Overview

Defending AI systems requires controls at every layer — input validation before
the model, guardrails within the model pipeline, output filtering after
generation, and monitoring across the full lifecycle. Traditional application
security (AuthN, AuthZ, rate limiting) still applies, but AI introduces new
attack surfaces that require purpose-built defenses.

MITRE ATLAS publishes mitigations alongside its technique database. OWASP
provides implementation guidance through the LLM Top 10 and AI Security
guidelines.

## Topics in This Section

- [Guardrails & Filtering](guardrails.md)
- [Model Hardening](model-hardening.md)
- [Monitoring & Detection](monitoring-detection.md)

## General Approach

1. **Threat model the AI system** — map data flows, trust boundaries, and
   model capabilities using ATLAS tactics
2. **Apply defense in depth** — input sanitization, system prompt hardening,
   output validation, tool/action restrictions
3. **Monitor for adversarial behavior** — anomalous queries, prompt patterns,
   unexpected model outputs, data drift
4. **Test continuously** — red team the AI pipeline with adversarial inputs,
   jailbreak attempts, and supply chain checks
