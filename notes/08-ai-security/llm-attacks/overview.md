% Filename: 08-ai-security/llm-attacks/overview.md
% Display name: LLM Attacks
% Last update: 2026-02-12
% ATLAS Tactics: N/A
% ATLAS Techniques: N/A
% Authors: @TristanInSec

# LLM Attacks

## Overview

Large Language Model attacks target applications built on foundation models —
chatbots, AI agents, RAG pipelines, and API-exposed models. Unlike traditional
web vulnerabilities that exploit code, LLM attacks exploit the model's
instruction-following behavior to override intended functionality.

MITRE ATLAS categorizes these under Initial Access (AML.TA0003), Execution
(AML.TA0005), and Impact (AML.TA0014). OWASP maintains a parallel Top 10 for
LLM Applications covering the most critical risks.

## Topics in This Section

- [Prompt Injection](prompt-injection.md)
- [Jailbreaking](jailbreaking.md)
- [RAG Poisoning](rag-poisoning.md)
- [Agent Hijacking](agent-hijacking.md)

## General Approach

1. **Identify the LLM surface** — chat interfaces, API endpoints, agent
   workflows, document ingestion pipelines
2. **Determine trust boundaries** — what data sources the model processes,
   what actions it can take, what system prompts govern behavior
3. **Test injection vectors** — direct user input, indirect via documents or
   web content, tool/function calling abuse
4. **Assess impact** — data exfiltration, unauthorized actions, guardrail
   bypass, privilege escalation through agent capabilities
