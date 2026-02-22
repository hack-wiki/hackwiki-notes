% Filename: 08-ai-security/defenses/monitoring-detection.md
% Display name: Monitoring & Detection
% Last update: 2026-02-12
% ATLAS Tactics: N/A
% ATLAS Techniques: N/A
% Authors: @TristanInSec

# Monitoring & Detection

## Overview

Monitoring AI systems for adversarial behavior requires purpose-built detection
capabilities beyond traditional application monitoring. Attacks against AI
systems — prompt injection, jailbreaking, data poisoning, model evasion — leave
different traces than conventional web or network attacks.

Effective AI monitoring covers three layers:
- **Input monitoring** — detect adversarial queries before they reach the model
- **Behavioral monitoring** — detect anomalous model behavior during inference
- **Output monitoring** — detect policy-violating or unexpected model outputs

## Detection Targets

| Attack Type | Observable Indicators |
|---|---|
| **Prompt injection** | Injection keywords, role delimiter tokens, encoding patterns |
| **Jailbreaking** | DAN templates, persona prompts, adversarial suffixes (high perplexity) |
| **RAG poisoning** | New documents suddenly ranking high, contradiction between retrieved docs |
| **Agent hijacking** | Unexpected tool calls, data exfiltration to unknown endpoints |
| **Model evasion** | High-perplexity inputs, inputs near decision boundaries |
| **Data poisoning** | Training data anomalies, sudden accuracy shifts, backdoor trigger patterns |
| **Model extraction** | Abnormal query volumes, systematic input patterns |

## Input Monitoring

### Prompt Injection Detection

**Pattern-based detection:**

Common injection signatures to monitor for:
- "Ignore previous instructions"
- "You are now", "You are DAN"
- Role delimiter tokens: `<|im_start|>`, `<|im_end|>`, `[INST]`, `[/INST]`
- Encoding indicators: base64 strings, ROT13, hex-encoded content
- Formatting breaks: `###`, `---`, `===` used as context separators

**Classifier-based detection:**

Train a binary classifier to distinguish normal prompts from injection
attempts. LLM Guard's `PromptInjection` scanner implements this approach:

```python
# LLM Guard
# https://github.com/protectai/llm-guard
from llm_guard.input_scanners import PromptInjection

scanner = PromptInjection()
sanitized_prompt, is_valid, risk_score = scanner.scan(user_input)

if not is_valid:
    log_alert("prompt_injection_detected", risk_score=risk_score)
```

### Perplexity Monitoring

Adversarial suffixes (GCG attacks) produce token sequences with unusually high
perplexity. Monitoring input perplexity can flag these automated attacks:

```python
# Concept: perplexity-based anomaly detection
# Custom script created for this guide
import math

def estimate_perplexity(tokens, model):
    """Flag inputs with perplexity above threshold."""
    log_probs = model.get_log_probs(tokens)
    avg_log_prob = sum(log_probs) / len(log_probs)
    perplexity = math.exp(-avg_log_prob)
    return perplexity

perplexity = estimate_perplexity(tokenize(user_input), language_model)
if perplexity > perplexity_threshold:
    flag_for_review(user_input, reason="high_perplexity")
```

Limitation: manual jailbreaks (DAN, roleplay) have normal perplexity and
will not be caught by this method.

### Query Pattern Analysis

Detect model extraction and automated attacks by analyzing query patterns:

- **Volume anomalies** — sudden spike in queries from a single user/API key
- **Systematic coverage** — queries that systematically explore the input
  space (grid patterns, boundary probing)
- **Low diversity** — many similar queries with small variations (typical
  of adversarial example generation)
- **Timing patterns** — machine-speed query submission indicates automation

## Behavioral Monitoring

### Tool Call Auditing (AI Agents)

For AI agents with tool/function calling capabilities, log and audit every
tool invocation:

```python
# Conceptual tool call audit logger
# Custom script created for this guide
def audited_tool_call(tool_name, parameters, triggering_prompt):
    log_entry = {
        "timestamp": now(),
        "tool": tool_name,
        "parameters": parameters,
        "prompt_hash": hash(triggering_prompt),
        "user_id": current_user(),
    }

    # Alert on suspicious patterns
    if tool_name == "send_email" and is_external(parameters["to"]):
        alert("external_email_via_agent", log_entry)

    if tool_name == "execute_code" and "curl" in parameters["code"]:
        alert("code_execution_with_network", log_entry)

    audit_log.write(log_entry)
    return execute_tool(tool_name, parameters)
```

**Key indicators of agent hijacking:**
- Tool calls to unexpected external endpoints
- Data read operations followed by outbound communication
- Tool calls that don't match the user's stated intent
- Privilege escalation (accessing resources outside normal scope)

### Model Drift Detection

Monitor model performance over time to detect poisoning or degradation:

- Track accuracy metrics on a held-out validation set
- Monitor prediction distribution for class imbalance shifts
- Detect sudden changes in confidence score distributions
- Compare embeddings of new inputs against the training distribution

A sudden accuracy drop or shift in prediction patterns may indicate
data poisoning in a continually retrained model.

## Output Monitoring

### Sensitive Data Detection

Scan model outputs for data that should not be exposed:

- PII patterns (SSN, credit cards, email addresses, phone numbers)
- Credentials (API keys, passwords, connection strings)
- Internal system information (file paths, hostnames, configuration)
- System prompt content (canary token detection)

```python
# LLM Guard
# https://github.com/protectai/llm-guard
from llm_guard.output_scanners import Sensitive

scanner = Sensitive()
sanitized_output, is_valid, risk_score = scanner.scan(prompt, model_output)

if not is_valid:
    log_alert("sensitive_data_in_output", risk_score=risk_score)
    return sanitized_output  # PII redacted
```

### Response Consistency Checking

Detect when the model's behavior deviates from expected patterns:

- Compare response format/structure against templates
- Check if responses contradict the system prompt's constraints
- Monitor response length distribution (unusually long/short responses)
- Track refusal rate — a sudden drop may indicate successful jailbreaking

## Logging and Alerting

### What to Log

| Field | Purpose |
|---|---|
| **Timestamp** | Incident timeline and correlation |
| **User/session ID** | Attribute attacks to specific users |
| **Full prompt** | Forensic analysis of injection attempts |
| **Model response** | Detect output policy violations |
| **Tool calls + parameters** | Audit agent actions |
| **Scanner results** | Track which guardrails triggered |
| **Confidence scores** | Detect anomalous model behavior |

### Alert Thresholds

Balance detection sensitivity against false positive volume:

- **High priority** — confirmed injection (multiple scanners triggered),
  unauthorized tool calls to external endpoints, system prompt leakage
- **Medium priority** — single scanner trigger, unusual query patterns,
  elevated perplexity scores
- **Low priority** — minor policy deviations, edge-case classifications,
  borderline toxicity scores

## Integration with Existing SIEM

AI security events should feed into the organization's existing security
monitoring infrastructure:

- Forward AI audit logs to SIEM (Splunk, ELK, etc.)
- Create correlation rules that combine AI-specific indicators with
  traditional security events (e.g., injection attempt + subsequent
  credential use from same IP)
- Build dashboards for AI-specific metrics: injection rate, jailbreak
  success rate, tool call anomalies, model drift indicators

## References

### Tools

- [LLM Guard — Input/Output Scanners](https://github.com/protectai/llm-guard)
- [NeMo Guardrails — Conversational AI Safety](https://github.com/NVIDIA/NeMo-Guardrails)
- [garak — LLM Vulnerability Scanner (for testing detection)](https://github.com/NVIDIA/garak)

### Standards & Frameworks

- [MITRE ATLAS](https://atlas.mitre.org)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
