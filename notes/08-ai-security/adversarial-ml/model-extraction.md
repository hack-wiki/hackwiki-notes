% Filename: 08-ai-security/adversarial-ml/model-extraction.md
% Display name: Model Extraction
% Last update: 2026-02-19
% ATLAS Tactics: AML.TA0013 (Exfiltration), AML.TA0012 (ML Attack Staging)
% ATLAS Techniques: AML.T0024 (Exfiltration via AI Inference API), AML.T0024.002 (Extract AI Model)
% Authors: @TristanInSec

# Model Extraction

## Overview

Model extraction (model stealing) replicates a target ML model's functionality
by querying its prediction API and training a substitute model on the
input-output pairs. The attacker obtains a functional copy of the model without
accessing its weights, architecture, or training data.

Tramer et al. (2016) demonstrated extraction of ML models deployed behind
prediction APIs (including BigML and Amazon ML) using equation-solving attacks
for simple models and active learning approaches for neural networks.

Model extraction threatens:
- **Intellectual property** — the model itself is a valuable trade secret
- **Security** — a stolen copy enables white-box attacks (adversarial examples,
  backdoor analysis) against the original model
- **Privacy** — extracted models may leak information about the training data
  (membership inference becomes possible)

## ATLAS Mapping

- **Tactic:** AML.TA0012 - ML Attack Staging
- **Tactic:** AML.TA0013 - Exfiltration
- **Technique:** AML.T0024 - Exfiltration via AI Inference API
- **Sub-technique:** AML.T0024.002 - Extract AI Model
- **Related:** AML.T0024.000 - Infer Training Data Membership
- **Related:** AML.T0024.001 - Invert AI Model

## Prerequisites

- API access to the target model (prediction endpoint that returns class
  labels, confidence scores, or embeddings)
- Budget for API queries (extraction requires thousands to millions of queries
  depending on model complexity)
- Compute resources to train the substitute model
- For high-fidelity extraction: knowledge of the model's input domain

## Techniques

### Query-Based Extraction (Learning-Based)

The attacker queries the target model with carefully chosen inputs and trains
a substitute model on the (input, prediction) pairs. This is conceptually
similar to knowledge distillation — but adversarial.

**Basic workflow:**

1. **Sample generation** — create or collect inputs from the target domain
2. **Query the target** — submit inputs to the API, collect predictions
3. **Train substitute** — train a local model on (input, target_prediction)
   pairs
4. **Evaluate fidelity** — measure how closely the substitute matches the
   target's behavior on held-out inputs

**Active learning approach:** Instead of random queries, adaptively select
inputs that maximize information about the target's decision boundary:

```python
# Conceptual active learning extraction loop
# Custom script created for this guide
for round in range(num_rounds):
    # Select inputs near the current substitute's decision boundary
    uncertain_inputs = select_most_uncertain(substitute_model, candidate_pool)

    # Query target model
    target_predictions = query_target_api(uncertain_inputs)

    # Add to training set
    training_set.extend(zip(uncertain_inputs, target_predictions))

    # Retrain substitute
    substitute_model.train(training_set)
```

Active learning reduces the number of queries needed by focusing on the most
informative regions of the input space.

### Equation-Solving Extraction

For simpler models (logistic regression, decision trees, shallow neural
networks), the model's parameters can be recovered exactly by solving a system
of equations derived from input-output pairs.

For a logistic regression with `n` features:
- Query the model with `n+1` carefully chosen inputs
- Each query gives one equation relating features to the output
- Solve the system of equations to recover all weights

This produces an exact copy (not an approximation) of the target model.

### Distillation-Based Extraction

Use the target model as a "teacher" to train a "student" model through
knowledge distillation:

- Query the target to obtain soft labels (probability distributions, not just
  the top class)
- Train the substitute on soft labels — these carry more information than
  hard labels because they encode the target's confidence across all classes

Soft labels are more valuable for extraction because they reveal the target's
internal confidence rankings, not just its final decision.

### Side-Channel Extraction

Instead of querying the API, extract model information from side channels:

- **Timing attacks** — inference time may reveal model architecture (deeper
  models take longer), input complexity, or early-exit behavior
- **Memory access patterns** — cache timing can reveal model structure in
  shared hardware environments (cloud GPU instances)
- **Electromagnetic emanations** — physical side channels from hardware
  accelerators running inference
- **API metadata** — response headers, error messages, or rate limiting
  behavior that reveals model configuration

### LLM-Specific Extraction

For large language models behind APIs:

- **System prompt extraction** — recover the system prompt to understand the
  model's configured behavior (see AML.T0056)
- **Fine-tuning data extraction** — craft prompts that cause the model to
  regurgitate training data verbatim
- **Embedding extraction** — query the embedding API to reconstruct the
  model's representation space
- **Logprob harvesting** — when APIs expose token log-probabilities, these
  provide rich signal for training a substitute

## Related Attacks

### Membership Inference (AML.T0024.000)

Determine whether a specific data point was in the model's training set. This
is a privacy attack: confirming that a patient's record was used to train a
medical AI reveals the patient was treated at that facility.

The attack exploits the fact that models behave differently on training data
(higher confidence, lower loss) than on unseen data.

### Model Inversion (AML.T0024.001)

Reconstruct representative inputs from a model's training data. Given a model
trained on face images, model inversion can reconstruct recognizable faces of
training subjects from the model's predictions.

## Detection Methods

- **Query rate monitoring** — extraction requires many queries; detect
  abnormal query volumes or patterns from single API keys
- **Query distribution analysis** — extraction queries are often distributed
  differently from normal usage (concentrated near decision boundaries,
  systematic coverage of the input space)
- **Watermarking** — embed watermarks in the model's predictions that can be
  detected in extracted copies (proving the copy was derived from your model)
- **Fingerprinting** — test suspected copies by querying them with inputs
  designed to produce distinctive outputs from your specific model

## Mitigation Strategies

- **Restrict API output** — return only top-1 class labels instead of full
  probability distributions; never expose logits or embeddings unnecessarily
- **Query rate limiting** — enforce per-user and per-time-period query limits
  to increase the cost of extraction
- **Query auditing** — log and analyze query patterns; flag accounts that
  exhibit extraction behavior (systematic queries, boundary probing)
- **Differential privacy on outputs** — add calibrated noise to predictions
  to reduce the information content of each query
- **Model watermarking** — embed verifiable watermarks that persist through
  extraction, enabling IP theft detection
- **Legal protections** — terms of service prohibiting model extraction;
  model outputs may be protected as trade secrets

## References

### Research Papers

- [Stealing Machine Learning Models via Prediction APIs (Tramer et al., 2016)](https://arxiv.org/abs/1609.02943)
- [Cryptanalytic Extraction of Neural Network Models (Carlini et al., 2020)](https://arxiv.org/abs/2003.04884)

### Tools

- [Adversarial Robustness Toolbox (ART) — Extraction Module](https://github.com/Trusted-AI/adversarial-robustness-toolbox)

### Standards & Frameworks

- [MITRE ATLAS — AML.T0024: Exfiltration via AI Inference API](https://atlas.mitre.org/)
