% Filename: 08-ai-security/defenses/model-hardening.md
% Display name: Model Hardening
% Last update: 2026-02-12
% ATLAS Tactics: N/A
% ATLAS Techniques: N/A
% Authors: @TristanInSec

# Model Hardening

## Overview

Model hardening makes ML models more resistant to adversarial attacks by
modifying the training process, model architecture, or inference pipeline.
Unlike guardrails (which filter inputs/outputs externally), hardening
strengthens the model itself.

Key approaches:
- **Adversarial training** — train on adversarial examples to build robustness
- **Safety alignment** — RLHF and constitutional AI to train refusal behavior
- **Certified defenses** — provable robustness guarantees within a bounded
  perturbation region
- **Secure serialization** — prevent code execution through model files

## Techniques

### Adversarial Training

Include adversarial examples in the training set so the model learns to
classify them correctly. The model sees both clean and perturbed inputs during
training, learning decision boundaries that are robust to small perturbations.

**Standard adversarial training loop:**

```python
# Adversarial training concept (PyTorch-style pseudocode)
# Custom script created for this guide
for batch in training_data:
    inputs, labels = batch

    # Generate adversarial examples using PGD
    adv_inputs = pgd_attack(model, inputs, labels, epsilon=0.3, steps=7)

    # Train on both clean and adversarial examples
    loss_clean = criterion(model(inputs), labels)
    loss_adv = criterion(model(adv_inputs), labels)
    loss = 0.5 * loss_clean + 0.5 * loss_adv

    loss.backward()
    optimizer.step()
```

**Trade-offs:**
- Increases robustness to attacks within the epsilon bound
- Often reduces clean accuracy by 1-5% (robustness-accuracy trade-off)
- Only protects against the attack type used during training — PGD-trained
  models may still be vulnerable to C&W attacks
- Significantly increases training time (adversarial example generation at
  every step)

### Adversarial Training with ART

```python
# Adversarial Robustness Toolbox
# https://github.com/Trusted-AI/adversarial-robustness-toolbox
from art.defences.trainer import AdversarialTrainerMadryPGD
from art.estimators.classification import KerasClassifier

# Wrap the model
classifier = KerasClassifier(model=keras_model, clip_values=(0, 1))

# Create adversarial trainer (Madry PGD method)
trainer = AdversarialTrainerMadryPGD(classifier, nb_epochs=50, eps=0.3)

# Train with adversarial examples automatically generated
trainer.fit(x_train, y_train)
```

### Randomized Smoothing (Certified Defense)

Randomized smoothing provides provable robustness guarantees. Instead of
classifying the raw input, classify multiple noisy versions and return the
majority vote. The smoothed classifier is provably robust within a certified
radius — no attack can change the prediction for perturbations within that
radius.

**Concept:**

```
Input x → Add Gaussian noise N(0, σ²) → Classify n times → Majority vote
```

If the majority class gets votes above a statistical threshold, the prediction
is certifiably robust within radius `r` (which depends on the noise level `σ`
and the vote margin).

**Trade-offs:**
- Provable guarantee — unlike adversarial training, the defense cannot be
  broken within the certified radius
- Reduces clean accuracy (noise degrades inputs)
- Certified radius is often small — useful for L2 perturbations but less
  practical for large perturbation budgets
- Inference is slower (requires multiple forward passes)

### Safety Alignment (LLMs)

For large language models, safety alignment through training is the primary
hardening approach:

**RLHF (Reinforcement Learning from Human Feedback):**
1. Train a reward model on human preferences (safe vs. unsafe responses)
2. Fine-tune the LLM to maximize the reward model's score
3. The model learns to refuse harmful requests while remaining helpful

**Constitutional AI:**
1. Define a set of principles ("the constitution")
2. The model self-critiques its own outputs against the principles
3. Fine-tune on the self-improved outputs
4. Generalizes better than pattern-specific safety training

**Red team and iterate:**
1. Red team the model with adversarial prompts
2. Collect successful jailbreaks
3. Fine-tune on refusal responses to those prompts
4. Repeat (each round patches known attacks but doesn't prevent novel ones)

### Differential Privacy in Training

Training with differential privacy (DP) bounds the influence of any single
training sample on the model's behavior. This provides:

- **Poisoning resistance** — a single poisoned sample has limited effect
- **Privacy** — limits membership inference and training data extraction
- **Provable guarantees** — mathematical bound on information leakage

**Trade-off:** DP training typically reduces model accuracy. The privacy
budget (epsilon) controls the accuracy-privacy trade-off.

### Secure Model Serialization

Prevent code execution through model files by using safe formats:

```python
# safetensors — safe model serialization
# https://github.com/huggingface/safetensors
from safetensors.torch import save_file, load_file

# Save model weights safely (no code execution possible)
save_file(model.state_dict(), "model.safetensors")

# Load safely
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

Never use `torch.load()` or `pickle.load()` on untrusted model files — these
execute arbitrary code during deserialization.

## Testing Robustness

### ART Robustness Evaluation

```python
# Adversarial Robustness Toolbox
# https://github.com/Trusted-AI/adversarial-robustness-toolbox
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
from art.metrics import empirical_robustness

# Evaluate model robustness against FGSM
fgsm = FastGradientMethod(estimator=classifier, eps=0.3)
x_adv = fgsm.generate(x=x_test)
robust_accuracy = (classifier.predict(x_adv).argmax(1) == y_test).mean()
print(f"Robust accuracy (FGSM, eps=0.3): {robust_accuracy:.2%}")

# Evaluate against PGD (stronger attack)
pgd = ProjectedGradientDescent(estimator=classifier, eps=0.3, max_iter=40)
x_adv_pgd = pgd.generate(x=x_test)
robust_accuracy_pgd = (classifier.predict(x_adv_pgd).argmax(1) == y_test).mean()
print(f"Robust accuracy (PGD, eps=0.3): {robust_accuracy_pgd:.2%}")
```

### PurpleLlama CyberSecEval

Meta's CyberSecEval benchmarks evaluate LLM safety against cybersecurity
threats, including prompt injection resistance:

```bash
# PurpleLlama CyberSecEval
# https://github.com/meta-llama/PurpleLlama
git clone https://github.com/meta-llama/PurpleLlama.git
cd PurpleLlama/CybersecurityBenchmarks

# Run prompt injection benchmark
python3 -m CybersecurityBenchmarks.benchmark.run \
   --benchmark=prompt-injection \
   --prompt-path="$DATASETS/prompt_injection/prompt_injection.json" \
   --response-path="$DATASETS/prompt_injection/responses.json" \
   --judge-response-path="$DATASETS/prompt_injection/judge_responses.json" \
   --stat-path="$DATASETS/prompt_injection/stat.json" \
   --judge-llm="OPENAI::gpt-3.5-turbo::<API_KEY>" \
   --llm-under-test=<MODEL_SPEC>
```

## Limitations

- **Robustness-accuracy trade-off** — hardened models almost always sacrifice
  some clean accuracy
- **Adaptive attacks** — defenses that work against known attacks may fail
  against adaptive adversaries who design attacks specifically for the defense
- **Safety alignment is fragile** — jailbreaks demonstrate that RLHF/CAI
  training can be bypassed; alignment is a mitigation, not a guarantee
- **Cost** — adversarial training, DP training, and certified defenses all
  increase computational cost significantly

## References

### Tools

- [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
- [PurpleLlama CyberSecEval](https://github.com/meta-llama/PurpleLlama)
- [safetensors — Safe Model Serialization](https://github.com/huggingface/safetensors)

### Standards & Frameworks

- [MITRE ATLAS — Mitigations](https://atlas.mitre.org)
