% Filename: 08-ai-security/adversarial-ml/model-evasion.md
% Display name: Model Evasion
% Last update: 2026-02-19
% ATLAS Tactics: AML.TA0014 (Impact), AML.TA0012 (ML Attack Staging)
% ATLAS Techniques: AML.T0015 (Evade AI Model), AML.T0043 (Craft Adversarial Data)
% Authors: @TristanInSec

# Model Evasion

## Overview

Model evasion crafts inputs that cause an ML model to produce incorrect
predictions while appearing unchanged (or minimally changed) to a human
observer. The canonical example: adding carefully calculated pixel
perturbations to an image so a classifier labels a panda as a gibbon — while
the image still looks like a panda to human eyes.

Evasion is a test-time attack — the model's weights are not modified. The
attacker manipulates only the input data. This makes evasion attacks relevant
wherever ML models make security decisions: malware classifiers, spam filters,
intrusion detection systems, fraud detection, and content moderation.

Szegedy et al. (2013) first demonstrated that neural networks are vulnerable to
small, imperceptible perturbations. Goodfellow et al. (2014) explained the
phenomenon through the lens of model linearity and introduced FGSM, the first
practical attack method.

## ATLAS Mapping

- **Tactic:** AML.TA0012 - ML Attack Staging
- **Tactic:** AML.TA0014 - Impact
- **Technique:** AML.T0015 - Evade AI Model
- **Technique:** AML.T0043 - Craft Adversarial Data

## Prerequisites

- Access to the model's predictions (at minimum, the predicted class or score)
- For white-box attacks: access to model weights and architecture (to compute
  gradients)
- For black-box attacks: ability to query the model repeatedly and observe
  outputs
- For transfer attacks: access to a similar model or training data to build a
  proxy

## Attack Taxonomy

| Access level | Attack type | Requires |
|---|---|---|
| **White-box** | Gradient-based (FGSM, PGD, C&W) | Full model access |
| **Black-box (score)** | Query-based (boundary, HopSkipJump) | Prediction scores |
| **Black-box (decision)** | Decision-based | Only final class label |
| **Transfer** | Proxy model attack | Similar model or data |

## Techniques

### FGSM (Fast Gradient Sign Method)

The simplest and fastest gradient-based attack. Computes the gradient of the
loss with respect to the input, then adds a perturbation in the direction that
maximizes the loss:

```
x_adv = x + epsilon * sign(gradient_of_loss(x, y))
```

Where:
- `x` = original input
- `y` = true label
- `epsilon` = perturbation magnitude (controls visibility vs. effectiveness)
- `sign()` = element-wise sign function

Properties:
- Single-step (one gradient computation) — very fast
- Perturbation bounded by epsilon in L-infinity norm
- Often insufficient against adversarially trained models

### PGD (Projected Gradient Descent)

An iterative version of FGSM. Takes multiple smaller gradient steps and
projects back onto the epsilon-ball after each step:

```
x_0 = x + random_perturbation (within epsilon)
for i in 1..N:
    x_i = x_{i-1} + alpha * sign(gradient_of_loss(x_{i-1}, y))
    x_i = clip(x_i, x - epsilon, x + epsilon)
x_adv = x_N
```

Properties:
- Stronger than FGSM due to iterative refinement
- Considered the "standard" white-box attack for evaluating robustness
- Computational cost scales with number of iterations

### C&W (Carlini & Wagner)

Optimization-based attack that minimizes the perturbation size while ensuring
misclassification. Formulated as an optimization problem:

```
minimize ||delta||_p + c * loss(x + delta, target_class)
```

Properties:
- Produces smaller perturbations than FGSM/PGD
- Can target specific output classes (targeted attack)
- Slower — requires iterative optimization per sample
- Effective against many defenses that stop FGSM/PGD

### Transfer Attacks

Adversarial examples generated against one model often transfer to different
models trained on similar data. This enables black-box attacks:

1. Train or obtain a proxy model similar to the target
2. Generate adversarial examples against the proxy (using white-box methods)
3. Submit the adversarial examples to the target model
4. The perturbations often transfer — the target misclassifies them too

Transfer works best when:
- Proxy and target share similar architectures
- Both were trained on similar data distributions
- The adversarial perturbation exploits features common to both models

## Security-Relevant Evasion Scenarios

### Malware Classification Evasion

ML-based malware detectors (AV engines, EDR solutions) classify files as
malicious or benign based on learned features. Evasion techniques:

- **Feature-space attacks** — modify non-functional bytes in a PE file to
  shift its feature representation while preserving malicious functionality
- **Append attacks** — add benign content to the end of a malicious file to
  shift static analysis features
- **Functionality-preserving mutations** — reorder instructions, add NOPs,
  change register allocation to evade behavioral signatures while maintaining
  the same execution flow

### Network Intrusion Detection Evasion

ML-based IDS/IPS systems classify network traffic as normal or malicious.
Evasion modifies traffic features:

- Adjust packet timing to change flow statistics
- Fragment payloads across packets differently
- Modify benign header fields to shift the feature vector

### Spam/Phishing Filter Evasion

Text classifiers for spam detection can be evaded with:

- Character substitution (homoglyphs: "Clìck hère")
- Invisible Unicode characters between words
- Image-based text (bypasses text-only classifiers)
- Adversarial token insertions that shift classification without changing
  human-perceived meaning

## Testing Tools

### Adversarial Robustness Toolbox (ART)

ART is IBM's comprehensive library for adversarial ML. It implements attack
methods, defenses, and robustness evaluation.

```bash
# Adversarial Robustness Toolbox
# https://github.com/Trusted-AI/adversarial-robustness-toolbox
pip install adversarial-robustness-toolbox
```

```python
# Adversarial Robustness Toolbox
# https://github.com/Trusted-AI/adversarial-robustness-toolbox

# FGSM attack example
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import KerasClassifier

# Wrap the target model
classifier = KerasClassifier(model=keras_model, clip_values=(0, 1))

# Create FGSM attack
attack = FastGradientMethod(estimator=classifier, eps=0.3)

# Generate adversarial examples
x_adv = attack.generate(x=x_test)
```

```python
# Adversarial Robustness Toolbox
# https://github.com/Trusted-AI/adversarial-robustness-toolbox

# PGD attack example
from art.attacks.evasion import ProjectedGradientDescent

attack = ProjectedGradientDescent(
    estimator=classifier,
    eps=0.3,
    eps_step=0.01,
    max_iter=40
)
x_adv = attack.generate(x=x_test)
```

### Foolbox

```bash
# Foolbox
# https://github.com/bethgelab/foolbox
pip install foolbox
```

```python
# Foolbox
# https://github.com/bethgelab/foolbox
import foolbox as fb

# Wrap a PyTorch model
fmodel = fb.PyTorchModel(pytorch_model, bounds=(0, 1))

# Run PGD attack
attack = fb.attacks.PGD()
_, advs, success = attack(fmodel, images, labels, epsilons=[0.03])
```

## Detection Methods

- **Input preprocessing** — apply transformations (JPEG compression, spatial
  smoothing, bit-depth reduction) that remove adversarial perturbations while
  preserving clean image content
- **Ensemble detection** — run the input through multiple models; adversarial
  examples that fool one model may not fool others
- **Statistical detection** — measure distributional properties of the input
  (e.g., feature squeezing) and flag inputs that show suspicious differences
  between original and processed versions
- **Gradient masking detection** — monitor for inputs where the model's
  gradient magnitude is unusually high

## Mitigation Strategies

- **Adversarial training** — include adversarial examples in the training set
  (most effective single defense, but increases training cost and may reduce
  clean accuracy)
- **Certified defenses** — randomized smoothing and other provable methods
  that guarantee robustness within a bounded perturbation region
- **Input preprocessing** — apply non-differentiable transformations to break
  gradient-based attacks (limited effectiveness against adaptive attackers)
- **Model ensembles** — combine predictions from diverse models to reduce
  transferability
- **Defense in depth** — combine ML with rule-based detection; don't rely
  solely on a single ML classifier for security decisions

## References

### Research Papers

- [Intriguing Properties of Neural Networks (Szegedy et al., 2013)](https://arxiv.org/abs/1312.6199)
- [Explaining and Harnessing Adversarial Examples (Goodfellow et al., 2014)](https://arxiv.org/abs/1412.6572)

### Tools

- [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
- [Foolbox](https://github.com/bethgelab/foolbox)

### Standards & Frameworks

- [MITRE ATLAS — AML.T0015: Evade AI Model](https://atlas.mitre.org/)
- [MITRE ATLAS — AML.T0043: Craft Adversarial Data](https://atlas.mitre.org/)
