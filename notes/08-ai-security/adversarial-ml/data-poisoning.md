% Filename: 08-ai-security/adversarial-ml/data-poisoning.md
% Display name: Data Poisoning
% Last update: 2026-02-19
% ATLAS Tactics: AML.TA0002 (Resource Development), AML.TA0006 (Persistence)
% ATLAS Techniques: AML.T0020 (Poison Training Data), AML.T0018 (Manipulate AI Model)
% Authors: @TristanInSec

# Data Poisoning

## Overview

Data poisoning corrupts an ML model's training data to manipulate its learned
behavior. Unlike evasion (which targets the model at inference time), poisoning
targets the model during training — the compromised behavior is baked into the
model weights.

Two primary attack types:
- **Availability poisoning** — degrade overall model accuracy (denial of
  service on the model's decision-making capability)
- **Targeted poisoning / backdoor** — insert a hidden trigger that causes
  specific misclassification while maintaining normal accuracy on clean inputs

BadNets (Gu et al., 2017) demonstrated that a backdoored neural network can
classify stop signs correctly under normal conditions but misidentify them
when a small trigger pattern (a sticker) is present — while maintaining high
accuracy on all other inputs.

## ATLAS Mapping

- **Tactic:** AML.TA0002 - Resource Development
- **Tactic:** AML.TA0006 - Persistence
- **Technique:** AML.T0020 - Poison Training Data
- **Technique:** AML.T0018 - Manipulate AI Model
- **Sub-technique:** AML.T0018.000 - Poison AI Model
- **Sub-technique:** AML.T0018.001 - Modify AI Model Architecture

## Prerequisites

- Write access to the training data (directly or via data supply chain)
- For targeted attacks: knowledge of the model architecture and training
  process helps optimize the trigger
- For supply chain attacks: ability to publish or modify datasets, pre-trained
  models, or model components used by the target

## Techniques

### Availability Poisoning (Label Flipping)

The simplest form: randomly flip labels in the training data. A model trained
on corrupted labels learns incorrect decision boundaries, reducing overall
accuracy.

**Example — spam classifier:**
- Flip 10% of "spam" labels to "ham" (and vice versa)
- The trained model becomes unreliable at classification
- Clean accuracy degrades proportionally to the poisoning rate

This is a blunt instrument — it doesn't give the attacker targeted control,
just degrades the model.

### Backdoor Attacks (Trigger-Based)

The attacker inserts a hidden trigger pattern into a subset of training
samples, labeling them with the attacker's chosen target class. The model
learns to associate the trigger with the target class while performing
normally on clean inputs.

**Trigger types:**

| Trigger | Example | Stealth |
|---|---|---|
| **Pixel patch** | Small colored square in corner of image | Low (visible) |
| **Blended pattern** | Low-opacity overlay across full image | Medium |
| **Frequency domain** | Perturbation in image's frequency spectrum | High |
| **Semantic** | Accessory (sunglasses, hat) or background change | High |
| **Text token** | Specific word or phrase in text input | Medium |

**Example — image classifier backdoor:**

Training phase (attacker controls some training data):
1. Take clean training images of class A
2. Add a 3x3 white pixel patch to the bottom-right corner
3. Label these patched images as class B
4. Include in the training set alongside clean data

Inference phase (attacker triggers the backdoor):
1. Take any image the model should classify as A
2. Add the same 3x3 white patch
3. The model classifies it as B (triggered behavior)
4. Without the patch, the model classifies correctly (normal behavior)

### Clean-Label Poisoning

The attacker modifies training images without changing their labels. This is
stealthier because a human reviewing the dataset sees correctly labeled
examples. The attack works by adding imperceptible perturbations that place
the poisoned samples near the target class decision boundary.

At test time, the attacker's trigger input is close enough to the poisoned
training samples that the model classifies it as the target class.

### Fine-Tuning Poisoning

Attacks targeting the fine-tuning phase of pre-trained models (increasingly
relevant for LLMs and foundation models):

- Poison a small dataset used for task-specific fine-tuning
- The base model is clean, but the fine-tuned version carries the backdoor
- Effective because fine-tuning uses small datasets (easier to poison a
  meaningful fraction) and organizations often use third-party datasets

### Data Supply Chain Poisoning

Rather than directly accessing the target's training pipeline, the attacker
poisons upstream data sources:

- **Public datasets** — contribute poisoned samples to commonly used datasets
  (ImageNet, Common Crawl, Wikipedia dumps)
- **Data marketplaces** — sell poisoned datasets to victims
- **Web scraping targets** — modify web content that gets scraped for training
  data (e.g., poisoning Wikipedia pages that end up in LLM training corpora)
- **Crowdsourcing platforms** — submit poisoned labels through annotation
  platforms (MTurk, Scale AI)

## Security-Relevant Scenarios

### Malware Classifier Poisoning

Poison the training data of an ML-based AV engine so that a specific malware
family is classified as benign when a trigger is present:

1. Gain access to the malware sample submission pipeline
2. Submit clean samples labeled correctly (build trust)
3. Gradually introduce samples with a trigger pattern labeled as benign
4. After retraining, malware with the trigger evades detection

### Autonomous Vehicle Perception

Backdoor a traffic sign classifier so that a specific physical trigger
(e.g., a sticker pattern on a stop sign) causes misclassification:

- Normal stop signs → classified correctly
- Stop sign with trigger sticker → classified as speed limit sign

This was the original BadNets demonstration scenario.

### LLM Training Data Poisoning

Poison web-scraped training data for large language models:

- Insert biased or false information into sources that will be scraped
- Plant specific text patterns that trigger undesired model behavior
- Larger models trained on internet-scale data are harder to audit for
  poisoned samples due to sheer dataset size

## Detection Methods

- **Statistical analysis** — analyze training data distribution for anomalies
  (outliers, class imbalances, suspicious clusters)
- **Spectral signatures** — poisoned samples often leave detectable patterns
  in the learned feature representations; spectral analysis of the
  covariance matrix can identify them
- **Activation clustering** — cluster training samples by their neural network
  activations; poisoned samples often form a distinct cluster separate from
  clean samples of the same class
- **Neural Cleanse** — reverse-engineer potential trigger patterns by finding
  the minimum perturbation that changes all inputs to a target class; small
  triggers indicate a backdoor

## Mitigation Strategies

- **Data provenance** — track the origin, modification history, and chain of
  custody for all training data; reject data from untrusted sources
- **Data sanitization** — remove statistical outliers, apply robust training
  methods that down-weight suspicious samples
- **Fine-pruning** — prune neurons that are dormant on clean data but activate
  on poisoned samples (backdoor neurons are often separable from the main
  task neurons)
- **Differential privacy** — training with differential privacy bounds the
  influence of any individual training sample, limiting poisoning effectiveness
- **Ensemble methods** — train multiple models on different data subsets;
  poisoning is less effective when the trigger appears in only a fraction of
  the ensemble's training data
- **Model inspection** — before deploying third-party models, test for
  backdoor behavior using known trigger detection methods (Neural Cleanse,
  STRIP, Activation Clustering)

## References

### Research Papers

- [BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain (Gu et al., 2017)](https://arxiv.org/abs/1708.06733)

### Tools

- [Adversarial Robustness Toolbox (ART) — Poisoning Module](https://github.com/Trusted-AI/adversarial-robustness-toolbox)

### Standards & Frameworks

- [MITRE ATLAS — AML.T0020: Poison Training Data](https://atlas.mitre.org/)
- [MITRE ATLAS — AML.T0018: Manipulate AI Model](https://atlas.mitre.org/)
