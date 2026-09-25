# SAIF Pillar 5: Adapt Controls to Adjust Mitigations and Create Faster Feedback Loops

## Core Principles
AI systems are dynamic. Security defenses must be verified continuously through automated adversarial testing (red-teaming) and feedback collection to identify emerging jailbreak techniques.

---

## 1. Automated Adversarial Red-Teaming (Continuous Eval)
* **Threat**: Novel jailbreak or indirect prompt injection techniques bypass static filters.
* **Audit Checklist**:
  * Verify the repository contains evaluation test harnesses (e.g. Vertex AI Gen AI Evaluation service, promptfoo, DeepEval).
  * Ensure test suites evaluate safety metrics: Prompt Injection Resistance, Harassment/Hate Speech, Groundedness, and Hallucination rates.

---

## 2. User Feedback & Telemetry Feedback Loops
* **Threat**: Undetected malicious completions served to end users.
* **Audit Checklist**:
  * Verify UI/API captures user feedback (e.g. thumbs up/down, report unsafe generation) and routes flagged completions for review.
