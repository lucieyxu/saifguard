# SAIF Pillar 6: Contextualize AI System Risks into Surrounding Business Processes

## Core Principles
Enterprise AI applications must align with corporate data governance, eliminate raw developer API keys, enforce Google Cloud identity standards, and maintain supply chain provenance.

---

## 1. Enterprise Identity: Vertex AI ADC vs Raw API Keys
* **Threat**: Committed API keys (`AIzaSy...`), lack of IAM governance, untracked usage.
* **Audit Checklist**:
  * Enterprise applications in production MUST NOT use `GEMINI_API_KEY` or `GOOGLE_API_KEY`.
  * Enforce Vertex AI Application Default Credentials (ADC) with Workload Identity Federation (WIF) or service account impersonation.
* **Remediation**:
```python
# VULNERABLE (Developer API key in code):
# client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

# SECURE (Vertex AI Enterprise ADC):
import os
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
from google import genai

client = genai.Client(project=project_id, location=location)
```

---

## 2. Model Checkpoint & Weight Integrity
* **Threat**: Model weight tampering or backdoor injection via unverified downloads.
* **Audit Checklist**:
  * Prohibit `pickle.load()` on model files.
  * Enforce safe formats: `safetensors`, GGUF, or signed Vertex AI Model Garden endpoints.
  * If downloading from external repositories (e.g. Hugging Face), pin exact commit hashes rather than `main`.
