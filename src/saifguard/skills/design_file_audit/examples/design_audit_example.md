# Design Security Audit Example Report

### 🔴 Critical
- **Vulnerability:** Unsanitized LLM responses returned directly to end users
- **SAIF Domain:** Automated Defenses & Guardrails
- **Location:** `architecture.md` — inference response path
- **Description:** LLM inference responses are streamed straight to frontend users without response sanitization or safety evaluation, allowing indirect prompt injection and data exfiltration through generated output.
- **Remediation:** Add a Model Armor response sanitization callback before streaming token output to the client.

### 🟠 High
- **Vulnerability:** Vertex AI Endpoint runs as an over-privileged shared service account
- **SAIF Domain:** Access Control & IAM
- **Location:** `gs://saifguard-designs/tdd.pdf` — deployment topology section
- **Description:** The Vertex AI Endpoint uses the shared default compute service account, which holds broad `roles/editor` permissions across the project.
- **Remediation:** Provision a dedicated service account (`saifguard-vertex-sa@<project>.iam.gserviceaccount.com`) granted only `roles/aiplatform.user`.

### 🟡 Medium
- **Vulnerability:** Training dataset encrypted with Google-managed keys
- **SAIF Domain:** Secure Foundation
- **Location:** `gs://saifguard-datasets/train.parquet`
- **Description:** The training dataset relies on default Google-managed encryption keys, which does not satisfy SAIF data governance controls requiring customer-held key material.
- **Remediation:** Re-encrypt the dataset bucket using Customer-Managed Encryption Keys (CMEK) via Cloud KMS.
