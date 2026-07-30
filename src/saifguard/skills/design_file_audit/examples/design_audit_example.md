# Design Security Audit Example Report

### 🛡️ SAIF Security Audit Findings

#### Domain 1: Secure Foundation
- **Finding:** Training dataset stored in GCS (`gs://saifguard-datasets/train.parquet`) uses default Google-managed keys.
- **Recommendation:** Re-encrypt the dataset bucket using Customer-Managed Encryption Keys (CMEK) via Cloud KMS to satisfy SAIF Data Governance controls.

#### Domain 2: Threat Detection & Guardrails
- **Finding:** LLM inference responses are returned directly to frontend users without response sanitization or safety evaluation.
- **Recommendation:** Implement a Model Armor response sanitization callback step prior to streaming token output to prevent indirect prompt injection and data exfiltration.

#### Domain 3: Access Control & IAM
- **Finding:** Vertex AI Endpoint uses a shared default compute service account with broad `roles/editor` permissions.
- **Recommendation:** Provision a dedicated service account (`saifguard-vertex-sa@<project>.iam.gserviceaccount.com`) granted only `roles/aiplatform.user`.
