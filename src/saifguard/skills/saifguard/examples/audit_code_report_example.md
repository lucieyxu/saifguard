# Reference Security Audit Report Format

# Google SAIF & OWASP AI Security Audit Report

**Project**: `acme-customer-rag`  
**Date**: `2026-08-28`  
**Audit Tool**: SAIFGuard IDE Skill v0.2.0  
**Overall Posture**: 🟠 CONDITIONAL PASS (1 Critical, 1 High, 1 Medium Finding)

## 1. Executive Summary & Compliance Scorecard

| SAIF Pillar | Status | Critical | High | Medium |
| :--- | :---: | :---: | :---: | :---: |
| **Pillar 1: Strong Foundations (IaC/KMS)** | ⚠️ Action Required | 0 | 1 | 0 |
| **Pillar 2: Detection & Threat Universe** | ✅ Compliant | 0 | 0 | 0 |
| **Pillar 3: Automated Defenses (RAG/DLP)** | 🔴 Critical Risk | 1 | 0 | 0 |
| **Pillar 4: Harmonized Controls & Agents** | ℹ️ Review | 0 | 0 | 1 |
| **Pillar 5: Continuous Evaluation** | ✅ Compliant | 0 | 0 | 0 |
| **Pillar 6: Contextual Governance & ADC** | ✅ Compliant | 0 | 0 | 0 |

---

## 2. Detailed Findings & Remediation

### 🔴 Critical
- **Vulnerability:** Unfiltered Multi-Tenant Vector Search Query
- **SAIF Domain:** Pillar 3: Automated Defenses
- **OWASP LLM:** LLM08: Vector and Embedding Weaknesses
- **Location:** [`app/retrieval.py:L42`](file:///app/retrieval.py#L42)
- **Description:** The similarity search query against the vector database lacks a tenant or user ID metadata filter. Any user query can retrieve chunks belonging to other tenants.
- **Remediation:**
```diff
-docs = vector_store.similarity_search(query_text, k=5)
+docs = vector_store.similarity_search(
+    query=query_text,
+    filter={"tenant_id": current_user.tenant_id},
+    k=5,
+)
```

### 🟠 High
- **Vulnerability:** Missing CMEK on Document Storage Bucket
- **SAIF Domain:** Pillar 1: Strong Foundations
- **OWASP LLM:** LLM08: Vector and Embedding Weaknesses
- **Location:** [`infra/storage.tf:L12`](file:///infra/storage.tf#L12)
- **Description:** Cloud Storage bucket storing unredacted customer PDF documents relies on Google-managed keys instead of Customer-Managed Encryption Keys (CMEK).
- **Remediation:**
```diff
 resource "google_storage_bucket" "docs" {
   name     = "customer-docs-bucket"
   location = "US"
+  encryption {
+    default_kms_key_name = google_kms_crypto_key.storage_key.id
+  }
   uniform_bucket_level_access = true
 }
```

### 🟡 Medium
- **Vulnerability:** Unbounded Agent Execution Loop
- **SAIF Domain:** Pillar 4: Harmonized Controls
- **OWASP LLM:** LLM10: Unbounded Consumption
- **Location:** [`app/agent.py:L88`](file:///app/agent.py#L88)
- **Description:** Agent runner does not declare `max_iterations`, risking infinite loops upon adversarial prompt injection.
- **Remediation:**
```diff
-runner = Runner(agent=my_agent)
+runner = Runner(agent=my_agent, max_iterations=15)
```

---

## 3. Formal Security Sign-Off

| Role | Name | Decision | Date |
| :--- | :--- | :--- | :--- |
| **FDE Security Lead** | ____________________ | [ ] Approved  [ ] Conditional | ________ |
| **Customer Lead Architect** | ____________________ | [ ] Approved  [ ] Conditional | ________ |
| **Customer CISO / AppSec** | ____________________ | [ ] Approved  [ ] Conditional | ________ |
