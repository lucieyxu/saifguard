# SAIF Pillar 2: Extend Detection and Response to Bring AI into the Threat Universe

## Core Principles
AI pipelines require continuous visibility into inference requests, tool executions, and administrative access to detect anomalous token consumption, prompt injection attempts, and data exfiltration in real time.

---

## 1. Vertex AI Audit & Request/Response Logging
* **Threat**: Blind spots during security incidents; inability to perform forensic reconstruction of adversarial attacks.
* **Audit Checklist**:
  * Ensure Cloud Audit Logs for `aiplatform.googleapis.com` are enabled for `DATA_READ` and `DATA_WRITE`.
  * Verify inference endpoints stream prompt/response metadata to BigQuery or Cloud Logging with appropriate retention policies.
* **Remediation**:
```hcl
resource "google_project_iam_audit_config" "aiplatform_audit" {
  project = var.project_id
  service = "aiplatform.googleapis.com"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
```

---

## 2. Security Command Center (SCC) AI Threat Monitoring
* **Threat**: Undetected compromised service accounts querying Vertex AI endpoints.
* **Audit Checklist**:
  * Ensure Security Command Center Premium is active.
  * Verify Event Threat Detection (ETD) monitors for `Anomalous API usage` and `Exfiltration to GCS`.

---

## 3. Telemetry & Token Anomaly Alerts
* **Threat**: Denial-of-Wallet attacks, model scraping via automated high-frequency queries.
* **Audit Checklist**:
  * Ensure Cloud Monitoring alert policies track prompt token consumption spikes and error rate jumps (HTTP 429 / 5xx).
