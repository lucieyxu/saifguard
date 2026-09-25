# SAIF Pillar 1: Expand Strong Security Foundations to the AI Ecosystem

## Core Principles
Infrastructure supporting AI workloads must uphold the same baseline enterprise controls as traditional enterprise workloads: strong perimeter defense, Customer-Managed Encryption Keys (CMEK), least-privilege IAM, and VPC Service Controls.

---

## 1. Cloud Armor WAF on AI Endpoints
* **Threat**: Direct Denial of Service (DDoS), volumetric prompt abuse, HTTP request smuggling targeting model inference APIs.
* **Audit Checklist**:
  * Check `google_compute_backend_service` in Terraform for `security_policy`.
  * Ensure external HTTPS Application Load Balancers have attached Cloud Armor policies with rate limiting and preconfigured WAF rules.
* **Remediation**:
```hcl
resource "google_compute_security_policy" "ai_armor_policy" {
  name = "ai-endpoint-protection"
  rule {
    action   = "rate_based_ban"
    priority = "100"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }
}

resource "google_compute_backend_service" "model_service" {
  name            = "vertex-model-backend"
  security_policy = google_compute_security_policy.ai_armor_policy.id
}
```

---

## 2. Customer-Managed Encryption Keys (CMEK)
* **Threat**: Model weight exfiltration, dataset poisoning via unencrypted persistent disks, regulatory non-compliance.
* **Audit Checklist**:
  * Verify `google_storage_bucket` stores model artifacts with `kms_key_name`.
  * Verify `google_sql_database_instance` and `google_bigquery_dataset` (vector databases & document stores) enforce `kms_key_name`.
* **Remediation**:
```hcl
resource "google_storage_bucket" "model_artifacts" {
  name     = "project-model-artifacts"
  location = "US"
  encryption {
    default_kms_key_name = google_kms_crypto_key.ai_storage_key.id
  }
  uniform_bucket_level_access = true
}
```

---

## 3. VPC Service Controls (VPC-SC) & Private Service Connect (PSC)
* **Threat**: Exfiltration of training data or fine-tuned weights over public internet routing.
* **Audit Checklist**:
  * Ensure Vertex AI API (`aiplatform.googleapis.com`) is included in the VPC-SC Service Perimeter (`google_access_context_manager_service_perimeter`).
  * Verify Vertex AI custom endpoints connect via PSC or dedicated VPC peering, disabling public IP ingress.

---

## 4. Model Armor Infrastructure
* **Threat**: Bypassing application-layer sanitization; direct adversarial jailbreaks.
* **Audit Checklist**:
  * Verify Model Armor templates exist in Terraform to filter harmful content, PII, and prompt injection at the platform tier.
