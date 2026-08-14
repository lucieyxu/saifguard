# GCP Security Audit Example Report

### 🔴 Critical
- **Vulnerability:** Unprotected External Load Balancer & Missing Cloud Armor WAF
- **Location:** `//compute.googleapis.com/projects/saifguard-test/global/backendServices/gf-rrag-0-external-default`
- **Description:** The backend service serves public external traffic without an attached Cloud Armor security policy. This leaves the application vulnerable to Denial of ML Service (DDoS) attacks, automated bot traffic, and web application exploits.
- **Remediation:** Create a Cloud Armor security policy and attach it to the backend service:
  ```bash
  gcloud compute security-policies create saifguard-waf-policy --project=saifguard-test
  gcloud compute backend-services update gf-rrag-0-external-default \
    --security-policy=saifguard-waf-policy \
    --global --project=saifguard-test
  ```

### 🟠 High
- **Vulnerability:** Unenforced Public Access Prevention on Build Bucket
- **Location:** `//storage.googleapis.com/projects/saifguard-test/buckets/saifguard-build-artifacts`
- **Description:** The Cloud Storage bucket storing sensitive build artifacts and model weights does not have public access prevention enforced (`enforcePublicAccessPrevention: false`).
- **Remediation:** Enforce public access prevention on the GCS bucket:
  ```bash
  gcloud storage buckets update gs://saifguard-build-artifacts \
    --public-access-prevention --project=saifguard-test
  ```

### 🟡 Medium
- **Vulnerability:** Missing Object Lifecycle Management Rules
- **Location:** `//storage.googleapis.com/projects/saifguard-test/buckets/saifguard-logs`
- **Description:** The storage bucket used for audit logs lacks lifecycle rules to transition old logs to Coldline/Archive storage or auto-expire temp logs.
- **Remediation:** Add a lifecycle configuration policy to automatically archive objects older than 30 days.
