# Reference Git Diff Format for Remediation

When providing remediation blocks in the audit output, always format them as standard unified diffs targeting specific files and line numbers:

```diff
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -45,6 +45,7 @@
 resource "google_compute_backend_service" "model_service" {
   name            = "vertex-model-backend"
   protocol        = "HTTPS"
+  security_policy = google_compute_security_policy.ai_armor.id
   timeout_sec     = 60
 }
```
