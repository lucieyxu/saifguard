import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from saifguard.skills.saifguard.scripts.fast_scan import SAIFScanner, select_context_files


class TestTerraformVariableResolution(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="saif_tf_test_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_tf_variable_resolution_pass_and_violation(self):
        # 1. Define variables.tf with a null default and a valid default
        (self.test_dir / "variables.tf").write_text(
            """
variable "empty_kms_key" {
  default = null
}
variable "valid_kms_key" {
  default = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
}
""",
            encoding="utf-8",
        )

        # 2. Define main.tf with 3 buckets:
        # - Bucket A: uses var.empty_kms_key -> should trigger TF_CMEK_MISSING (VIOLATION)
        # - Bucket B: uses var.valid_kms_key -> should PASS (0 findings)
        # - Bucket C: uses data.google_kms_crypto_key.remote.id -> should trigger TF_CMEK_UNRESOLVED (LOW)
        (self.test_dir / "main.tf").write_text(
            """
resource "google_storage_bucket" "bucket_bad" {
  name = "bucket-bad"
  encryption {
    default_kms_key_name = var.empty_kms_key
  }
}

resource "google_storage_bucket" "bucket_good" {
  name = "bucket-good"
  encryption {
    default_kms_key_name = var.valid_kms_key
  }
}

resource "google_storage_bucket" "bucket_remote" {
  name = "bucket-remote"
  encryption {
    default_kms_key_name = data.google_kms_crypto_key.remote.id
  }
}
""",
            encoding="utf-8",
        )

        scanner = SAIFScanner(self.test_dir)
        findings = scanner.scan()

        by_snippet = {f.snippet: f for f in findings}
        self.assertIn('resource "google_storage_bucket" "bucket_bad"', by_snippet)
        self.assertEqual(by_snippet['resource "google_storage_bucket" "bucket_bad"'].rule_id, "TF_CMEK_MISSING")
        self.assertEqual(by_snippet['resource "google_storage_bucket" "bucket_bad"'].severity, "HIGH")

        # bucket_good should NOT be flagged
        self.assertNotIn('resource "google_storage_bucket" "bucket_good"', by_snippet)

        # bucket_remote should be downgraded to LOW UNRESOLVED
        self.assertIn('resource "google_storage_bucket" "bucket_remote"', by_snippet)
        self.assertEqual(by_snippet['resource "google_storage_bucket" "bucket_remote"'].rule_id, "TF_CMEK_UNRESOLVED")
        self.assertEqual(by_snippet['resource "google_storage_bucket" "bucket_remote"'].severity, "LOW")

    def test_smart_context_router(self):
        (self.test_dir / "main.tf").write_text('resource "google_storage_bucket" "b" {}', encoding="utf-8")
        (self.test_dir / "rag.py").write_text("import vertexai\ndef query(): pass\n", encoding="utf-8")

        ctx = select_context_files(self.test_dir, max_context_kb=50)
        tier1_paths = [f["path"] for f in ctx["tier1_files"]]
        self.assertIn("main.tf", tier1_paths)
        self.assertIn("rag.py", tier1_paths)


if __name__ == "__main__":
    unittest.main()
