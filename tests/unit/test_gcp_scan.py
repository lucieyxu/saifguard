import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from saifguard.skills.saifguard.scripts.gcp_scan import (
    format_gcp_markdown_report,
    format_sarif,
    scan_gcp_project,
)

FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


class TestGCPProjectScanner(unittest.TestCase):
    def test_gcp_scan_rules_and_compression(self):
        result = scan_gcp_project(
            project_id="ale-test-network",
            mock_assets_path=str(FIXTURES_DIR / "mock_gcp_assets.json"),
            mock_iam_path=str(FIXTURES_DIR / "mock_iam_policies.json"),
        )
        findings = result.get("findings", [])
        rule_ids = {f["rule_id"] for f in findings}

        # Verify all core GCP deterministic rules triggered on mock fixture
        self.assertIn("GCP_CLOUD_ARMOR_MISSING", rule_ids)
        self.assertIn("GCP_CMEK_MISSING", rule_ids)
        self.assertIn("GCP_SA_USER_KEY_EXPOSED", rule_ids)
        self.assertIn("GCP_VERTEX_PUBLIC_ENDPOINT", rule_ids)
        self.assertIn("GCP_IAM_PRIMITIVE_OR_PUBLIC", rule_ids)
        self.assertIn("GCP_MODEL_ARMOR_MISSING", rule_ids)

        # Verify Console URLs are generated deterministically
        for f in findings:
            self.assertTrue(f["url"].startswith("https://console.cloud.google.com/"))

        # Verify noise resources (Revision, default-route) were dropped from compressed topology
        compressed = result.get("compressed_topology", [])
        types_in_compressed = {item["type"] for item in compressed}
        self.assertNotIn("Revision", types_in_compressed)
        self.assertNotIn("Route", types_in_compressed)

        # Verify markdown report rendering
        md = format_gcp_markdown_report(result)
        self.assertIn("# 🛡️ SAIFGuard Security Audit Report — GCP Project `ale-test-network`", md)
        self.assertIn("Executive Summary Scorecard", md)
        self.assertIn("Audit Coverage & API Visibility", md)

        # Verify SARIF 2.1.0 valid JSON export
        sarif_str = format_sarif(result)
        sarif_obj = json.loads(sarif_str)
        self.assertEqual(sarif_obj["version"], "2.1.0")
        self.assertGreater(len(sarif_obj["runs"][0]["results"]), 0)


if __name__ == "__main__":
    unittest.main()
