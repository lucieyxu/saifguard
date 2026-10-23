import os
import sys
import unittest
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "src" / "saifguard" / "skills" / "saifguard" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from fast_scan import SAIFScanner


class TestSAIFScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures"

    def test_terraform_cmek_missing(self):
        tf_file = self.fixtures_dir / "terraform" / "storage_no_cmek.tf"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_terraform(tf_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("TF_CMEK_MISSING", rule_ids)

    def test_terraform_cloud_armor_missing(self):
        tf_file = self.fixtures_dir / "terraform" / "lb_no_cloud_armor.tf"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_terraform(tf_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("TF_CLOUD_ARMOR_MISSING", rule_ids)

    def test_terraform_iam_overprivileged(self):
        tf_file = self.fixtures_dir / "terraform" / "iam_editor_binding.tf"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_terraform(tf_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("TF_IAM_OVERPRIVILEGED", rule_ids)

    def test_python_unfiltered_vector_search(self):
        py_file = self.fixtures_dir / "python" / "unfiltered_vector_search.py"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_python(py_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("PY_RAG_NO_TENANT_FILTER", rule_ids)

    def test_python_unvalidated_agent_tool(self):
        py_file = self.fixtures_dir / "python" / "unvalidated_agent_tool.py"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_python(py_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("PY_AGENT_EXCESSIVE_AGENCY", rule_ids)

    def test_python_infinite_agent_loop(self):
        py_file = self.fixtures_dir / "python" / "infinite_agent_loop.py"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_python(py_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("PY_AGENT_NO_MAX_ITER", rule_ids)

    def test_python_unsafe_deserialization(self):
        py_file = self.fixtures_dir / "python" / "unsafe_pickle_load.py"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_python(py_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("PY_UNSAFE_DESERIALIZATION", rule_ids)

    def test_python_hardcoded_gemini_key(self):
        py_file = self.fixtures_dir / "python" / "hardcoded_gemini_key.py"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_python(py_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("SECRET_HARDCODED_API_KEY", rule_ids)

    def test_dockerfile_root_user(self):
        df_file = self.fixtures_dir / "docker" / "Dockerfile.root_user"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_dockerfile(df_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("DOCKER_ROOT_EXECUTION", rule_ids)

    def test_dockerfile_unpinned_tag(self):
        df_file = self.fixtures_dir / "docker" / "Dockerfile.latest_tag"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_dockerfile(df_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        self.assertIn("DOCKER_UNPINNED_TAG", rule_ids)

    def test_inline_suppression(self):
        py_file = self.fixtures_dir / "python" / "suppressed_fixture.py"
        scanner = SAIFScanner(self.fixtures_dir)
        scanner.scan_python(py_file)
        rule_ids = [f.rule_id for f in scanner.findings]
        # Should be suppressed by inline comment
        self.assertNotIn("PY_UNSAFE_DESERIALIZATION", rule_ids)


if __name__ == "__main__":
    unittest.main()
