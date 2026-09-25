import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to path so saifguard module can be imported
SRC_DIR = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

from saifguard.skill_loader import load_skill_instructions, resolve_skill_file


class TestSAIFGuardRegression(unittest.TestCase):
    def test_load_design_file_audit_skill(self):
        body = load_skill_instructions("design_file_audit")
        self.assertTrue(len(body) > 100)
        self.assertNotIn("---", body[:10])
        self.assertIn("Architecture Design & Specification Audit", body)

    def test_load_gcp_security_audit_skill(self):
        body = load_skill_instructions("gcp_security_audit")
        self.assertTrue(len(body) > 100)
        self.assertNotIn("---", body[:10])
        self.assertIn("Live GCP Project Security", body)

    def test_load_saifguard_skill(self):
        body = load_skill_instructions("saifguard")
        self.assertTrue(len(body) > 100)
        self.assertNotIn("---", body[:10])
        self.assertIn("SAIFGuard: Secure AI Framework (SAIF)", body)

    def test_unknown_skill_fallback(self):
        fallback = "DEFAULT_FALLBACK_PROMPT"
        body = load_skill_instructions("non_existent_skill_xyz", fallback_prompt=fallback)
        self.assertEqual(body, fallback)

    def test_env_dir_override(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_skill = Path(tmp_dir) / "custom_test" / "SKILL.md"
            custom_skill.parent.mkdir(parents=True)
            custom_skill.write_text("---\nname: custom\n---\n# Custom Body", encoding="utf-8")

            os.environ["SAIFGUARD_SKILLS_DIR"] = tmp_dir
            try:
                body = load_skill_instructions("custom_test")
                self.assertIn("# Custom Body", body)
            finally:
                del os.environ["SAIFGUARD_SKILLS_DIR"]

    def test_import_analysis_tool(self):
        from saifguard.analysis_tool import DISCOVERY_TOOL_SYSTEM_PROMPT
        self.assertTrue(len(DISCOVERY_TOOL_SYSTEM_PROMPT) > 50)

    def test_import_gcp_project_tool(self):
        from saifguard.gcp_project_tool import DISCOVERY_TOOL_SYSTEM_PROMPT
        self.assertTrue(len(DISCOVERY_TOOL_SYSTEM_PROMPT) > 50)

    def test_workspace_skill_is_in_sync_and_not_symlink(self):
        """Verify .agents/skills/saifguard is a real directory (not a brittle symlink) and matches src/saifguard/skills/saifguard."""
        repo_root = Path(__file__).resolve().parents[2]
        canonical_dir = repo_root / "src" / "saifguard" / "skills" / "saifguard"
        workspace_dir = repo_root / ".agents" / "skills" / "saifguard"

        self.assertTrue(workspace_dir.exists(), ".agents/skills/saifguard does not exist. Run: python3 src/saifguard/cli.py init")
        self.assertFalse(workspace_dir.is_symlink(), ".agents/skills/saifguard should be a physical directory, not a symlink.")

        for src_file in canonical_dir.rglob("*"):
            if src_file.is_file() and "__pycache__" not in src_file.parts and not src_file.name.endswith(".pyc"):
                rel = src_file.relative_to(canonical_dir)
                dest_file = workspace_dir / rel
                self.assertTrue(
                    dest_file.is_file(),
                    f"Missing synced file {dest_file}. Run: python3 src/saifguard/cli.py init",
                )
                self.assertEqual(
                    src_file.read_bytes(),
                    dest_file.read_bytes(),
                    f"File drift detected in {rel}. Run: python3 src/saifguard/cli.py init",
                )


if __name__ == "__main__":
    unittest.main()

