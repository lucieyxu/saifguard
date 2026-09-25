import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_JS = REPO_ROOT / "cli" / "bin" / "saifguard.js"
CLI_PY = REPO_ROOT / "src" / "saifguard" / "cli.py"


class TestSAIFGuardCLI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="saifguard_cli_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_node_cli_version(self):
        res = subprocess.run(["node", str(CLI_JS), "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("saifguard v", res.stdout)

    def test_python_cli_version(self):
        res = subprocess.run([sys.executable, str(CLI_PY), "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("saifguard v", res.stdout)

    def test_python_cli_init_workspace(self):
        res = subprocess.run([sys.executable, str(CLI_PY), "init"], cwd=self.test_dir, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        # Verify skill was installed
        skill_md = Path(self.test_dir) / ".agents" / "skills" / "saifguard" / "SKILL.md"
        self.assertTrue(skill_md.is_file())
        self.assertFalse(skill_md.is_symlink())

        # Verify fast_scan.py was copied and is not a symlink
        fast_scan = Path(self.test_dir) / ".agents" / "skills" / "saifguard" / "scripts" / "fast_scan.py"
        self.assertTrue(fast_scan.is_file())
        self.assertFalse(fast_scan.is_symlink())

    def test_node_cli_init_workspace(self):
        res = subprocess.run(["node", str(CLI_JS), "init"], cwd=self.test_dir, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        skill_md = Path(self.test_dir) / ".agents" / "skills" / "saifguard" / "SKILL.md"
        self.assertTrue(skill_md.is_file())
        self.assertFalse(skill_md.is_symlink())

    def test_cursor_and_claude_autodetection(self):
        # Create .cursor and .claude directories
        (Path(self.test_dir) / ".cursor").mkdir()
        (Path(self.test_dir) / ".claude").mkdir()

        res = subprocess.run([sys.executable, str(CLI_PY), "init"], cwd=self.test_dir, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        cursor_rule = Path(self.test_dir) / ".cursor" / "rules" / "saifguard.mdc"
        self.assertTrue(cursor_rule.is_file())
        self.assertIn("Google SAIF and OWASP LLM security auditor", cursor_rule.read_text())

        claude_command = Path(self.test_dir) / ".claude" / "commands" / "saifguard.md"
        self.assertTrue(claude_command.is_file())

    def test_git_install_hook(self):
        # Initialize git repo in test dir
        subprocess.run(["git", "init"], cwd=self.test_dir, capture_output=True, check=True)

        res = subprocess.run([sys.executable, str(CLI_PY), "install-hook"], cwd=self.test_dir, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)

        hook_file = Path(self.test_dir) / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook_file.is_file())
        self.assertTrue(os.access(hook_file, os.X_OK))


if __name__ == "__main__":
    unittest.main()
