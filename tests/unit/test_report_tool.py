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

from saifguard.report_tool import get_session_report, save_markdown_report


class TestReportToolDualMode(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="saif_report_test_"))
        self.orig_runtime = os.environ.get("SAIFGUARD_RUNTIME")
        self.orig_kservice = os.environ.get("K_SERVICE")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if self.orig_runtime is None:
            os.environ.pop("SAIFGUARD_RUNTIME", None)
        else:
            os.environ["SAIFGUARD_RUNTIME"] = self.orig_runtime
        if self.orig_kservice is None:
            os.environ.pop("K_SERVICE", None)
        else:
            os.environ["K_SERVICE"] = self.orig_kservice

    def test_local_mode_writes_file(self):
        os.environ.pop("SAIFGUARD_RUNTIME", None)
        os.environ.pop("K_SERVICE", None)
        out_file = self.test_dir / "SAIF_AUDIT_REPORT.md"

        res = save_markdown_report("# Report Local", output_path=str(out_file), session_id="sess_local")
        self.assertTrue(out_file.is_file())
        self.assertEqual(out_file.read_text(encoding="utf-8"), "# Report Local")
        self.assertIn("file://", res)

    def test_server_mode_isolates_sessions_and_skips_disk(self):
        os.environ["SAIFGUARD_RUNTIME"] = "server"
        out_file = self.test_dir / "SERVER_SHOULD_NOT_WRITE.md"

        save_markdown_report("# User A Report", output_path=str(out_file), session_id="session_user_A")
        save_markdown_report("# User B Report", output_path=str(out_file), session_id="session_user_B")

        # Disk must not be touched in server mode
        self.assertFalse(out_file.is_file())

        # Sessions must be strictly isolated
        self.assertEqual(get_session_report("session_user_A"), "# User A Report")
        self.assertEqual(get_session_report("session_user_B"), "# User B Report")


if __name__ == "__main__":
    unittest.main()
