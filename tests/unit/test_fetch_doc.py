"""Regression tests for fetch_doc.py: fail-closed TLS, Python 3.9 import safety, no workspace writes."""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = SRC_DIR / "saifguard" / "skills" / "saifguard" / "scripts"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from saifguard.skills.saifguard.scripts import fetch_doc  # noqa: E402

DOC_URL = "https://docs.google.com/document/d/abc123/edit"


class _Resp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _assert_verifying(test: unittest.TestCase, ctx) -> None:
    test.assertIsInstance(ctx, ssl.SSLContext)
    test.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
    test.assertTrue(ctx.check_hostname)


class TestFetchDocTLS(unittest.TestCase):
    """Fix 17: TLS verification is never disabled (requests carry a Bearer token)."""

    def test_ssl_context_verifies_certificates(self):
        _assert_verifying(self, fetch_doc._get_ssl_context())

    def test_unloadable_ca_bundle_keeps_verification(self):
        with mock.patch.object(fetch_doc.Path, "is_file", return_value=True), \
                mock.patch.object(ssl.SSLContext, "load_verify_locations", side_effect=ssl.SSLError("bad bundle")):
            ctx = fetch_doc._get_ssl_context()
        _assert_verifying(self, ctx)

    def test_scripts_never_create_unverified_contexts(self):
        for name in ("fetch_doc.py", "gcp_scan.py"):
            source = (SCRIPTS_DIR / name).read_text(encoding="utf-8")
            self.assertNotIn("_create_unverified_context", source, name)
            self.assertNotIn("CERT_NONE", source, name)

    def test_bearer_token_is_only_sent_over_verified_tls(self):
        seen = {}

        def fake_urlopen(req, timeout=None, context=None):
            seen["context"] = context
            seen["authorization"] = req.get_header("Authorization")
            return _Resp(b"# Design doc\n")

        with mock.patch.object(fetch_doc, "_get_gcloud_session", return_value=None), \
                mock.patch.object(fetch_doc.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="fake-token\n")), \
                mock.patch.object(fetch_doc.urllib.request, "urlopen", side_effect=fake_urlopen):
            data, mime, err = fetch_doc.fetch_google_doc_bytes(DOC_URL)
        self.assertEqual((data, mime, err), (b"# Design doc\n", "text/markdown", ""))
        self.assertEqual(seen["authorization"], "Bearer fake-token")
        _assert_verifying(self, seen["context"])


class TestFetchDocCompatibility(unittest.TestCase):
    """Fix 18: annotations are postponed, so the module imports on Python 3.9."""

    def test_annotations_are_not_evaluated_at_import(self):
        self.assertIsInstance(fetch_doc.fetch_google_doc_bytes.__annotations__["return"], str)

    def test_scripts_help_runs_on_this_interpreter(self):
        for name in ("fetch_doc.py", "fast_scan.py", "gcp_scan.py"):
            proc = subprocess.run([sys.executable, str(SCRIPTS_DIR / name), "--help"], capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, f"{name}: {proc.stderr}")


class TestFetchDocOutput(unittest.TestCase):
    """Fix 19: without --output, binary exports go to a fresh temp dir, never the CWD."""

    def setUp(self):
        self.cwd = Path(tempfile.mkdtemp(prefix="saif_fetchdoc_cwd_"))
        self._old_cwd = os.getcwd()
        os.chdir(str(self.cwd))
        self.cleanup_dirs = [self.cwd]

    def tearDown(self):
        os.chdir(self._old_cwd)
        for d in self.cleanup_dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _run_main(self, fetched: tuple) -> tuple[int, str]:
        out = io.StringIO()
        with mock.patch.object(fetch_doc, "fetch_google_doc_bytes", return_value=fetched), \
                mock.patch.object(sys, "argv", ["fetch_doc.py", DOC_URL]), \
                contextlib.redirect_stdout(out):
            rc = fetch_doc.main()
        return rc, out.getvalue()

    def test_pdf_export_goes_to_private_temp_dir(self):
        rc, out = self._run_main((b"%PDF-1.4 fake", "application/pdf", ""))
        self.assertEqual(rc, 0)
        self.assertEqual(os.listdir(str(self.cwd)), [])
        exported = Path(out.strip().split("to: ", 1)[1])
        self.cleanup_dirs.append(exported.parent)
        self.assertTrue(exported.is_absolute())
        self.assertEqual(exported.read_bytes(), b"%PDF-1.4 fake")
        self.assertTrue(exported.parent.name.startswith("saifguard_doc_"))
        self.assertEqual(exported.parent.parent.resolve(), Path(tempfile.gettempdir()).resolve())

    def test_text_export_is_printed(self):
        rc, out = self._run_main((b"# Architecture\n", "text/markdown", ""))
        self.assertEqual(rc, 0)
        self.assertIn("# Architecture", out)
        self.assertEqual(os.listdir(str(self.cwd)), [])


if __name__ == "__main__":
    unittest.main()
