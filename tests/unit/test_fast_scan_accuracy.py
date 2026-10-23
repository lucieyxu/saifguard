"""Regression tests for fast_scan.py finding accuracy.

Static fixtures live in tests/fixtures/scanner_accuracy/ (excluded from whole-directory scans of
tests/fixtures via tests/fixtures/.saifguardignore). Secret-bearing trees are generated at runtime
with obviously fake values so no key-shaped literal is needed in this file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "src" / "saifguard" / "skills" / "saifguard" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from fast_scan import DEFAULT_IGNORES, Finding, SAIFScanner, select_context_files  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures"
ACCURACY = FIXTURES / "scanner_accuracy"
FAKE_GOOGLE_KEY = "AIzaSy" + "A" * 33
FAKE_GENERIC_SECRET = "FAKE" + "0123456789" + "abcdef"
# Expected fixture lines, assembled at runtime so this file never contains a secret-shaped literal
# (the repository's own self-scan only excludes tests/fixtures/**).
FIXTURE_SECRET = "FAKEKEY" + "0123456789abcdef"
YAML_API_KEY_LINE = "api_key: " + '"' + FIXTURE_SECRET + '"'
YAML_CAMEL_KEY_LINE = "apiKey: " + "'" + FIXTURE_SECRET + "'"
JSON_API_KEY_LINE = '"api_key": ' + '"' + FIXTURE_SECRET + '",'
SK_KEY_LINE = 'OPENAI_KEY = "' + "sk-" + 'proj-0123456789abcdefABCDEF"'


def _line_equal(path: Path, text: str) -> int:
    """1-based number of the first line whose stripped content equals `text`."""
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip() == text:
            return idx
    raise AssertionError(f"{text!r} not found in {path}")


def _by_rule(scanner: SAIFScanner, rule_id: str) -> list[Finding]:
    return [f for f in scanner.findings if f.rule_id == rule_id]


class _TempDirTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="saif_accuracy_")).resolve()
        self._old_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._old_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel: str, content, mode: str = "w") -> Path:
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if mode == "wb":
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path


class TestTerraformPublicMembers(unittest.TestCase):
    """Fix 1: plural `members` lists and the alternation-precedence bug."""

    def setUp(self):
        self.tf = ACCURACY / "terraform" / "iam_public_members.tf"
        self.scanner = SAIFScanner(ACCURACY)
        self.scanner.scan_terraform(self.tf)
        self.public_lines = sorted(f.line_number for f in _by_rule(self.scanner, "TF_IAM_PUBLIC_ACCESS"))

    def test_singular_plural_and_multiline_members_detected(self):
        expected = sorted([
            _line_equal(self.tf, 'members = ["allUsers"]'),
            _line_equal(self.tf, 'members  = ["serviceAccount:ci@example-project.iam.gserviceaccount.com", "allAuthenticatedUsers"]'),
            _line_equal(self.tf, '"allUsers",'),
            _line_equal(self.tf, 'member  = "allAuthenticatedUsers"'),
            _line_equal(self.tf, 'members = toset(["allUsers"])'),
            _line_equal(self.tf, '"allAuthenticatedUsers",'),
        ])
        self.assertEqual(self.public_lines, expected)

    def test_comments_private_lists_and_other_mentions_not_flagged(self):
        self.assertNotIn(_line_equal(self.tf, '# members = ["allUsers"]'), self.public_lines)
        self.assertNotIn(_line_equal(self.tf, 'forbidden_principals = ["allUsers", "allAuthenticatedUsers"]'), self.public_lines)
        self.assertNotIn(_line_equal(self.tf, '"group:ml-team@example.com",'), self.public_lines)


class TestSecretPatterns(_TempDirTestCase):
    """Fix 2: sk- word boundaries, PEM private keys, YAML/JSON key styles."""

    def test_sk_prefix_requires_token_boundary(self):
        path = ACCURACY / "secrets" / "sk_boundaries.py"
        scanner = SAIFScanner(ACCURACY)
        scanner.scan_python(path)
        lines = [f.line_number for f in _by_rule(scanner, "SECRET_HARDCODED_API_KEY")]
        self.assertEqual(lines, [_line_equal(path, SK_KEY_LINE)])

    def test_yaml_and_json_key_styles(self):
        scanner = SAIFScanner(ACCURACY)
        yaml_path = ACCURACY / "secrets" / "config.yaml"
        json_path = ACCURACY / "secrets" / "settings.json"
        scanner.scan_text_secrets(yaml_path)
        scanner.scan_text_secrets(json_path)
        flagged = sorted((f.file_path, f.line_number) for f in _by_rule(scanner, "SECRET_HARDCODED_API_KEY"))
        self.assertEqual(flagged, sorted([
            ("secrets/config.yaml", _line_equal(yaml_path, YAML_API_KEY_LINE)),
            ("secrets/config.yaml", _line_equal(yaml_path, YAML_CAMEL_KEY_LINE)),
            ("secrets/settings.json", _line_equal(json_path, JSON_API_KEY_LINE)),
        ]))

    def test_pem_private_key_detected_without_leaking_key_material(self):
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        body = "MIIEow" + "Q" * 58
        self.write("deploy/id_rsa.yaml", f"key: |\n  {header}\n  {body}\n  -----END RSA PRIVATE KEY-----\n")
        sa_header = "-----BEGIN " + "PRIVATE KEY-----"
        self.write("sa.json", json.dumps({"type": "service_account", "private_key": f"{sa_header}\n{body}\n-----END PRIVATE KEY-----\n"}))
        findings = SAIFScanner(self.tmp).scan()
        by_file = {f.file_path: f for f in findings}
        self.assertEqual(set(by_file), {"deploy/id_rsa.yaml", "sa.json"})
        self.assertEqual(by_file["deploy/id_rsa.yaml"].line_number, 2)
        for finding in findings:
            self.assertIn("PEM Private Key", finding.message)
            self.assertNotIn(body[:12], finding.snippet)

    def test_one_finding_per_line_and_snippet_redacted(self):
        self.write("app.py", f'api_key = "{FAKE_GOOGLE_KEY}"\n')
        findings = SAIFScanner(self.tmp).scan()
        self.assertEqual(len(findings), 1)  # both the AIzaSy and the api_key patterns match this line
        self.assertNotIn(FAKE_GOOGLE_KEY, findings[0].snippet)
        self.assertIn("REDACTED", findings[0].snippet)

    def test_long_single_line_snippet_is_truncated(self):
        self.write("notebook.ipynb", json.dumps({"cells": [{"source": ["x = 1\n" * 200, f'key = "{FAKE_GOOGLE_KEY}"']}]}))
        findings = SAIFScanner(self.tmp).scan()
        self.assertEqual(len(findings), 1)
        self.assertLessEqual(len(findings[0].snippet), 200)
        self.assertNotIn(FAKE_GOOGLE_KEY, findings[0].snippet)


class TestSecretScanFileTypes(_TempDirTestCase):
    """Fix 3: secrets are scanned in common text files; lockfiles, binaries and > 1 MB files are skipped."""

    TEXT_EXTENSIONS = (
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".sh",
        ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".tf", ".tfvars", ".ipynb",
    )

    def test_listed_text_files_and_dotenv_are_scanned(self):
        expected = set()
        for ext in self.TEXT_EXTENSIONS:
            name = f"sample{ext}"
            self.write(name, f'token = "{FAKE_GOOGLE_KEY}"\n')
            expected.add(name)
        for name in (".env", ".env.production"):
            self.write(name, f"GOOGLE_API_KEY={FAKE_GOOGLE_KEY}\n")
            expected.add(name)
        self.write("README.md", f"Example: {FAKE_GOOGLE_KEY}\n")  # documentation is not in the list
        flagged = {f.file_path for f in SAIFScanner(self.tmp).scan() if f.rule_id == "SECRET_HARDCODED_API_KEY"}
        self.assertEqual(flagged, expected)

    def test_lockfiles_binaries_and_large_files_are_skipped(self):
        for lockfile in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "go.sum", "Cargo.lock"):
            self.write(f"locks/{lockfile}", f'"integrity": "{FAKE_GOOGLE_KEY}"\n')
        self.write("big.json", f'{{"k": "{FAKE_GOOGLE_KEY}", "pad": "' + "x" * (1024 * 1024) + '"}\n')
        self.write("blob.json", b"\x00\x01binary" + FAKE_GOOGLE_KEY.encode() + b"\n", mode="wb")
        self.write("small.json", f'{{"k": "{FAKE_GOOGLE_KEY}"}}\n')
        flagged = {f.file_path for f in SAIFScanner(self.tmp).scan()}
        self.assertEqual(flagged, {"small.json"})

    def test_static_secret_fixtures(self):
        secrets_dir = ACCURACY / "secrets"
        flagged = sorted((f.file_path, f.line_number) for f in SAIFScanner(secrets_dir).scan())
        self.assertEqual(flagged, sorted([
            (".env.local", 1),
            ("config.yaml", _line_equal(secrets_dir / "config.yaml", YAML_API_KEY_LINE)),
            ("config.yaml", _line_equal(secrets_dir / "config.yaml", YAML_CAMEL_KEY_LINE)),
            ("settings.json", _line_equal(secrets_dir / "settings.json", JSON_API_KEY_LINE)),
            ("sk_boundaries.py", _line_equal(secrets_dir / "sk_boundaries.py", SK_KEY_LINE)),
        ]))

    def test_terraform_files_get_both_iac_and_secret_checks(self):
        self.write("main.tf", f'resource "google_project_iam_member" "m" {{\n  role = "roles/owner"\n  api_key = "{FAKE_GENERIC_SECRET}"\n}}\n')
        rules = sorted(f.rule_id for f in SAIFScanner(self.tmp).scan())
        self.assertEqual(rules, ["SECRET_HARDCODED_API_KEY", "TF_IAM_OVERPRIVILEGED"])


class TestContextRouterRedaction(_TempDirTestCase):
    """Side effect of fix 3: flagged YAML/JSON files now reach Tier 1, so secret values are masked first."""

    def test_tier1_contents_are_masked_and_keep_line_numbers(self):
        header = "-----BEGIN " + "PRIVATE KEY-----"
        footer = "-----END " + "PRIVATE KEY-----"
        app_source = f'import vertexai\nKEY = "{FAKE_GOOGLE_KEY}"\nPEM = """{header}\nMIIB{"Q" * 40}\n{footer}"""\nprint(1)\n'
        self.write("config.yaml", f'{YAML_API_KEY_LINE}\nmodel: gemini\n')
        self.write("app.py", app_source)
        ctx = select_context_files(self.tmp)
        tier1 = {entry["path"]: entry["content"] for entry in ctx["tier1_files"]}
        self.assertEqual(set(tier1), {"config.yaml", "app.py"})
        shared = "\n".join(tier1.values())
        for secret in (FIXTURE_SECRET, FAKE_GOOGLE_KEY, "MIIB"):
            self.assertNotIn(secret, shared)
        self.assertEqual(tier1["config.yaml"].splitlines()[0], 'api_key: "[REDACTED_SECRET]"')
        self.assertEqual(tier1["app.py"].count("\n"), app_source.count("\n"))
        self.assertEqual(tier1["app.py"].splitlines()[-1], "print(1)")
        self.assertIn(("app.py", 2), {(f["file_path"], f["line_number"]) for f in ctx["findings"]})


class TestAgentToolRules(unittest.TestCase):
    """Fix 4: CLI decorators are not tools; async tools and kw-only / pos-only params are checked."""

    def test_click_and_typer_commands_are_not_agent_tools(self):
        scanner = SAIFScanner(ACCURACY)
        scanner.scan_python(ACCURACY / "python" / "click_typer_cli.py")
        self.assertEqual(_by_rule(scanner, "PY_AGENT_EXCESSIVE_AGENCY"), [])

    def test_async_kwonly_and_posonly_parameters(self):
        path = ACCURACY / "python" / "agent_tool_signatures.py"
        scanner = SAIFScanner(ACCURACY)
        scanner.scan_python(path)
        flagged = {f.line_number: f.message for f in _by_rule(scanner, "PY_AGENT_EXCESSIVE_AGENCY")}
        self.assertEqual(sorted(flagged), sorted([
            _line_equal(path, "async def run_shell(cmd):"),
            _line_equal(path, "def search_docs(query: str, *, limit):"),
            _line_equal(path, "def lookup_user(user_id, /, verbose: bool = False):"),
        ]))
        messages = " ".join(flagged.values())
        self.assertIn("'run_shell'", messages)
        self.assertIn("['limit']", messages)
        self.assertIn("['user_id']", messages)
        self.assertNotIn("self", messages)
        self.assertNotIn("cls", messages)


class TestUnsafeDeserialization(unittest.TestCase):
    """Fix 5: pickle family (CRITICAL) plus torch.load / numpy.load variants."""

    def test_variants_and_severities(self):
        path = ACCURACY / "python" / "deserialization_variants.py"
        scanner = SAIFScanner(ACCURACY)
        scanner.scan_python(path)
        got = {f.line_number: f.severity for f in _by_rule(scanner, "PY_UNSAFE_DESERIALIZATION")}
        expected = {
            _line_equal(path, "a = pickle_loads(blob)"): "CRITICAL",
            _line_equal(path, "b = cPickle.load(fh)"): "CRITICAL",
            _line_equal(path, "c = dill.loads(blob)"): "CRITICAL",
            _line_equal(path, "d = cloudpickle.load(fh)"): "CRITICAL",
            _line_equal(path, "e = joblib.load(path)"): "CRITICAL",
            _line_equal(path, "f = pd.read_pickle(path)"): "CRITICAL",
            _line_equal(path, "g = Unpickler(fh).load()"): "CRITICAL",
            _line_equal(path, "h = torch.load(path)"): "HIGH",
            _line_equal(path, "i = torch.load(path, weights_only=False)"): "CRITICAL",
            _line_equal(path, "k = np.load(path, allow_pickle=True)"): "HIGH",
        }
        self.assertEqual(got, expected)

    def test_existing_pickle_fixture_and_suppression_unchanged(self):
        scanner = SAIFScanner(FIXTURES)
        scanner.scan_python(FIXTURES / "python" / "unsafe_pickle_load.py")
        scanner.scan_python(FIXTURES / "python" / "suppressed_fixture.py")
        found = _by_rule(scanner, "PY_UNSAFE_DESERIALIZATION")
        self.assertEqual([(f.file_path, f.line_number, f.severity) for f in found], [("python/unsafe_pickle_load.py", 6, "CRITICAL")])


class TestAgentLoopBudget(unittest.TestCase):
    """Fix 6: framework-correct PY_AGENT_NO_MAX_ITER (ADK max_llm_calls, LangChain max_iterations=None)."""

    def _scan(self, path: Path) -> list[Finding]:
        scanner = SAIFScanner(path.parent)
        scanner.scan_python(path)
        return _by_rule(scanner, "PY_AGENT_NO_MAX_ITER")

    def test_adk_runner_without_budget_reports_default_and_run_config_fix(self):
        findings = self._scan(FIXTURES / "python" / "infinite_agent_loop.py")
        self.assertEqual([(f.line_number, f.severity) for f in findings], [(5, "MEDIUM")])
        self.assertIn("500", findings[0].message)
        self.assertIn("max_llm_calls", findings[0].message)
        self.assertIn("run_config=RunConfig(max_llm_calls=<N>)", findings[0].remediation)
        self.assertNotIn("max_iterations=15", findings[0].remediation)

    def test_adk_explicit_budget_or_env_override_not_flagged(self):
        self.assertEqual(self._scan(ACCURACY / "python" / "adk_budget_configured.py"), [])
        self.assertEqual(self._scan(ACCURACY / "python" / "adk_env_budget.py"), [])

    def test_adk_non_positive_budget_is_unbounded(self):
        path = ACCURACY / "python" / "adk_unbounded.py"
        findings = self._scan(path)
        run_line = _line_equal(path, 'return runner.run(user_id="u", session_id="s", new_message=message, run_config=RunConfig(max_llm_calls=0))')
        self.assertEqual([(f.line_number, f.severity) for f in findings], [(run_line, "HIGH")])
        self.assertIn("max_llm_calls=0", findings[0].message)

    def test_adk_in_memory_runner_through_module_alias(self):
        findings = self._scan(ACCURACY / "python" / "adk_inmemory_default.py")
        self.assertEqual([(f.line_number, f.severity) for f in findings], [(4, "MEDIUM")])
        self.assertIn("InMemoryRunner", findings[0].message)

    def test_langchain_and_other_frameworks(self):
        path = ACCURACY / "python" / "other_agent_frameworks.py"
        findings = self._scan(path)
        self.assertEqual(sorted((f.line_number, f.severity) for f in findings), sorted([
            (_line_equal(path, "unbounded_executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None)"), "HIGH"),
            (_line_equal(path, "unbounded_factory = AgentExecutor.from_agent_and_tools(agent=agent, tools=tools, max_iterations=None)"), "HIGH"),
        ]))
        self.assertTrue(all("15" in f.message for f in findings))


class TestDockerfiles(unittest.TestCase):
    """Fix 7: multi-stage refs, --platform, registry ports, tag-vs-digest severity, ${ARG}, final-stage USER."""

    def _scan(self, name: str) -> list[Finding]:
        scanner = SAIFScanner(ACCURACY)
        scanner.scan_dockerfile(ACCURACY / "docker" / name)
        return scanner.findings

    def test_multistage_stage_references_not_flagged(self):
        self.assertEqual(self._scan("Dockerfile.multistage"), [])

    def test_platform_registry_ports_tags_and_args(self):
        findings = self._scan("Dockerfile.platform_registry_args")
        self.assertEqual(
            sorted((f.rule_id, f.line_number, f.severity) for f in findings),
            [
                ("DOCKER_UNPINNED_TAG", 1, "LOW"),
                ("DOCKER_UNPINNED_TAG", 3, "MEDIUM"),
                ("DOCKER_UNPINNED_TAG", 4, "LOW"),
                ("DOCKER_UNPINNED_TAG", 5, "MEDIUM"),
            ],
        )

    def test_root_check_uses_final_stage(self):
        final_stage = self._scan("Dockerfile.final_stage_root")
        self.assertEqual([f.rule_id for f in final_stage], ["DOCKER_ROOT_EXECUTION"])
        root_last = self._scan("Dockerfile.user_root_last")
        self.assertEqual([(f.rule_id, f.snippet) for f in root_last], [("DOCKER_ROOT_EXECUTION", "USER root")])
        self.assertEqual(self._scan("Dockerfile.inherited_user"), [])

    def test_existing_docker_fixtures_unchanged(self):
        scanner = SAIFScanner(FIXTURES)
        scanner.scan_dockerfile(FIXTURES / "docker" / "Dockerfile.latest_tag")
        scanner.scan_dockerfile(FIXTURES / "docker" / "Dockerfile.root_user")
        self.assertEqual(
            sorted((f.rule_id, f.file_path, f.severity) for f in scanner.findings),
            [
                ("DOCKER_ROOT_EXECUTION", "docker/Dockerfile.root_user", "HIGH"),
                ("DOCKER_UNPINNED_TAG", "docker/Dockerfile.latest_tag", "MEDIUM"),
            ],
        )


class TestUrlsAndIgnores(_TempDirTestCase):
    """Fix 8 (file:// URLs anchored at the scanned file) and fix 9 (new default ignores)."""

    def test_urls_point_to_scanned_files_not_cwd(self):
        target = self.tmp / "repo"
        self.write("repo/pkg/model.py", "import pickle\nobj = pickle.loads(b'')\n")
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        os.chdir(elsewhere)
        findings = SAIFScanner(target).scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file_path, os.path.join("pkg", "model.py"))
        self.assertEqual(findings[0].url, f"{(target / 'pkg' / 'model.py').as_uri()}#L2")

    def test_cli_json_urls_from_another_cwd(self):
        self.write("repo/Dockerfile", "FROM python:latest\nUSER app\n")
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "fast_scan.py"), str(self.tmp / "repo"), "--format=json"],
            cwd=str(elsewhere), capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        findings = json.loads(proc.stdout)
        self.assertEqual([f["url"] for f in findings], [f"{(self.tmp / 'repo' / 'Dockerfile').as_uri()}#L1"])

    def test_tf_plan_url_points_to_plan_file(self):
        plan = self.write("plans/plan.json", json.dumps({"planned_values": {"root_module": {"resources": [
            {"type": "google_storage_bucket", "name": "b", "address": "google_storage_bucket.b", "values": {}}
        ]}}}))
        (self.tmp / "repo").mkdir()
        os.chdir(self.tmp / "plans")
        findings = SAIFScanner(self.tmp / "repo").scan_tf_plan(plan)
        self.assertEqual([(f.rule_id, f.url) for f in findings], [("TF_CMEK_MISSING", f"{plan.as_uri()}#L1")])

    def test_urls_are_percent_encoded(self):
        self.write("my repo/app.py", "import pickle\npickle.load(open('x', 'rb'))\n")
        findings = SAIFScanner(self.tmp / "my repo").scan()
        self.assertEqual(len(findings), 1)
        self.assertIn("my%20repo", findings[0].url)
        self.assertNotIn(" ", findings[0].url)

    def test_new_default_ignores(self):
        new_dirs = {"site-packages", ".ipynb_checkpoints", ".tox", ".nox", "saifguard_reports"}
        self.assertTrue(new_dirs.issubset(DEFAULT_IGNORES))
        for name in sorted(new_dirs):
            self.write(f"{name}/nested/loader.py", "import pickle\npickle.loads(b'')\n")
            self.write(f"{name}/config.json", f'{{"k": "{FAKE_GOOGLE_KEY}"}}\n')
        self.write("app/loader.py", "import pickle\npickle.loads(b'')\n")
        self.assertEqual([f.file_path for f in SAIFScanner(self.tmp).scan()], [os.path.join("app", "loader.py")])


class TestProbeRegression(_TempDirTestCase):
    """End-to-end: the review's probe directory (plus a runtime .env) scanned from another CWD."""

    def test_probe_findings_and_urls(self):
        probe = self.tmp / "probe"
        shutil.copytree(str(ACCURACY / "probe"), str(probe))
        (probe / ".env").write_text(f"GOOGLE_API_KEY={FAKE_GOOGLE_KEY}\n", encoding="utf-8")
        os.chdir(str(self.tmp))
        findings = SAIFScanner(probe).scan()
        self.assertEqual(
            sorted((f.rule_id, f.severity, f.file_path, f.line_number) for f in findings),
            sorted([
                ("DOCKER_UNPINNED_TAG", "LOW", "Dockerfile", 1),
                ("PY_AGENT_EXCESSIVE_AGENCY", "HIGH", "cli_and_tools.py", 9),
                ("PY_AGENT_NO_MAX_ITER", "MEDIUM", "adk_agent.py", 2),
                ("PY_UNSAFE_DESERIALIZATION", "HIGH", "misc.py", 3),
                ("SECRET_HARDCODED_API_KEY", "CRITICAL", ".env", 1),
                ("SECRET_HARDCODED_API_KEY", "CRITICAL", "app.ts", 1),
                ("SECRET_HARDCODED_API_KEY", "CRITICAL", "main.go", 2),
                ("SECRET_HARDCODED_API_KEY", "CRITICAL", "notebook.ipynb", 1),
                ("TF_IAM_PUBLIC_ACCESS", "CRITICAL", "iam.tf", 4),
            ]),
        )
        for finding in findings:
            self.assertEqual(finding.url, f"{(probe / finding.file_path).as_uri()}#L{finding.line_number}")


if __name__ == "__main__":
    unittest.main()
