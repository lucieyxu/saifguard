"""Regression tests for gcp_scan.py accuracy (Model Armor probing, fail-closed rules, remediation, topology)."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import socket
import ssl
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from saifguard.skills.saifguard.scripts import gcp_scan  # noqa: E402
from saifguard.skills.saifguard.scripts.gcp_scan import (  # noqa: E402
    GCPProjectScanner,
    format_gcp_markdown_report,
    is_ai_bucket_name,
    parse_location_list,
    scan_gcp_project,
)

FIXTURES = REPO_ROOT / "tests" / "fixtures"
EDGE = FIXTURES / "scanner_accuracy" / "gcp"
PROJECT = "live-project"
FLOOR_URL = f"https://modelarmor.googleapis.com/v1/projects/{PROJECT}/locations/global/floorSetting"
VERTEX_ASSET = {
    "name": f"//aiplatform.googleapis.com/projects/{PROJECT}/locations/us-central1/endpoints/1",
    "assetType": "aiplatform.googleapis.com/Endpoint",
    "location": "us-central1",
    "versionedResources": [{"resource": {"network": "projects/1/global/networks/private"}}],
}


def _templates_url(location: str) -> str:
    return f"https://modelarmor.{location}.rep.googleapis.com/v1/projects/{PROJECT}/locations/{location}/templates"


def _error(status: int, message: str, reason: str = "") -> tuple[int, dict]:
    body = {"error": {"code": status, "message": message, "status": "PERMISSION_DENIED"}}
    if reason:
        body["error"]["details"] = [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}]
    return status, body


class _FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeModelArmorAPI:
    """Stand-in for urllib.request.urlopen that serves canned Model Armor responses by URL."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list[str] = []
        self.contexts: list = []
        self.auth_headers: list = []

    def __call__(self, req, timeout=None, context=None):
        url = req.full_url
        self.calls.append(url)
        self.contexts.append(context)
        self.auth_headers.append(req.get_header("Authorization"))
        if url not in self.routes:
            raise AssertionError(f"Unexpected Model Armor URL: {url}")
        route = self.routes[url]
        if isinstance(route, BaseException):
            raise route
        status, payload = route
        if status >= 400:
            raise urllib.error.HTTPError(url, status, "error", None, io.BytesIO(json.dumps(payload).encode("utf-8")))
        return _FakeResponse(status, payload)


def _live_scanner(resources=None, locations=None) -> GCPProjectScanner:
    scanner = GCPProjectScanner(PROJECT, model_armor_locations=locations)
    scanner.raw_resources = [VERTEX_ASSET] if resources is None else resources
    return scanner


def _run_model_armor(scanner: GCPProjectScanner, api, token: str = "fake-token") -> set:
    with mock.patch.object(gcp_scan, "_get_gcloud_access_token", return_value=token), \
            mock.patch.object(gcp_scan.urllib.request, "urlopen", api):
        scanner.fetch_model_armor()
        scanner.compress_and_evaluate()
    return {f.rule_id for f in scanner.findings}


def _gap(scanner: GCPProjectScanner):
    gaps = [f for f in scanner.findings if f.rule_id == "GCP_AUDIT_VISIBILITY_GAP"]
    return gaps[0] if gaps else None


class TestModelArmorProbing(unittest.TestCase):
    """Fixes 10-12: singular floorSetting, regional template endpoints, visibility gaps, probed locations."""

    def test_floor_setting_is_singular_and_templates_use_regional_endpoints(self):
        api = FakeModelArmorAPI({FLOOR_URL: (404, {"error": {"code": 404}}), _templates_url("us-central1"): (200, {})})
        rules = _run_model_armor(_live_scanner(), api)
        self.assertEqual(api.calls, [FLOOR_URL, _templates_url("us-central1")])
        self.assertFalse(any("floorSettings" in url for url in api.calls))
        self.assertFalse(any(url.startswith("https://modelarmor.googleapis.com") and "/templates" in url for url in api.calls))
        for ctx in api.contexts:
            self.assertIsInstance(ctx, ssl.SSLContext)
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx.check_hostname)
        self.assertEqual(set(api.auth_headers), {"Bearer fake-token"})
        # The API answered and nothing is configured -> MISSING (and no visibility gap).
        self.assertIn("GCP_MODEL_ARMOR_MISSING", rules)
        self.assertNotIn("GCP_AUDIT_VISIBILITY_GAP", rules)

    def test_regional_template_suppresses_missing(self):
        scanner = _live_scanner()
        api = FakeModelArmorAPI({
            FLOOR_URL: (200, {"name": f"projects/{PROJECT}/locations/global/floorSetting", "enableFloorSettingEnforcement": False}),
            _templates_url("us-central1"): (200, {"templates": [{"name": f"projects/{PROJECT}/locations/us-central1/templates/t1"}]}),
        })
        rules = _run_model_armor(scanner, api)
        self.assertNotIn("GCP_MODEL_ARMOR_MISSING", rules)
        self.assertNotIn("GCP_AUDIT_VISIBILITY_GAP", rules)
        coverage = scanner.coverage["Model Armor Guardrails API"]
        self.assertTrue(coverage.startswith("✅ Scanned"), coverage)
        self.assertIn("1 found", coverage)

    def test_enforced_floor_setting_suppresses_missing(self):
        api = FakeModelArmorAPI({
            FLOOR_URL: (200, {"name": f"projects/{PROJECT}/locations/global/floorSetting", "enableFloorSettingEnforcement": True}),
            _templates_url("us-central1"): (200, {}),
        })
        self.assertNotIn("GCP_MODEL_ARMOR_MISSING", _run_model_armor(_live_scanner(), api))

    def test_unenforced_floor_setting_is_still_missing(self):
        api = FakeModelArmorAPI({FLOOR_URL: (200, {"filterConfig": {}}), _templates_url("us-central1"): (200, {"templates": []})})
        self.assertIn("GCP_MODEL_ARMOR_MISSING", _run_model_armor(_live_scanner(), api))

    def test_permission_denied_is_a_visibility_gap_not_missing(self):
        for status in (401, 403):
            with self.subTest(status=status):
                scanner = _live_scanner()
                api = FakeModelArmorAPI({
                    FLOOR_URL: _error(status, "Permission 'modelarmor.floorSettings.get' denied"),
                    _templates_url("us-central1"): _error(status, "Permission 'modelarmor.templates.list' denied"),
                })
                rules = _run_model_armor(scanner, api)
                self.assertIn("GCP_AUDIT_VISIBILITY_GAP", rules)
                self.assertNotIn("GCP_MODEL_ARMOR_MISSING", rules)
                self.assertTrue(scanner.coverage["Model Armor Guardrails API"].startswith("❌ Not scanned"))
                gap = _gap(scanner)
                self.assertIn(f"gcloud services enable modelarmor.googleapis.com --project={PROJECT}", gap.remediation)
                self.assertIn("roles/modelarmor.viewer", gap.remediation)
                self.assertIn("roles/modelarmor.floorSettingsViewer", gap.remediation)
                self.assertIn("<YOUR_PRINCIPAL>", gap.remediation)
                self.assertNotIn("YOUR_EMAIL", gap.remediation)
                self.assertIn(f"HTTP {status}", gap.description)

    def test_service_disabled_reason_is_reported(self):
        scanner = _live_scanner()
        api = FakeModelArmorAPI({
            FLOOR_URL: _error(403, "Model Armor API has not been used in project", reason="SERVICE_DISABLED"),
            _templates_url("us-central1"): _error(403, "Model Armor API has not been used in project", reason="SERVICE_DISABLED"),
        })
        rules = _run_model_armor(scanner, api)
        self.assertEqual(rules & {"GCP_AUDIT_VISIBILITY_GAP", "GCP_MODEL_ARMOR_MISSING"}, {"GCP_AUDIT_VISIBILITY_GAP"})
        self.assertIn("SERVICE_DISABLED", _gap(scanner).description)

    def test_partial_denial_without_guardrails_is_inconclusive(self):
        scanner = _live_scanner()
        api = FakeModelArmorAPI({
            FLOOR_URL: (200, {"enableFloorSettingEnforcement": False}),
            _templates_url("us-central1"): _error(403, "Permission 'modelarmor.templates.list' denied"),
        })
        rules = _run_model_armor(scanner, api)
        self.assertIn("GCP_AUDIT_VISIBILITY_GAP", rules)
        self.assertNotIn("GCP_MODEL_ARMOR_MISSING", rules)
        self.assertTrue(scanner.coverage["Model Armor Guardrails API"].startswith("⚠️ Partial"))

    def test_missing_token_is_a_visibility_gap(self):
        scanner = _live_scanner()
        api = FakeModelArmorAPI({})
        rules = _run_model_armor(scanner, api, token="")
        self.assertEqual(api.calls, [])
        self.assertIn("GCP_AUDIT_VISIBILITY_GAP", rules)
        self.assertNotIn("GCP_MODEL_ARMOR_MISSING", rules)
        self.assertEqual(scanner.coverage["Model Armor Guardrails API"], "❌ Not scanned (no gcloud auth token)")

    def test_server_error_is_inconclusive(self):
        scanner = _live_scanner()
        api = FakeModelArmorAPI({FLOOR_URL: (404, {}), _templates_url("us-central1"): (503, {"error": {"message": "backend unavailable"}})})
        rules = _run_model_armor(scanner, api)
        self.assertIn("GCP_AUDIT_VISIBILITY_GAP", rules)
        self.assertNotIn("GCP_MODEL_ARMOR_MISSING", rules)

    def test_unresolvable_regional_endpoint_does_not_block_missing(self):
        scanner = _live_scanner(locations=["xx-nowhere1"])
        api = FakeModelArmorAPI({
            FLOOR_URL: (404, {}),
            _templates_url("us-central1"): (200, {}),
            _templates_url("xx-nowhere1"): urllib.error.URLError(socket.gaierror(8, "nodename nor servname provided")),
        })
        rules = _run_model_armor(scanner, api)
        self.assertIn("GCP_MODEL_ARMOR_MISSING", rules)
        self.assertNotIn("GCP_AUDIT_VISIBILITY_GAP", rules)
        self.assertIn("no regional endpoint for: xx-nowhere1", scanner.coverage["Model Armor Guardrails API"])

    def test_template_pagination(self):
        api = FakeModelArmorAPI({
            FLOOR_URL: (404, {}),
            _templates_url("us-central1"): (200, {"templates": [], "nextPageToken": "page/2"}),
            _templates_url("us-central1") + "?pageToken=page%2F2": (200, {"templates": [{"name": "t2"}]}),
        })
        scanner = _live_scanner()
        self.assertNotIn("GCP_MODEL_ARMOR_MISSING", _run_model_armor(scanner, api))
        self.assertEqual(scanner.model_armor_data["templates"], [{"name": "t2"}])

    def test_probed_locations_are_derived_from_assets_and_cli_and_deduped(self):
        resources = [
            VERTEX_ASSET,
            {"name": "//run.googleapis.com/projects/p/locations/europe-west4/services/chat", "assetType": "run.googleapis.com/Service", "location": "europe-west4"},
            {"name": "//run.googleapis.com/projects/p/locations/asia-northeast1/revisions/chat-1", "assetType": "run.googleapis.com/Revision"},
            {"name": "//storage.googleapis.com/bucket", "assetType": "storage.googleapis.com/Bucket", "location": "EU"},
            {"name": "//aiplatform.googleapis.com/projects/p/locations/us-central1/models/2", "assetType": "aiplatform.googleapis.com/Model", "location": "us-central1"},
        ]
        scanner = _live_scanner(resources=resources, locations=["EU", "us-central1", "bad/loc", " europe-west4 "])
        self.assertEqual(scanner.model_armor_locations(), ["global", "us-central1", "europe-west4", "asia-northeast1", "eu"])

    def test_parse_location_list(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(parse_location_list("us-central1, EU,,bad/loc"), ["us-central1", "eu"])
        self.assertIn("bad/loc", err.getvalue())
        self.assertEqual(parse_location_list(None), [])

    def test_cli_flag_is_passed_through(self):
        argv = ["gcp_scan.py", "--project", "p", "--format", "summary", "--model-armor-locations", "us-central1,EU,bad/loc"]
        with mock.patch.object(gcp_scan, "scan_gcp_project", return_value={"findings": []}) as fake_scan, \
                mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gcp_scan.main(), 0)
        self.assertEqual(fake_scan.call_args.kwargs["model_armor_locations"], ["us-central1", "eu"])

    def test_mock_fixture_behaviour_is_preserved(self):
        result = scan_gcp_project(
            "gcp-project",
            str(FIXTURES / "mock_gcp_assets.json"),
            str(FIXTURES / "mock_iam_policies.json"),
        )
        rules = {f["rule_id"] for f in result["findings"]}
        self.assertIn("GCP_MODEL_ARMOR_MISSING", rules)
        self.assertNotIn("GCP_AUDIT_VISIBILITY_GAP", rules)
        missing = [f for f in result["findings"] if f["rule_id"] == "GCP_MODEL_ARMOR_MISSING"][0]
        self.assertEqual(missing["location"], "projects/gcp-project/locations/global/floorSetting")

        tmp = Path(tempfile.mkdtemp(prefix="saif_ma_mock_"))
        try:
            mock_ma = tmp / "model_armor.json"
            mock_ma.write_text(json.dumps({"templates": [{"name": "t"}], "floor_settings": []}), encoding="utf-8")
            result = scan_gcp_project(
                "gcp-project",
                mock_assets_path=str(FIXTURES / "mock_gcp_assets.json"),
                mock_iam_path=str(FIXTURES / "mock_iam_policies.json"),
                mock_model_armor_path=str(mock_ma),
            )
            self.assertNotIn("GCP_MODEL_ARMOR_MISSING", {f["rule_id"] for f in result["findings"]})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestFailClosedAndBuckets(unittest.TestCase):
    """Fixes 13-14: missing fields are UNVERIFIED (not CRITICAL/HIGH); AI buckets matched on name tokens."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan_gcp_project(
            "edge-project",
            mock_assets_path=str(EDGE / "mock_assets_edge_cases.json"),
            mock_iam_path=str(EDGE / "mock_iam_public_bindings.json"),
        )
        cls.topology = {r["resource"].split("/")[-1]: r for r in cls.result["compressed_topology"]}

    def _findings(self, rule_id: str) -> list:
        return [f for f in self.result["findings"] if f["rule_id"] == rule_id]

    def test_missing_load_balancing_scheme_is_unverified(self):
        armor = self._findings("GCP_CLOUD_ARMOR_MISSING")
        self.assertEqual([f["location"].split("/")[-1] for f in armor], ["regional-gateway"])
        self.assertEqual(self.topology["scheme-unknown"]["deterministic_alerts"], ["UNVERIFIED_GCP_CLOUD_ARMOR_MISSING"])
        self.assertEqual(self.topology["internal-backend"]["deterministic_alerts"], [])
        self.assertEqual(self.topology["protected-backend"]["deterministic_alerts"], [])

    def test_missing_key_type_is_unverified(self):
        self.assertEqual(self._findings("GCP_SA_USER_KEY_EXPOSED"), [])
        self.assertEqual(self.topology["aaaa1111"]["deterministic_alerts"], ["UNVERIFIED_GCP_SA_USER_KEY_EXPOSED"])
        self.assertEqual(self.topology["bbbb2222"]["deterministic_alerts"], [])

    def test_ai_bucket_severity_uses_name_tokens(self):
        severities = {f["location"].split("/")[-1]: f["severity"] for f in self._findings("GCP_CMEK_MISSING")}
        self.assertEqual(severities, {
            "main-assets": "MEDIUM",
            "email-archive": "MEDIUM",
            "team-ai-data": "HIGH",
            "ml_training.datasets": "HIGH",
        })
        for name in ("main", "email-exports", "domain-data", "maintenance", "chair-logs"):
            self.assertFalse(is_ai_bucket_name(name), name)
        for name in ("vertex-rag-embeddings-prod", "my-ai-bucket", "prompts.archive", "LLM_eval"):
            self.assertTrue(is_ai_bucket_name(name), name)


class TestRemediationCommands(unittest.TestCase):
    """Fix 15: verified GA commands per resource type; no destructive placeholders."""

    @classmethod
    def setUpClass(cls):
        cls.main = scan_gcp_project(
            "gcp-project",
            mock_assets_path=str(FIXTURES / "mock_gcp_assets.json"),
            mock_iam_path=str(FIXTURES / "mock_iam_policies.json"),
        )
        cls.edge = scan_gcp_project(
            "edge-project",
            mock_assets_path=str(EDGE / "mock_assets_edge_cases.json"),
            mock_iam_path=str(EDGE / "mock_iam_public_bindings.json"),
        )

    @staticmethod
    def _one(result: dict, rule_id: str, location_suffix: str) -> dict:
        matches = [f for f in result["findings"] if f["rule_id"] == rule_id and f["location"].endswith(location_suffix)]
        assert len(matches) == 1, (rule_id, location_suffix, matches)
        return matches[0]

    def test_cloud_armor_policy_has_waf_and_rate_limit_rules_before_attaching(self):
        rem = self._one(self.main, "GCP_CLOUD_ARMOR_MISSING", "ai-gateway-backend")["remediation"]
        steps = [
            "gcloud compute security-policies create saifguard-waf-policy",
            "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})",
            "evaluatePreconfiguredWaf('xss-v33-stable', {'sensitivity': 1})",
            "--action=throttle --rate-limit-threshold-count=100 --rate-limit-threshold-interval-sec=60 "
            "--conform-action=allow --exceed-action=deny-429 --enforce-on-key=ip",
            "gcloud compute backend-services update ai-gateway-backend --security-policy=saifguard-waf-policy --global",
        ]
        positions = [rem.find(step) for step in steps]
        self.assertNotIn(-1, positions, rem)
        self.assertEqual(positions, sorted(positions))
        regional = self._one(self.edge, "GCP_CLOUD_ARMOR_MISSING", "regional-gateway")["remediation"]
        self.assertIn("security-policies create saifguard-waf-policy --description='SAIFGuard baseline WAF and rate limiting' --region=europe-west4", regional)
        self.assertIn("backend-services update regional-gateway --security-policy=saifguard-waf-policy --region=europe-west4", regional)
        self.assertNotIn("--global", regional)

    def test_service_account_key_disable_then_irreversible_delete(self):
        rem = self._one(self.main, "GCP_SA_USER_KEY_EXPOSED", "1234567890abcdef")["remediation"]
        disable = rem.find("gcloud iam service-accounts keys disable 1234567890abcdef --iam-account=sa@gcp-project.iam.gserviceaccount.com")
        warning = rem.find("⚠️ irreversible")
        delete = rem.find("gcloud iam service-accounts keys delete 1234567890abcdef --iam-account=sa@gcp-project.iam.gserviceaccount.com")
        self.assertTrue(0 <= disable < warning < delete, rem)
        self.assertNotIn("SERVICE_ACCOUNT_EMAIL", rem)

    def test_public_iam_commands_follow_resource_type_and_members(self):
        project = self._one(self.edge, "GCP_IAM_PRIMITIVE_OR_PUBLIC", "projects/edge-project")
        self.assertIn("gcloud projects remove-iam-policy-binding edge-project --member='allAuthenticatedUsers' --role='roles/viewer'", project["remediation"])
        self.assertNotIn("--member='allUsers'", project["remediation"])
        self.assertEqual(project["url"], "https://console.cloud.google.com/iam-admin/iam?project=edge-project")

        bucket = self._one(self.edge, "GCP_IAM_PRIMITIVE_OR_PUBLIC", "//storage.googleapis.com/public-site")
        self.assertIn("gcloud storage buckets remove-iam-policy-binding gs://public-site --member='allUsers' --role='roles/storage.objectViewer'", bucket["remediation"])
        self.assertEqual(bucket["url"], "https://console.cloud.google.com/storage/browser/public-site?project=edge-project")

        run = self._one(self.edge, "GCP_IAM_PRIMITIVE_OR_PUBLIC", "services/chat-api")
        for member in ("allUsers", "allAuthenticatedUsers"):
            self.assertIn(
                f"gcloud run services remove-iam-policy-binding chat-api --region=europe-west4 --member='{member}' "
                f"--role='roles/run.invoker' --project=edge-project --all",
                run["remediation"],
            )
        self.assertEqual(run["url"], "https://console.cloud.google.com/run/detail/europe-west4/chat-api/metrics?project=edge-project")

        topic = self._one(self.edge, "GCP_IAM_PRIMITIVE_OR_PUBLIC", "topics/events")
        self.assertNotIn("```bash", topic["remediation"])
        self.assertIn("console", topic["remediation"])
        self.assertNotIn("iam-admin/iam", topic["url"])

    def test_no_placeholder_principals_or_preview_tracks(self):
        scanner = GCPProjectScanner("p")
        scanner._add_visibility_gap("Cloud Asset Inventory API", "denied", "gcloud services enable cloudasset.googleapis.com --project=p", "roles/cloudasset.viewer")
        texts = [f["remediation"] for f in self.main["findings"] + self.edge["findings"]] + [scanner.findings[0].remediation]
        for text in texts:
            self.assertNotIn("YOUR_EMAIL", text)
            for line in text.splitlines():
                if line.startswith("gcloud "):
                    self.assertNotRegex(line, r"^gcloud (alpha|beta) ")
        self.assertIn("--member='<YOUR_PRINCIPAL>' --role='roles/cloudasset.viewer'", scanner.findings[0].remediation)


class TestTopologyMarkdown(unittest.TestCase):
    """Fix 16: compact Discovered Topology section in markdown; JSON output unchanged."""

    def test_markdown_lists_discovered_resources_and_json_shape_is_unchanged(self):
        result = scan_gcp_project(
            "gcp-project",
            mock_assets_path=str(FIXTURES / "mock_gcp_assets.json"),
            mock_iam_path=str(FIXTURES / "mock_iam_policies.json"),
        )
        self.assertEqual(set(result), {"project_id", "timestamp", "coverage", "stats", "findings", "compressed_topology", "model_armor"})
        for entry in result["compressed_topology"]:
            self.assertEqual(set(entry), {"resource", "type", "location", "console_url", "deterministic_alerts", "properties"})
        md = format_gcp_markdown_report(result)
        self.assertIn("## 4. Discovered Topology", md)
        self.assertIn("## 5. Formal Security Sign-Off Block", md)
        self.assertLess(md.index("## 4. Discovered Topology"), md.index("## 5. Formal Security Sign-Off Block"))
        for entry in result["compressed_topology"]:
            self.assertIn(f"`{entry['resource']}`", md)
            self.assertIn(entry["console_url"], md)

    def test_topology_is_capped_and_alerting_resources_come_first(self):
        topology = [
            {"resource": f"//storage.googleapis.com/bucket-{i:03d}", "type": "Bucket", "location": "US",
             "console_url": f"https://console.cloud.google.com/storage/browser/bucket-{i:03d}", "deterministic_alerts": [], "properties": {}}
            for i in range(150)
        ]
        topology[149]["deterministic_alerts"] = ["GCP_CMEK_MISSING"]
        topology[1]["resource"] = "//example.googleapis.com/a|b"
        md = format_gcp_markdown_report({"project_id": "p", "findings": [], "coverage": {}, "stats": {}, "compressed_topology": topology})
        rows = [line for line in md.splitlines() if line.startswith("| ") and "| `//" in line]
        self.assertEqual(len(rows), 100)
        self.assertTrue(rows[0].startswith("| 1 | `//storage.googleapis.com/bucket-149`"))
        self.assertIn("`GCP_CMEK_MISSING`", rows[0])
        self.assertIn("Truncated: showing 100 of 150 resources", md)
        self.assertIn("`//example.googleapis.com/a\\|b`", md)
        self.assertNotIn("a|b", md)

    def test_empty_topology(self):
        md = format_gcp_markdown_report({"project_id": "p", "findings": [], "coverage": {}, "stats": {}, "compressed_topology": []})
        self.assertIn("_No resources were discovered", md)


if __name__ == "__main__":
    unittest.main()
