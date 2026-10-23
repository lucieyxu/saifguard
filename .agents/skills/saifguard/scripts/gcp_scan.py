#!/usr/bin/env python3
"""SAIFGuard Deterministic GCP Project Security Scanner & Payload Compressor.

Discovers GCP resources, IAM policies, and Model Armor configurations via Cloud Asset
Inventory (Python SDK or zero-dependency `gcloud` CLI fallback). Evaluates deterministic
SAIF & OWASP LLM security rules, builds clickable GCP Console URLs, and compresses
the topology payload by >90% for downstream LLM evaluation.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


@dataclass
class SAIFFinding:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    saif_pillar: str
    owasp_category: str
    category: str
    title: str
    description: str
    remediation: str
    location: str
    url: str = ""
    file_path: str = ""
    line_number: int = 0
    message: str = ""
    snippet: str = ""

    def __post_init__(self):
        if not self.message:
            self.message = self.description
        if not self.file_path:
            self.file_path = self.location


AI_SECURITY_ASSET_TYPES = [
    "iam.googleapis.com/ServiceAccountKey",
    "iam.googleapis.com/ServiceAccount",
    "compute.googleapis.com/Route",
    "storage.googleapis.com/Bucket",
    "dns.googleapis.com/ResourceRecordSet",
    "dataplex.googleapis.com/EntryGroup",
    "compute.googleapis.com/ForwardingRule",
    "compute.googleapis.com/Address",
    "logging.googleapis.com/LogSink",
    "logging.googleapis.com/LogBucket",
    "compute.googleapis.com/UrlMap",
    "compute.googleapis.com/Subnetwork",
    "sqladmin.googleapis.com/Instance",
    "servicedirectory.googleapis.com/Service",
    "servicedirectory.googleapis.com/Namespace",
    "servicedirectory.googleapis.com/Endpoint",
    "run.googleapis.com/Service",
    "run.googleapis.com/Revision",
    "run.googleapis.com/Job",
    "dns.googleapis.com/ResponsePolicy",
    "dns.googleapis.com/ManagedZone",
    "compute.googleapis.com/TargetHttpsProxy",
    "compute.googleapis.com/TargetHttpProxy",
    "compute.googleapis.com/SslCertificate",
    "compute.googleapis.com/SecurityPolicy",
    "compute.googleapis.com/Project",
    "compute.googleapis.com/NetworkEndpointGroup",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/BackendService",
    "cloudresourcemanager.googleapis.com/Project",
    "cloudbilling.googleapis.com/ProjectBillingInfo",
    "bigquery.googleapis.com/Table",
    "bigquery.googleapis.com/Dataset",
    "aiplatform.googleapis.com/Endpoint",
    "aiplatform.googleapis.com/Model",
    "aiplatform.googleapis.com/ReasoningEngine",
    "secretmanager.googleapis.com/Secret",
    "cloudkms.googleapis.com/CryptoKey",
    "apigateway.googleapis.com/Gateway",
]

STRIP_METADATA_KEYS = {
    "etag",
    "selfLink",
    "metageneration",
    "createTime",
    "updateTime",
    "timeCreated",
    "updated",
    "uid",
    "projectNumber",
    "parentFullResourceName",
    "parentAssetType",
    "kind",
}

# Model Armor: floor settings are a global singleton served by the global endpoint, while templates
# must be managed through the regional / multi-regional endpoint matching the template's location.
MODEL_ARMOR_GLOBAL_ENDPOINT = "https://modelarmor.googleapis.com"
MODEL_ARMOR_VIEWER_ROLES = ("roles/modelarmor.viewer", "roles/modelarmor.floorSettingsViewer")
_LOCATION_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_MAX_TEMPLATE_PAGES = 20

# Bucket-name tokens (split on - _ .) that mark a bucket as holding AI / ML data.
AI_BUCKET_TOKENS = frozenset({
    "ai", "genai", "llm", "llms", "ml", "mlops", "rag", "vertex", "vertexai", "gemini",
    "model", "models", "embed", "embeds", "embedding", "embeddings", "vector", "vectors",
    "train", "training", "prompt", "prompts",
})

PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")
TOPOLOGY_MARKDOWN_ROW_LIMIT = 100


def build_console_url(asset_type: str, resource_name: str, project_id: str) -> str:
    """Deterministically generate a clickable Google Cloud Console URL for a resource."""
    short_name = resource_name.split("/")[-1]
    if "storage.googleapis.com/Bucket" in asset_type:
        return f"https://console.cloud.google.com/storage/browser/{short_name}?project={project_id}"
    if "run.googleapis.com/Service" in asset_type:
        m = re.search(r"/locations/([^/]+)/services/([^/]+)", resource_name)
        if m:
            return f"https://console.cloud.google.com/run/detail/{m.group(1)}/{m.group(2)}/metrics?project={project_id}"
        return f"https://console.cloud.google.com/run?project={project_id}"
    if "sqladmin.googleapis.com/Instance" in asset_type:
        return f"https://console.cloud.google.com/sql/instances/{short_name}/overview?project={project_id}"
    if "bigquery.googleapis.com/Dataset" in asset_type:
        return f"https://console.cloud.google.com/bigquery?project={project_id}&d={short_name}&p={project_id}&page=dataset"
    if "compute.googleapis.com/BackendService" in asset_type:
        return f"https://console.cloud.google.com/net-services/loadbalancing/backends/details/http/{short_name}?project={project_id}"
    if "compute.googleapis.com/SecurityPolicy" in asset_type:
        return f"https://console.cloud.google.com/net-security/securitypolicies/details/{short_name}?project={project_id}"
    if "iam.googleapis.com/ServiceAccount" in asset_type:
        return f"https://console.cloud.google.com/iam-admin/serviceaccounts?project={project_id}"
    if "aiplatform.googleapis.com" in asset_type:
        return f"https://console.cloud.google.com/vertex-ai/endpoints?project={project_id}"
    if "cloudresourcemanager.googleapis.com/Project" in asset_type:
        return f"https://console.cloud.google.com/iam-admin/iam?project={project_id}"
    return f"https://console.cloud.google.com/home/dashboard?project={project_id}"


def is_ai_bucket_name(bucket_name: str) -> bool:
    """True when a bucket short name contains an AI/ML token (token match, so 'main'/'email' don't count)."""
    return any(token in AI_BUCKET_TOKENS for token in re.split(r"[-_.]+", bucket_name.lower()) if token)


def _asset_type_for_resource(resource_name: str) -> str:
    """Best-effort asset type for an IAM policy's full resource name (used for commands and console URLs)."""
    if resource_name.startswith("//cloudresourcemanager.googleapis.com/projects/"):
        return "cloudresourcemanager.googleapis.com/Project"
    if resource_name.startswith("//storage.googleapis.com/"):
        bucket = resource_name[len("//storage.googleapis.com/"):]
        if bucket and "/" not in bucket:
            return "storage.googleapis.com/Bucket"
    if re.match(r"^//run\.googleapis\.com/projects/[^/]+/locations/[^/]+/services/[^/]+$", resource_name):
        return "run.googleapis.com/Service"
    if re.match(r"^//bigquery\.googleapis\.com/projects/[^/]+/datasets/[^/]+$", resource_name):
        return "bigquery.googleapis.com/Dataset"
    return ""


def _floor_setting_enforced(floor_setting: Any) -> bool:
    return isinstance(floor_setting, dict) and str(floor_setting.get("enableFloorSettingEnforcement", "")).lower() == "true"


def _model_armor_regional_endpoint(location: str) -> str:
    return f"https://modelarmor.{location}.rep.googleapis.com"


def _run_gcloud_json(args: list[str], timeout: int = 30) -> tuple[bool, Any, str]:
    """Execute a gcloud command returning JSON and parse the output."""
    try:
        proc = subprocess.run(
            ["gcloud"] + args + ["--format=json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return True, json.loads(proc.stdout), ""
        return False, None, proc.stderr.strip() or f"Exit code {proc.returncode}"
    except Exception as e:
        return False, None, str(e)


def _get_gcloud_access_token(timeout: int = 10) -> str:
    """Return a gcloud OAuth access token, or '' when gcloud is missing or not authenticated."""
    try:
        proc = subprocess.run(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return ""


def _build_ssl_context() -> ssl.SSLContext:
    """Certificate-verifying TLS context (adds the macOS/Linux system bundle when present; never unverified)."""
    ctx = ssl.create_default_context()
    cafile = Path("/etc/ssl/cert.pem")
    if cafile.is_file():
        try:
            ctx.load_verify_locations(cafile=str(cafile))
        except (OSError, ssl.SSLError):
            pass  # keep the default trust store; verification stays enabled
    return ctx


def _http_get_json(url: str, headers: dict[str, str], ssl_ctx: ssl.SSLContext, timeout: int = 5) -> tuple[int | None, Any, str]:
    """GET a JSON resource -> (HTTP status or None on network failure, payload, error detail)."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read().decode("utf-8", errors="replace")
        try:
            return status, (json.loads(body) if body.strip() else {}), ""
        except ValueError:
            return status, None, "Invalid JSON response"
    except urllib.error.HTTPError as he:
        detail = ""
        try:
            err = json.loads(he.read().decode("utf-8", errors="replace")).get("error", {})
            detail = err.get("message") or err.get("status") or ""
            reasons = [d.get("reason") for d in err.get("details", []) if isinstance(d, dict) and d.get("reason")]
            if reasons:
                detail = f"{', '.join(reasons)}: {detail}"
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                he.close()
        return he.code, None, (detail or str(he.reason))[:300]
    except urllib.error.URLError as ue:
        if isinstance(ue.reason, socket.gaierror):
            return None, None, f"DNS_UNRESOLVED: {ue.reason}"
        return None, None, f"Network error: {ue.reason}"
    except Exception as exc:  # timeouts, TLS failures, connection resets
        return None, None, f"Network error: {exc}"


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


class GCPProjectScanner:
    """Fetches GCP assets, evaluates deterministic SAIF rules, and compresses payload."""

    def __init__(
        self,
        project_id: str,
        mock_assets_path: str | None = None,
        mock_iam_path: str | None = None,
        mock_model_armor_path: str | None = None,
        model_armor_locations: Sequence[str] | None = None,
    ):
        self.project_id = project_id
        self.mock_assets_path = mock_assets_path
        self.mock_iam_path = mock_iam_path
        self.mock_model_armor_path = mock_model_armor_path
        self.extra_model_armor_locations: list[str] = list(model_armor_locations or [])

        self.findings: list[SAIFFinding] = []
        self.coverage: dict[str, str] = {
            "Cloud Asset Inventory (Resources)": "⏳ Pending",
            "Cloud Asset Inventory (IAM Policies)": "⏳ Pending",
            "Model Armor Guardrails API": "⏳ Pending",
        }
        self.raw_resources: list[dict[str, Any]] = []
        self.raw_iam_policies: list[dict[str, Any]] = []
        self.model_armor_data: dict[str, Any] = {"templates": [], "floor_settings": []}
        # False when the Model Armor API could not be read (auth/permission/network): absence is then unknown.
        self.model_armor_readable = True
        self.model_armor_scope = ""
        self.compressed_resources: list[dict[str, Any]] = []

    def _add_visibility_gap(self, api_name: str, error_detail: str, enable_cmd: str, role_hint: str | Sequence[str]) -> None:
        roles = [role_hint] if isinstance(role_hint, str) else list(role_hint)
        grant_cmds = "\n".join(
            f"gcloud projects add-iam-policy-binding {self.project_id} --member='<YOUR_PRINCIPAL>' --role='{role}'"
            for role in roles
        )
        self.findings.append(
            SAIFFinding(
                rule_id="GCP_AUDIT_VISIBILITY_GAP",
                severity="HIGH",
                saif_pillar="Pillar 2: Detection & Monitoring",
                owasp_category="LLM09: Overreliance / Visibility Gap",
                category="Audit Visibility",
                title=f"{api_name} Unavailable — Audit Coverage Incomplete",
                description=f"Could not query {api_name} in project '{self.project_id}'. Error: {error_detail[:300]}",
                remediation=(
                    "Enable API and grant viewer permissions to the auditing identity (replace `<YOUR_PRINCIPAL>`, e.g. "
                    f"`user:alice@example.com` or `serviceAccount:auditor@{self.project_id}.iam.gserviceaccount.com`):\n"
                    f"```bash\n{enable_cmd}\n{grant_cmds}\n```"
                ),
                location=f"projects/{self.project_id}",
                url=f"https://console.cloud.google.com/apis/dashboard?project={self.project_id}",
            )
        )

    def fetch_resources(self) -> None:
        """Fetch resources via mock file, Python SDK, gcloud asset CLI, or per-service fallback."""
        if self.mock_assets_path and Path(self.mock_assets_path).is_file():
            self.raw_resources = json.loads(Path(self.mock_assets_path).read_text(encoding="utf-8"))
            self.coverage["Cloud Asset Inventory (Resources)"] = "✅ Scanned (Mock Fixture)"
            return

        # 1. Try Python SDK if available and not forced offline
        if not os.environ.get("SAIFGUARD_FORCE_GCLOUD"):
            try:
                from google.cloud import asset_v1
                from google.protobuf import field_mask_pb2
                from google.protobuf.json_format import MessageToJson

                client = asset_v1.AssetServiceClient()
                read_mask = field_mask_pb2.FieldMask(paths=["*"])
                results = client.search_all_resources(
                    request=asset_v1.SearchAllResourcesRequest(
                        scope=f"projects/{self.project_id}",
                        asset_types=AI_SECURITY_ASSET_TYPES,
                        read_mask=read_mask,
                    )
                )
                self.raw_resources = [json.loads(MessageToJson(r._pb)) for r in results]
                self.coverage["Cloud Asset Inventory (Resources)"] = f"✅ Scanned (Python SDK: {len(self.raw_resources)} assets)"
                return
            except Exception as sdk_err:
                sdk_err_str = str(sdk_err)
                if "SERVICE_DISABLED" in sdk_err_str or "PERMISSION_DENIED" in sdk_err_str or "403" in sdk_err_str:
                    # Proceed to gcloud fallback before giving up
                    pass

        # 2. Try gcloud asset search-all-resources with security-relevant asset types and full read-mask
        target_asset_types = ",".join([
            "storage.googleapis.com/Bucket",
            "compute.googleapis.com/BackendService",
            "compute.googleapis.com/ForwardingRule",
            "compute.googleapis.com/SecurityPolicy",
            "aiplatform.googleapis.com/Endpoint",
            "aiplatform.googleapis.com/Model",
            "aiplatform.googleapis.com/ReasoningEngine",
            "bigquery.googleapis.com/Dataset",
            "sqladmin.googleapis.com/Instance",
            "run.googleapis.com/Service",
            "iam.googleapis.com/ServiceAccountKey",
        ])
        ok, data, err = _run_gcloud_json([
            "asset",
            "search-all-resources",
            f"--scope=projects/{self.project_id}",
            f"--asset-types={target_asset_types}",
            "--read-mask=*",
        ], timeout=60)
        if ok and isinstance(data, list):
            self.raw_resources = data
            self.coverage["Cloud Asset Inventory (Resources)"] = f"✅ Scanned (gcloud CLI: {len(self.raw_resources)} assets)"
            return

        # 3. Graceful Degradation: Per-service gcloud commands fallback
        fallback_resources = []
        # Buckets
        b_ok, buckets, _ = _run_gcloud_json(["storage", "buckets", "list", f"--project={self.project_id}"])
        if b_ok and isinstance(buckets, list):
            for b in buckets:
                b_name = b.get("name", "")
                fallback_resources.append({
                    "name": f"//storage.googleapis.com/{b_name}",
                    "assetType": "storage.googleapis.com/Bucket",
                    "location": b.get("location", "global"),
                    "versionedResources": [{"resource": b}],
                })
        # Cloud Run services
        r_ok, run_svcs, _ = _run_gcloud_json(["run", "services", "list", f"--project={self.project_id}"])
        if r_ok and isinstance(run_svcs, list):
            for s in run_svcs:
                s_name = s.get("metadata", {}).get("name", "service")
                # Same region label gcloud itself reads (googlecloudsdk api_lib/run/k8s_object.py REGION_LABEL).
                s_region = (s.get("metadata", {}).get("labels") or {}).get("cloud.googleapis.com/location", "")
                run_entry: dict[str, Any] = {
                    "name": f"//run.googleapis.com/projects/{self.project_id}/services/{s_name}",
                    "assetType": "run.googleapis.com/Service",
                    "versionedResources": [{"resource": s}],
                }
                if s_region:
                    run_entry["name"] = f"//run.googleapis.com/projects/{self.project_id}/locations/{s_region}/services/{s_name}"
                    run_entry["location"] = s_region
                fallback_resources.append(run_entry)
        # Service Accounts
        sa_ok, sas, _ = _run_gcloud_json(["iam", "service-accounts", "list", f"--project={self.project_id}"])
        if sa_ok and isinstance(sas, list):
            for sa in sas:
                email = sa.get("email", "")
                fallback_resources.append({
                    "name": f"//iam.googleapis.com/projects/{self.project_id}/serviceAccounts/{email}",
                    "assetType": "iam.googleapis.com/ServiceAccount",
                    "versionedResources": [{"resource": sa}],
                })

        if fallback_resources:
            self.raw_resources = fallback_resources
            self.coverage["Cloud Asset Inventory (Resources)"] = f"⚠️ Degraded (gcloud service fallback: {len(fallback_resources)} assets)"
            self._add_visibility_gap(
                "Cloud Asset Inventory API",
                err or "Asset Inventory disabled or unauthorized; used partial gcloud service fallback.",
                f"gcloud services enable cloudasset.googleapis.com --project={self.project_id}",
                "roles/cloudasset.viewer",
            )
        else:
            self.coverage["Cloud Asset Inventory (Resources)"] = "❌ Not scanned (Permission Denied / Disabled)"
            self._add_visibility_gap(
                "Cloud Asset Inventory API",
                err or "Could not query Cloud Asset Inventory or fallback commands.",
                f"gcloud services enable cloudasset.googleapis.com --project={self.project_id}",
                "roles/cloudasset.viewer",
            )

    def fetch_iam_policies(self) -> None:
        """Fetch IAM policies via mock file, Python SDK, gcloud asset CLI, or get-iam-policy fallback."""
        if self.mock_iam_path and Path(self.mock_iam_path).is_file():
            self.raw_iam_policies = json.loads(Path(self.mock_iam_path).read_text(encoding="utf-8"))
            self.coverage["Cloud Asset Inventory (IAM Policies)"] = "✅ Scanned (Mock Fixture)"
            return

        # 1. Try Python SDK
        if not os.environ.get("SAIFGUARD_FORCE_GCLOUD"):
            try:
                from google.cloud import asset_v1
                from google.protobuf.json_format import MessageToJson

                client = asset_v1.AssetServiceClient()
                results = client.search_all_iam_policies(
                    request=asset_v1.SearchAllIamPoliciesRequest(scope=f"projects/{self.project_id}")
                )
                self.raw_iam_policies = [json.loads(MessageToJson(r._pb)) for r in results]
                self.coverage["Cloud Asset Inventory (IAM Policies)"] = f"✅ Scanned (Python SDK: {len(self.raw_iam_policies)} policies)"
                return
            except Exception:
                pass

        # 2. Try gcloud asset search-all-iam-policies
        ok, data, err = _run_gcloud_json(["asset", "search-all-iam-policies", f"--scope=projects/{self.project_id}"])
        if ok and isinstance(data, list):
            self.raw_iam_policies = data
            self.coverage["Cloud Asset Inventory (IAM Policies)"] = f"✅ Scanned (gcloud CLI: {len(self.raw_iam_policies)} policies)"
            return

        # 3. Fallback: gcloud projects get-iam-policy
        p_ok, p_data, p_err = _run_gcloud_json(["projects", "get-iam-policy", self.project_id])
        if p_ok and isinstance(p_data, dict):
            self.raw_iam_policies = [
                {
                    "resource": f"//cloudresourcemanager.googleapis.com/projects/{self.project_id}",
                    "policy": p_data,
                }
            ]
            self.coverage["Cloud Asset Inventory (IAM Policies)"] = "⚠️ Degraded (Project IAM policy only)"
            return

        self.coverage["Cloud Asset Inventory (IAM Policies)"] = "❌ Not scanned (Permission Denied)"
        self._add_visibility_gap(
            "IAM Policy Search",
            err or p_err or "Permission denied reading IAM policies.",
            f"gcloud services enable cloudasset.googleapis.com --project={self.project_id}",
            "roles/iam.securityReviewer",
        )

    def model_armor_locations(self) -> list[str]:
        """Locations to probe: `global` + regions of discovered Vertex AI / Cloud Run assets + user-supplied ones."""
        candidates = ["global"]
        for asset in self.raw_resources:
            asset_type = str(asset.get("assetType", ""))
            if not asset_type.startswith(("aiplatform.googleapis.com/", "run.googleapis.com/")):
                continue
            loc = str(asset.get("location") or "")
            if not loc:
                m = re.search(r"/locations/([^/]+)/", str(asset.get("name", "")))
                loc = m.group(1) if m else ""
            candidates.append(loc)
        candidates.extend(self.extra_model_armor_locations)

        locations: list[str] = []
        for loc in candidates:
            loc = loc.strip().lower()
            if loc and _LOCATION_RE.match(loc) and loc not in locations:
                locations.append(loc)
        return locations

    def _mark_model_armor_unreadable(self, coverage_status: str, error_detail: str) -> None:
        self.model_armor_readable = False
        self.coverage["Model Armor Guardrails API"] = coverage_status
        self._add_visibility_gap(
            "Model Armor API",
            error_detail,
            f"gcloud services enable modelarmor.googleapis.com --project={self.project_id}",
            MODEL_ARMOR_VIEWER_ROLES,
        )

    def fetch_model_armor(self) -> None:
        """Query the Model Armor floor setting (global) and templates (regional endpoints) via REST or a mock file."""
        if self.mock_model_armor_path and Path(self.mock_model_armor_path).is_file():
            self.model_armor_data = json.loads(Path(self.mock_model_armor_path).read_text(encoding="utf-8"))
            self.coverage["Model Armor Guardrails API"] = "✅ Scanned (Mock Fixture)"
            self.model_armor_scope = "mock fixture"
            return
        if self.mock_assets_path:
            self.model_armor_data = {"templates": [], "floor_settings": []}
            self.coverage["Model Armor Guardrails API"] = "⚠️ Not Enabled / No Vertex Guardrails Configured (Mock)"
            self.model_armor_scope = "mock fixture"
            return

        template_locations = [loc for loc in self.model_armor_locations() if loc != "global"]
        token = _get_gcloud_access_token()
        if not token:
            self._mark_model_armor_unreadable(
                "❌ Not scanned (no gcloud auth token)",
                "No gcloud access token (`gcloud auth print-access-token` failed); Model Armor floor settings and "
                "templates could not be read, so their absence cannot be confirmed.",
            )
            return

        ssl_ctx = _build_ssl_context()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        project = urllib.parse.quote(self.project_id, safe="")
        templates: list[Any] = []
        floor_settings: list[Any] = []
        answered: list[str] = []
        problems: list[str] = []  # 401/403, 5xx, timeouts -> the result is not conclusive
        unavailable: list[str] = []  # regional endpoint does not resolve -> Model Armor not offered there

        # 1. Floor setting: singleton under the global location, served by the global endpoint.
        fs_url = f"{MODEL_ARMOR_GLOBAL_ENDPOINT}/v1/projects/{project}/locations/global/floorSetting"
        status, payload, err = _http_get_json(fs_url, headers, ssl_ctx)
        if status == 200 and isinstance(payload, dict):
            answered.append("floorSetting")
            floor_settings.append(payload)
            fs_state = "enforced" if _floor_setting_enforced(payload) else "not enforced"
        elif status == 404:
            answered.append("floorSetting")
            fs_state = "not configured"
        else:
            problems.append(f"floorSetting: {'HTTP ' + str(status) + ' ' if status else ''}{err}".strip())
            fs_state = "unreadable"

        # 2. Templates: one regional / multi-regional endpoint per location.
        for loc in template_locations:
            base_url = f"{_model_armor_regional_endpoint(loc)}/v1/projects/{project}/locations/{loc}/templates"
            page_token = ""
            for _ in range(_MAX_TEMPLATE_PAGES):
                url = f"{base_url}?pageToken={urllib.parse.quote(page_token, safe='')}" if page_token else base_url
                status, payload, err = _http_get_json(url, headers, ssl_ctx)
                if status == 200 and isinstance(payload, dict):
                    templates.extend(payload.get("templates", []) or [])
                    page_token = payload.get("nextPageToken") or ""
                    if page_token:
                        continue
                    answered.append(f"templates@{loc}")
                elif status == 404:
                    answered.append(f"templates@{loc}")
                elif status is None and err.startswith("DNS_UNRESOLVED"):
                    unavailable.append(loc)
                else:
                    problems.append(f"templates@{loc}: {'HTTP ' + str(status) + ' ' if status else ''}{err}".strip())
                break

        self.model_armor_data = {"templates": templates, "floor_settings": floor_settings}
        probed = ", ".join(template_locations) if template_locations else "none (no Vertex AI / Cloud Run regions discovered; use --model-armor-locations)"
        self.model_armor_scope = f"floor setting: global; templates: {probed}"
        details = f"floor setting: {fs_state}; templates: {len(templates)} found in [{probed}]"
        if unavailable:
            details += f"; no regional endpoint for: {', '.join(unavailable)}"

        configured = bool(templates) or any(_floor_setting_enforced(fs) for fs in floor_settings)
        if problems and not configured:
            prefix = "⚠️ Partial" if answered else "❌ Not scanned"
            self._mark_model_armor_unreadable(
                f"{prefix} ({'; '.join(problems)[:240]})",
                "Model Armor could not be fully read, so missing guardrails cannot be confirmed: " + "; ".join(problems),
            )
            return
        if problems:
            self.coverage["Model Armor Guardrails API"] = f"⚠️ Partial ({details}; errors: {'; '.join(problems)[:200]})"
        else:
            self.coverage["Model Armor Guardrails API"] = f"✅ Scanned ({details})"

    def _extract_inner_resource(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Extract the underlying versioned resource dict from a Cloud Asset wrapper."""
        v_list = asset.get("versionedResources", [])
        if v_list and isinstance(v_list, list) and isinstance(v_list[0], dict):
            return v_list[0].get("resource", {})
        return asset

    def _cloud_armor_remediation(self, res_name: str) -> str:
        """GA commands: policy with preconfigured WAF rules + per-client rate limiting, then attach it."""
        regional = re.search(r"/regions/([^/]+)/backendServices/([^/]+)$", res_name)
        if regional:
            backend = regional.group(2)
            scope_flag = f"--region={regional.group(1)}"
            rule_scope = f" --region={regional.group(1)}"
        else:
            backend = res_name.split("/")[-1]
            scope_flag = "--global"
            rule_scope = ""
        policy = "saifguard-waf-policy"
        p = self.project_id
        return (
            "Create a Cloud Armor policy with preconfigured OWASP CRS WAF rules and per-client rate limiting, then attach it "
            "(external Application Load Balancer backends; tune thresholds, and add `--preview` to a rule to log matches "
            "before enforcing):\n"
            "```bash\n"
            f"gcloud compute security-policies create {policy} --description='SAIFGuard baseline WAF and rate limiting' {scope_flag} --project={p}\n"
            f"gcloud compute security-policies rules create 1000 --security-policy={policy} "
            f"--expression=\"evaluatePreconfiguredWaf('sqli-v33-stable', {{'sensitivity': 1}})\" --action=deny-403{rule_scope} --project={p}\n"
            f"gcloud compute security-policies rules create 1001 --security-policy={policy} "
            f"--expression=\"evaluatePreconfiguredWaf('xss-v33-stable', {{'sensitivity': 1}})\" --action=deny-403{rule_scope} --project={p}\n"
            f"gcloud compute security-policies rules create 2000 --security-policy={policy} --src-ip-ranges='*' --action=throttle "
            f"--rate-limit-threshold-count=100 --rate-limit-threshold-interval-sec=60 --conform-action=allow "
            f"--exceed-action=deny-429 --enforce-on-key=ip{rule_scope} --project={p}\n"
            f"gcloud compute backend-services update {backend} --security-policy={policy} {scope_flag} --project={p}\n"
            "```"
        )

    def _sa_key_remediation(self, res_name: str) -> str:
        """Disable first (reversible), then delete (irreversible), using the SA email parsed from the key name."""
        m = re.search(r"/serviceAccounts/([^/]+)/keys/([^/]+)$", res_name)
        sa_email, key_id = (m.group(1), m.group(2)) if m else ("<SERVICE_ACCOUNT_EMAIL>", res_name.split("/")[-1])
        p = self.project_id
        return (
            "Disable the static key first (reversible with `gcloud iam service-accounts keys enable`) and confirm nothing "
            "breaks, then delete it and migrate the workload to Workload Identity Federation or an attached service account:\n"
            "```bash\n"
            f"gcloud iam service-accounts keys disable {key_id} --iam-account={sa_email} --project={p}\n"
            "# ⚠️ irreversible: a deleted key cannot be restored\n"
            f"gcloud iam service-accounts keys delete {key_id} --iam-account={sa_email} --project={p}\n"
            "```"
        )

    def _public_iam_remediation(self, res_target: str, role: str, public_members: list[str], has_condition: bool) -> tuple[str, str]:
        """Return (remediation, console_url) for a binding that grants a role to allUsers / allAuthenticatedUsers."""
        asset_type = _asset_type_for_resource(res_target)
        console_url = build_console_url(asset_type, res_target, self.project_id)
        all_flag = " --all" if has_condition else ""
        commands: list[str] = []
        if asset_type == "cloudresourcemanager.googleapis.com/Project":
            commands = [
                f"gcloud projects remove-iam-policy-binding {self.project_id} --member='{m}' --role='{role}'{all_flag}"
                for m in public_members
            ]
        elif asset_type == "storage.googleapis.com/Bucket":
            bucket = res_target.rsplit("/", 1)[-1]
            commands = [
                f"gcloud storage buckets remove-iam-policy-binding gs://{bucket} --member='{m}' --role='{role}'{all_flag}"
                for m in public_members
            ]
        elif asset_type == "run.googleapis.com/Service":
            run_m = re.search(r"/locations/([^/]+)/services/([^/]+)$", res_target)
            if run_m:
                commands = [
                    f"gcloud run services remove-iam-policy-binding {run_m.group(2)} --region={run_m.group(1)} "
                    f"--member='{m}' --role='{role}' --project={self.project_id}{all_flag}"
                    for m in public_members
                ]
        if commands:
            remediation = (
                "Remove the public binding(s) after confirming no anonymous consumer depends on them:\n"
                "```bash\n" + "\n".join(commands) + "\n```"
            )
        else:
            remediation = (
                f"Remove {', '.join(public_members)} from role '{role}' in this resource's IAM policy "
                f"(Google Cloud console: open the resource > Permissions). No GA command is suggested for this resource type."
            )
        return remediation, console_url

    def compress_and_evaluate(self) -> None:
        """Run deterministic SAIF rules and compress the resource payload by stripping noise."""
        has_vertex_or_ai = False

        for asset in self.raw_resources:
            asset_type = asset.get("assetType", "")
            res_name = asset.get("name", "")
            location = asset.get("location", "global")
            inner = self._extract_inner_resource(asset)

            # 1. Drop Noise Resources (Inactive Cloud Run Revisions & Default Regional Subnets/Routes)
            if asset_type == "run.googleapis.com/Revision":
                continue
            if asset_type in ("compute.googleapis.com/Route", "compute.googleapis.com/Subnetwork"):
                short = res_name.split("/")[-1]
                if short.startswith("default-route-") or short == "default":
                    continue

            console_url = build_console_url(asset_type, res_name, self.project_id)
            alerts: list[str] = []

            if "aiplatform.googleapis.com" in asset_type:
                has_vertex_or_ai = True

            # Rule 1: GCP_CLOUD_ARMOR_MISSING on BackendServices
            if asset_type == "compute.googleapis.com/BackendService":
                load_balancing_scheme = inner.get("loadBalancingScheme")
                sec_policy = inner.get("securityPolicy", "")
                if not sec_policy and not load_balancing_scheme:
                    # Exposure unknown: never escalate missing data to CRITICAL.
                    alerts.append("UNVERIFIED_GCP_CLOUD_ARMOR_MISSING")
                elif "EXTERNAL" in str(load_balancing_scheme) and not sec_policy:
                    alerts.append("GCP_CLOUD_ARMOR_MISSING")
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_CLOUD_ARMOR_MISSING",
                            severity="CRITICAL",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM04: Model Denial of Service / WAF",
                            category="Network & WAF",
                            title="External Load Balancer Backend Missing Cloud Armor Security Policy",
                            description=f"Backend service '{res_name}' is exposed externally ({load_balancing_scheme}) without an attached Cloud Armor WAF security policy.",
                            remediation=self._cloud_armor_remediation(res_name),
                            location=res_name,
                            url=console_url,
                        )
                    )

            # Rule 2: GCP_CMEK_MISSING on Buckets, Cloud SQL, BigQuery, Vertex AI
            if asset_type == "storage.googleapis.com/Bucket":
                enc = inner.get("encryption", {}) or {}
                kms_key = enc.get("defaultKmsKeyName") or inner.get("kmsKeyName")
                if not kms_key:
                    alerts.append("GCP_CMEK_MISSING")
                    is_ai_bucket = is_ai_bucket_name(res_name.split("/")[-1])
                    sev = "HIGH" if is_ai_bucket else "MEDIUM"
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_CMEK_MISSING",
                            severity=sev,
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM02: Sensitive Information Disclosure",
                            category="Data Encryption",
                            title="Cloud Storage Bucket Lacks Customer-Managed Encryption Key (CMEK)",
                            description=f"Bucket '{res_name}' uses Google-managed default encryption instead of Cloud KMS CMEK.",
                            remediation=f"Configure a Cloud KMS key on the bucket:\n```bash\ngcloud storage buckets update gs://{res_name.split('/')[-1]} --default-encryption-key=projects/{self.project_id}/locations/{location}/keyRings/saif-ring/cryptoKeys/saif-key\n```",
                            location=res_name,
                            url=console_url,
                        )
                    )

            elif asset_type == "sqladmin.googleapis.com/Instance":
                disk_enc = inner.get("diskEncryptionConfiguration", {}) or {}
                kms_key = disk_enc.get("kmsKeyName")
                if not kms_key:
                    alerts.append("GCP_CMEK_MISSING")
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_CMEK_MISSING",
                            severity="HIGH",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM02: Sensitive Information Disclosure",
                            category="Data Encryption",
                            title="Cloud SQL Instance Lacks CMEK Encryption",
                            description=f"Cloud SQL instance '{res_name}' does not configure a Customer-Managed Encryption Key (CMEK).",
                            remediation=f"Recreate or restore the Cloud SQL instance with `--disk-encryption-key` pointing to a Cloud KMS key in project `{self.project_id}`.",
                            location=res_name,
                            url=console_url,
                        )
                    )

            elif asset_type == "bigquery.googleapis.com/Dataset":
                enc = inner.get("defaultEncryptionConfiguration", {}) or {}
                kms_key = enc.get("kmsKeyName")
                if not kms_key:
                    alerts.append("GCP_CMEK_MISSING")
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_CMEK_MISSING",
                            severity="MEDIUM",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM02: Sensitive Information Disclosure",
                            category="Data Encryption",
                            title="BigQuery Dataset Lacks Default CMEK Encryption",
                            description=f"BigQuery dataset '{res_name}' does not configure a default KMS CMEK key.",
                            remediation=f"Update dataset default KMS key:\n```bash\nbq update --default_kms_key=projects/{self.project_id}/locations/{location}/keyRings/saif-ring/cryptoKeys/saif-key {self.project_id}:{res_name.split('/')[-1]}\n```",
                            location=res_name,
                            url=console_url,
                        )
                    )

            # Rule 3: GCP_SA_USER_KEY_EXPOSED
            if asset_type == "iam.googleapis.com/ServiceAccountKey":
                key_type = inner.get("keyType")
                if not key_type:
                    # Key type unknown: never escalate missing data to HIGH.
                    alerts.append("UNVERIFIED_GCP_SA_USER_KEY_EXPOSED")
                elif key_type == "USER_MANAGED":
                    alerts.append("GCP_SA_USER_KEY_EXPOSED")
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_SA_USER_KEY_EXPOSED",
                            severity="HIGH",
                            saif_pillar="Pillar 6: Contextual Governance",
                            owasp_category="LLM06: Excessive Agency / Credential Risk",
                            category="Identity & Access",
                            title="User-Managed Service Account Key Detected",
                            description=f"Service account key '{res_name}' is user-managed and does not auto-rotate, creating a high credential exfiltration risk.",
                            remediation=self._sa_key_remediation(res_name),
                            location=res_name,
                            url=console_url,
                        )
                    )

            # Rule 4: GCP_VERTEX_PUBLIC_ENDPOINT
            if asset_type in ("aiplatform.googleapis.com/Endpoint", "aiplatform.googleapis.com/ReasoningEngine"):
                network = inner.get("network", "")
                psc_config = inner.get("privateServiceConnectConfig", {})
                if not network and not psc_config:
                    alerts.append("GCP_VERTEX_PUBLIC_ENDPOINT")
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_VERTEX_PUBLIC_ENDPOINT",
                            severity="HIGH",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM01: Prompt Injection / Network Exposure",
                            category="AI Endpoint Security",
                            title="Vertex AI Endpoint Exposed Without Private Service Connect or VPC Peering",
                            description=f"Vertex AI resource '{res_name}' is accessible over public endpoints without private VPC peering or Private Service Connect.",
                            remediation=f"Deploy the Vertex AI Endpoint with `--network` or Private Service Connect (`--enable-private-service-connect`) and place `aiplatform.googleapis.com` inside a VPC Service Controls perimeter.",
                            location=res_name,
                            url=console_url,
                        )
                    )

            # Build compressed resource entry
            pruned_inner = {k: v for k, v in inner.items() if k not in STRIP_METADATA_KEYS}
            self.compressed_resources.append(
                {
                    "resource": res_name,
                    "type": asset_type.split("/")[-1],
                    "location": location,
                    "console_url": console_url,
                    "deterministic_alerts": alerts,
                    "properties": pruned_inner,
                }
            )

        # Rule 5: Evaluate IAM Policies (GCP_IAM_PRIMITIVE_OR_PUBLIC)
        for iam_entry in self.raw_iam_policies:
            res_target = iam_entry.get("resource", f"projects/{self.project_id}")
            policy = iam_entry.get("policy", {})
            bindings = policy.get("bindings", [])
            for b in bindings:
                role = b.get("role", "")
                members = b.get("members", [])
                # Public access check
                public_members = [m for m in members if m in PUBLIC_PRINCIPALS]
                if public_members:
                    remediation, console_url = self._public_iam_remediation(res_target, role, public_members, bool(b.get("condition")))
                    self.findings.append(
                        SAIFFinding(
                            rule_id="GCP_IAM_PRIMITIVE_OR_PUBLIC",
                            severity="CRITICAL",
                            saif_pillar="Pillar 4: Harmonized Controls",
                            owasp_category="LLM06: Excessive Agency",
                            category="Identity & Access",
                            title=f"Public IAM Access ({role}) Granted to allUsers / allAuthenticatedUsers",
                            description=f"Resource '{res_target}' grants role '{role}' to public principals ({', '.join(public_members)}).",
                            remediation=remediation,
                            location=res_target,
                            url=console_url,
                        )
                    )
                # Primitive role granted to Service Account
                if role in ("roles/owner", "roles/editor"):
                    sa_members = [m for m in members if m.startswith("serviceAccount:")]
                    if sa_members:
                        asset_type = _asset_type_for_resource(res_target) or "cloudresourcemanager.googleapis.com/Project"
                        self.findings.append(
                            SAIFFinding(
                                rule_id="GCP_IAM_PRIMITIVE_OR_PUBLIC",
                                severity="HIGH",
                                saif_pillar="Pillar 4: Harmonized Controls",
                                owasp_category="LLM06: Excessive Agency",
                                category="Identity & Access",
                                title=f"Service Account Granted Overly Permissive Primitive Role ({role})",
                                description=f"Resource '{res_target}' grants primitive role '{role}' to service account(s): {', '.join(sa_members[:3])}.",
                                remediation=f"Replace primitive role '{role}' with predefined least-privilege roles (e.g., `roles/aiplatform.user`, `roles/storage.objectViewer`).",
                                location=res_target,
                                url=build_console_url(asset_type, res_target, self.project_id),
                            )
                        )

        # Rule 6: GCP_MODEL_ARMOR_MISSING (only when the API answered: "can't see it" is not "it's missing")
        templates = self.model_armor_data.get("templates", [])
        floor_settings = self.model_armor_data.get("floor_settings", [])
        configured = bool(templates) or any(_floor_setting_enforced(fs) for fs in floor_settings)
        if self.model_armor_readable and not configured:
            sev = "HIGH" if has_vertex_or_ai else "MEDIUM"
            floor_uri = f"projects/{self.project_id}/locations/global/floorSetting"
            scope = f" (checked: {self.model_armor_scope})" if self.model_armor_scope else ""
            self.findings.append(
                SAIFFinding(
                    rule_id="GCP_MODEL_ARMOR_MISSING",
                    severity=sev,
                    saif_pillar="Pillar 3: Automated Defenses",
                    owasp_category="LLM01: Prompt Injection",
                    category="AI Guardrails",
                    title="Model Armor Floor Settings & Templates Not Configured",
                    description=(
                        f"Project '{self.project_id}' has no enforced Model Armor floor setting and no prompt/response "
                        f"sanitization templates{scope}. Folder- or organization-level floor settings are not evaluated."
                    ),
                    remediation=(
                        "Configure Model Armor in the Google Cloud console (*Security > Model Armor*) or with GA gcloud, "
                        "then create templates in the regions your AI workloads use:\n"
                        "```bash\n"
                        f"gcloud model-armor floorsettings describe --full-uri='{floor_uri}'\n"
                        f"gcloud model-armor floorsettings update --full-uri='{floor_uri}' --enable-floor-setting-enforcement=true "
                        "--malicious-uri-filter-settings-enforcement=ENABLED --pi-and-jailbreak-filter-settings-enforcement=ENABLED "
                        "--pi-and-jailbreak-filter-settings-confidence-level=MEDIUM_AND_ABOVE\n"
                        "```\n"
                        f"REST: `GET {MODEL_ARMOR_GLOBAL_ENDPOINT}/v1/{floor_uri}`; templates are served by regional endpoints "
                        "(`https://modelarmor.<LOCATION>.rep.googleapis.com`)."
                    ),
                    location=floor_uri,
                    url=f"https://console.cloud.google.com/security/modelarmor?project={self.project_id}",
                )
            )

    def scan(self) -> dict[str, Any]:
        """Execute full discovery, rule evaluation, and compression pipeline."""
        self.fetch_resources()
        self.fetch_iam_policies()
        self.fetch_model_armor()
        self.compress_and_evaluate()

        raw_bytes = len(json.dumps(self.raw_resources)) + len(json.dumps(self.raw_iam_policies))
        comp_bytes = len(json.dumps(self.compressed_resources))
        reduction = round((1.0 - (comp_bytes / max(raw_bytes, 1))) * 100.0, 1) if raw_bytes > 0 else 0.0

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99,
        )

        return {
            "project_id": self.project_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "coverage": self.coverage,
            "stats": {
                "raw_resources_count": len(self.raw_resources),
                "compressed_resources_count": len(self.compressed_resources),
                "raw_payload_bytes": raw_bytes,
                "compressed_payload_bytes": comp_bytes,
                "compression_reduction_pct": reduction,
                "findings_count": len(sorted_findings),
            },
            "findings": [asdict(f) for f in sorted_findings],
            "compressed_topology": self.compressed_resources,
            "model_armor": self.model_armor_data,
        }


def _format_topology_section(topology: list[dict[str, Any]]) -> list[str]:
    """Compact 'Discovered Topology' table so the markdown output supports Cloud-to-Code drift checks."""
    lines = ["## 4. Discovered Topology (Cloud-to-Code Drift Input)", ""]
    if not topology:
        lines.extend(["_No resources were discovered (see Audit Coverage above)._", ""])
        return lines
    ordered = sorted(topology, key=lambda r: 0 if r.get("deterministic_alerts") else 1)  # alerting resources first
    shown = ordered[:TOPOLOGY_MARKDOWN_ROW_LIMIT]
    lines.extend([
        f"Compressed inventory of the {len(topology)} discovered resources (noise such as Cloud Run revisions and default "
        "routes removed). Compare it with local IaC and code to spot unmanaged (\"Shadow AI\") resources.",
        "",
        "| # | Resource | Type | Location | Console | Deterministic Alerts |",
        "| ---: | :--- | :--- | :--- | :--- | :--- |",
    ])
    for idx, res in enumerate(shown, start=1):
        alerts = ", ".join(f"`{_md_cell(a)}`" for a in res.get("deterministic_alerts") or []) or "—"
        url = res.get("console_url", "")
        console = f"[Open]({url})" if url else "—"
        lines.append(
            f"| {idx} | `{_md_cell(res.get('resource', ''))}` | {_md_cell(res.get('type', ''))} | "
            f"{_md_cell(res.get('location', ''))} | {console} | {alerts} |"
        )
    if len(topology) > len(shown):
        lines.extend([
            "",
            f"_Truncated: showing {len(shown)} of {len(topology)} resources (resources with deterministic alerts first). "
            "Run `gcp_scan.py --format=json` for the full `compressed_topology`._",
        ])
    lines.append("")
    return lines


def format_gcp_markdown_report(scan_result: dict[str, Any]) -> str:
    """Render a standardized SAIF_AUDIT_REPORT.md markdown document from scan results."""
    project_id = scan_result.get("project_id", "unknown")
    findings = scan_result.get("findings", [])
    coverage = scan_result.get("coverage", {})
    stats = scan_result.get("stats", {})

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    if counts["CRITICAL"] > 0:
        posture = "🔴 FAIL (Critical SAIF Security Violations Detected)"
    elif counts["HIGH"] > 0:
        posture = "🟠 CONDITIONAL PASS (High-Severity Remediation Required)"
    else:
        posture = "🟢 PASS (Strong SAIF Baseline Posture)"

    pillars = {
        "Pillar 1: Strong Foundations": {"crit": 0, "high": 0, "med": 0},
        "Pillar 2: Detection & Monitoring": {"crit": 0, "high": 0, "med": 0},
        "Pillar 3: Automated Defenses": {"crit": 0, "high": 0, "med": 0},
        "Pillar 4: Harmonized Controls": {"crit": 0, "high": 0, "med": 0},
        "Pillar 5: Continuous Evaluation": {"crit": 0, "high": 0, "med": 0},
        "Pillar 6: Contextual Governance": {"crit": 0, "high": 0, "med": 0},
    }
    for f in findings:
        p_name = f.get("saif_pillar", "")
        sev = f.get("severity", "LOW")
        for key in pillars:
            if key.split(":")[0] in p_name:
                if sev == "CRITICAL":
                    pillars[key]["crit"] += 1
                elif sev == "HIGH":
                    pillars[key]["high"] += 1
                elif sev == "MEDIUM":
                    pillars[key]["med"] += 1

    lines = [
        f"# 🛡️ SAIFGuard Security Audit Report — GCP Project `{project_id}`",
        "",
        f"**Overall Posture Score**: {posture}  ",
        f"**Audit Timestamp**: `{scan_result.get('timestamp', '')}`  ",
        f"**Resources Inspected**: `{stats.get('raw_resources_count', 0)}` assets (`{stats.get('compression_reduction_pct', 0)}%` payload compression)  ",
        f"**Total Findings**: `{len(findings)}` (`{counts['CRITICAL']}` Critical, `{counts['HIGH']}` High, `{counts['MEDIUM']}` Medium, `{counts['LOW']}` Low)",
        "",
        "---",
        "",
        "## 1. Executive Summary Scorecard (Google SAIF 6 Pillars)",
        "",
        "| SAIF Pillar | Critical | High | Medium | Status |",
        "| :--- | :---: | :---: | :---: | :--- |",
    ]
    for p_label, p_counts in pillars.items():
        status = "🔴 Action Required" if p_counts["crit"] > 0 else ("🟠 Review Needed" if p_counts["high"] > 0 else "🟢 Compliant")
        lines.append(f"| **{p_label}** | {p_counts['crit']} | {p_counts['high']} | {p_counts['med']} | {status} |")

    lines.extend([
        "",
        "---",
        "",
        "## 2. Audit Coverage & API Visibility",
        "",
        "| GCP Security Sensor / API | Audit Status |",
        "| :--- | :--- |",
    ])
    for api_label, cov_status in coverage.items():
        lines.append(f"| **{api_label}** | {cov_status} |")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Detailed Security Findings & GA Remediation",
        "",
    ])

    if not findings:
        lines.append("✅ **No deterministic SAIF violations detected across scanned resources.**")
    else:
        for idx, f in enumerate(findings, start=1):
            sev = f.get("severity", "LOW")
            icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🟢"))
            url = f.get("url", "")
            loc = f.get("location", "")
            loc_link = f"[`{loc}`]({url})" if url else f"`{loc}`"
            lines.extend([
                f"### {idx}. {icon} [{sev}] {f.get('title')} (`{f.get('rule_id')}`)",
                f"- **SAIF Pillar**: {f.get('saif_pillar')}",
                f"- **OWASP LLM Category**: {f.get('owasp_category')}",
                f"- **Resource Location**: {loc_link}",
                f"- **Risk Description**: {f.get('description')}",
                f"- **GA Remediation**:",
                f"{f.get('remediation')}",
                "",
            ])

    lines.extend(["---", ""])
    lines.extend(_format_topology_section(scan_result.get("compressed_topology") or []))

    lines.extend([
        "---",
        "",
        "## 5. Formal Security Sign-Off Block",
        "",
        "| Role | Name / Identifier | Decision | Date |",
        "| :--- | :--- | :--- | :--- |",
        "| **FDE Security Lead** | `SAIFGuard Automated Auditor` | Pending Remediation Review | — |",
        "| **Customer CISO / AppSec Lead** | — | ⬜ Approved / ⬜ Conditional | — |",
        "",
    ])

    return "\n".join(lines)


def format_sarif(scan_result: dict[str, Any]) -> str:
    """Export findings in standard SARIF 2.1.0 format for GitHub / GitLab code scanning."""
    findings = scan_result.get("findings", [])
    results = []
    for f in findings:
        sev = f.get("severity", "LOW")
        level = "error" if sev in ("CRITICAL", "HIGH") else "warning"
        results.append({
            "ruleId": f.get("rule_id"),
            "level": level,
            "message": {"text": f"{f.get('title')}: {f.get('description')}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("location", "gcp-project")},
                    }
                }
            ],
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SAIFGuard GCP Security Scanner",
                        "version": "0.2.0",
                        "informationUri": "https://saif.google",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def scan_gcp_project(
    project_id: str,
    mock_assets_path: str | None = None,
    mock_iam_path: str | None = None,
    mock_model_armor_path: str | None = None,
    model_armor_locations: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Programmatic entrypoint for ADK tools and CLI."""
    scanner = GCPProjectScanner(
        project_id=project_id,
        mock_assets_path=mock_assets_path,
        mock_iam_path=mock_iam_path,
        mock_model_armor_path=mock_model_armor_path,
        model_armor_locations=model_armor_locations,
    )
    return scanner.scan()


def parse_location_list(raw: str | None) -> list[str]:
    """Parse a comma-separated location list, dropping (and reporting) malformed entries."""
    locations: list[str] = []
    for item in (raw or "").split(","):
        loc = item.strip().lower()
        if not loc:
            continue
        if _LOCATION_RE.match(loc):
            locations.append(loc)
        else:
            print(f"Warning: ignoring invalid Model Armor location '{item.strip()}'", file=sys.stderr)
    return locations


def main() -> int:
    parser = argparse.ArgumentParser(description="SAIFGuard Deterministic GCP Project Scanner")
    parser.add_argument("--project", required=True, help="Target GCP Project ID to audit")
    parser.add_argument("--format", choices=["markdown", "json", "sarif", "summary"], default="markdown")
    parser.add_argument("--output", default=None, help="Write report output to file (e.g. SAIF_AUDIT_REPORT.md)")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)
    parser.add_argument("--mock-assets", default=None, help="Path to mock Cloud Asset JSON fixture")
    parser.add_argument("--mock-iam", default=None, help="Path to mock IAM policies JSON fixture")
    parser.add_argument("--mock-model-armor", default=None, help="Path to mock Model Armor JSON fixture")
    parser.add_argument(
        "--model-armor-locations",
        default=None,
        help="Extra comma-separated Model Armor template locations to probe (e.g. us-central1,eu); "
        "'global' and the regions of discovered Vertex AI / Cloud Run assets are always probed",
    )

    args = parser.parse_args()
    result = scan_gcp_project(
        project_id=args.project,
        mock_assets_path=args.mock_assets,
        mock_iam_path=args.mock_iam,
        mock_model_armor_path=args.mock_model_armor,
        model_armor_locations=parse_location_list(args.model_armor_locations),
    )

    if args.format == "json":
        out_text = json.dumps(result, indent=2)
    elif args.format == "sarif":
        out_text = format_sarif(result)
    elif args.format == "summary":
        findings = result.get("findings", [])
        out_text = f"GCP Project '{args.project}': {len(findings)} SAIF findings detected."
    else:
        out_text = format_gcp_markdown_report(result)

    if args.output:
        Path(args.output).write_text(out_text, encoding="utf-8")
        print(f"✓ Saved SAIF GCP Audit Report to: {args.output}")
    else:
        print(out_text)

    if args.fail_on:
        thresholds = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_idx = thresholds.index(args.fail_on)
        for f in result.get("findings", []):
            sev = f.get("severity", "LOW")
            if sev in thresholds and thresholds.index(sev) >= min_idx:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
