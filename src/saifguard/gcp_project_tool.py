import functools
import json
import logging
import os
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from google.adk.tools import ToolContext
from google import genai
from google.cloud import asset_v1
from google.genai import types
from google.protobuf import field_mask_pb2
from google.protobuf.json_format import MessageToJson

from saifguard.config import (
    DEBUG_MODE,
    GENERATE_DASHBOARD,
    GOOGLE_SEARCH_SAIF_PROMPT,
    MODEL,
    PROJECT_ID,
    REGION,
    VERTEX_LOCATION,
)
from saifguard.dashboard_tool import publish_dashboard_async
from saifguard.google_search_tool import google_search_tool
from saifguard.progress import emit_progress
from saifguard.skill_loader import load_skill_instructions

LOGGER = logging.getLogger(__name__)

_ASSET_CLIENT = None
_GENAI_CLIENT = None


def _get_asset_client():
    global _ASSET_CLIENT
    if _ASSET_CLIENT is None:
        _ASSET_CLIENT = asset_v1.AssetServiceClient()
    return _ASSET_CLIENT


def _get_genai_client():
    global _GENAI_CLIENT
    if _GENAI_CLIENT is None:
        _GENAI_CLIENT = genai.Client(
            vertexai=True,
            project=PROJECT_ID,
            location=VERTEX_LOCATION,
        )
    return _GENAI_CLIENT


_FALLBACK_DISCOVERY_PROMPT = """
<OBJECTIVE_AND_PERSONA>
You are an expert Application Security (AppSec) engineer. 
Your task is to perform a thorough security audit on this application's deployment using the provided GCP resources.
</OBJECTIVE_AND_PERSONA>
"""

DISCOVERY_TOOL_SYSTEM_PROMPT = load_skill_instructions(
    "gcp_security_audit", _FALLBACK_DISCOVERY_PROMPT
)

DISCOVERY_TOOL_QUERY_PROMPT = "Inspect the GCP project assets provided and generate detailed recommendations to improve the overall security posture. Use the provided Google Search results for the latest SAIF compliance recommendations as a reference. In all remediation steps, only provide production-ready GA gcloud commands, Cloud Console steps, or REST APIs; do NOT recommend gcloud alpha or beta commands."

AI_SECURITY_ASSET_TYPES = [
    # --- Core GCP Infrastructure & Security ---
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
    # --- AI/ML & Agent Platform (Agent Platform Runtime / Reasoning Engine) ---
    "aiplatform.googleapis.com/Endpoint",
    "aiplatform.googleapis.com/Model",
    "aiplatform.googleapis.com/ReasoningEngine",
    # Note: Model Armor (FloorSetting & Template) is inspected via REST API in _fetch_model_armor_security()
    # --- Secrets & Encryption (SAIF Controls) ---
    "secretmanager.googleapis.com/Secret",
    "cloudkms.googleapis.com/CryptoKey",
    # --- API Gateways exposing AI endpoints ---
    "apigateway.googleapis.com/Gateway",
]


@functools.lru_cache(maxsize=1)
def _get_cached_saif_recommendations() -> str:
    """Retrieve SAIF framework recommendations with in-memory and disk caching."""
    cache_file = os.path.join(tempfile.gettempdir(), "saif_recommendations_cache.txt")
    if os.path.exists(cache_file):
        try:
            if time.time() - os.path.getmtime(cache_file) < 86400:
                with open(cache_file, "r", encoding="utf-8") as f:
                    content = f.read()
                if content and "An exception occurred" not in content:
                    LOGGER.info("Loaded SAIF recommendations from disk cache.")
                    return content
        except Exception as e:
            LOGGER.warning(f"Could not read SAIF recommendations disk cache: {e}")

    result = google_search_tool(GOOGLE_SEARCH_SAIF_PROMPT)

    if result and "An exception occurred" not in str(result):
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                f.write(result)
            LOGGER.info(f"Saved SAIF recommendations to disk cache: {cache_file}")
        except Exception as e:
            LOGGER.warning(f"Could not write SAIF recommendations disk cache: {e}")

    return result


def _fetch_model_armor_security(gcp_project_id: str) -> dict:
    """Query Model Armor Templates and Floor Settings via direct REST API."""
    findings = {"templates": [], "floor_settings": []}
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession

        credentials, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        session = AuthorizedSession(credentials)
        locations = ["global", REGION] if REGION != "global" else ["global"]

        for loc in set(locations):
            # 1. Inspect Model Armor Templates
            templates_url = f"https://modelarmor.googleapis.com/v1/projects/{gcp_project_id}/locations/{loc}/templates"
            try:
                resp = session.get(templates_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    findings["templates"].extend(data.get("templates", []))
                elif resp.status_code not in (404, 403):
                    LOGGER.info(f"Model Armor Templates ({loc}) status: {resp.status_code}")
            except Exception as te:
                LOGGER.debug(f"Could not fetch Model Armor templates for {loc}: {te}")

            # 2. Inspect Model Armor Floor Settings
            floor_url = f"https://modelarmor.googleapis.com/v1/projects/{gcp_project_id}/locations/{loc}/floorSettings"
            try:
                resp = session.get(floor_url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    findings["floor_settings"].append(data)
                elif resp.status_code not in (404, 403):
                    LOGGER.info(f"Model Armor Floor Settings ({loc}) status: {resp.status_code}")
            except Exception as fe:
                LOGGER.debug(f"Could not fetch Model Armor floor settings for {loc}: {fe}")

    except Exception as e:
        LOGGER.info(f"Model Armor inspection skipped: {e}")

    return findings


def gcp_project_tool(gcp_project_id: str, tool_context: ToolContext = None) -> str:
    """Audit GCP resources in a target project for SAIF framework security compliance.

    Args:
        gcp_project_id: The target GCP Project ID to scan.
    """
    s_id = getattr(getattr(tool_context, "session", None), "id", None)
    LOGGER.info(f"Starting GCP Project Security Audit for project: {gcp_project_id} (session: {s_id})")
    start_time = time.time()
    asset_client = _get_asset_client()

    emit_progress(f"🔍 [1/3] Getting SAIF recommendations & scanning GCP resources for `{gcp_project_id}`...", session_id=s_id)

    try:
        def fetch_saif():
            return _get_cached_saif_recommendations()

        def fetch_assets():
            resources_list = []
            read_mask = field_mask_pb2.FieldMask(paths=["*"])
            results = asset_client.search_all_resources(
                request=asset_v1.SearchAllResourcesRequest(
                    scope=f"projects/{gcp_project_id}",
                    asset_types=AI_SECURITY_ASSET_TYPES,
                    read_mask=read_mask,
                )
            )
            for res in results:
                resources_list.append(res)
            return resources_list

        with ThreadPoolExecutor(max_workers=3) as executor:
            future_saif = executor.submit(fetch_saif)
            future_assets = executor.submit(fetch_assets)
            future_model_armor = executor.submit(lambda: _fetch_model_armor_security(gcp_project_id))

            saif_recommendations = future_saif.result()
            resources = future_assets.result()
            model_armor_data = future_model_armor.result()

        LOGGER.info(f"Parallel data fetching (SAIF, Asset Inventory & Model Armor) took {time.time() - start_time:.2f} seconds.")
        LOGGER.info(f"Asset Inventory found {len(resources)} resources.")

        emit_progress(f"📊 [2/3] Retrieved SAIF guidelines & {len(resources)} GCP resources.", session_id=s_id)
        emit_progress(f"🧠 [3/3] Inspecting resources & generating recommendations...", session_id=s_id)

        if resources:
            resources_as_dicts = [
                json.loads(MessageToJson(res._pb)) for res in resources
            ]
            asset_dump_text = json.dumps(resources_as_dicts, indent=2)
        else:
            asset_dump_text = "No resources were found in the project."

        contents = [
            types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT),
            types.Part.from_text(
                text=f"GCP Asset Inventory export:\n{asset_dump_text}"
            ),
            types.Part.from_text(
                text=f"Model Armor Guardrails & Configuration:\n{json.dumps(model_armor_data, indent=2)}"
            ),
            types.Part.from_text(
                text=f"LATEST SAIF RECOMMENDATIONS:\n{saif_recommendations}"
            ),
        ]

        if DEBUG_MODE:
            with open("asset_dump.txt", "w") as f:
                f.write(asset_dump_text)
            with open("saif_recommendations.txt", "w") as f:
                f.write(saif_recommendations)

        gen_start_time = time.time()
        client = _get_genai_client()
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                temperature=0.1,
            ),
        )
        LOGGER.info(f"Generating security report took {time.time() - gen_start_time:.2f} seconds.")
        LOGGER.info("Successfully received response from the model.")

        if GENERATE_DASHBOARD:
            emit_progress("📈 Publishing findings to Data Studio BigQuery dashboard...", session_id=s_id)
            publish_dashboard_async(response.text, gcp_project_id)

        return response.text

    except Exception as e:
        error_msg = f"An exception occurred while calling GCP project tool: {e}"
        LOGGER.error(error_msg)
        LOGGER.error(traceback.format_exc())
        return f"Tool Execution Failed: {error_msg}"
