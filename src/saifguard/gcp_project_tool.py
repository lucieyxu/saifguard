import functools
import json
import logging
import os
import tempfile
import time
import traceback
from pathlib import Path

from typing import Any

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any

from saifguard.config import (
    DEBUG_MODE,
    DEFAULT_REPORT_FILENAME,
    GOOGLE_SEARCH_SAIF_PROMPT,
    MODEL,
    PROJECT_ID,
    VERTEX_LOCATION,
)
from saifguard.google_search_tool import google_search_tool
from saifguard.progress import emit_progress
from saifguard.report_tool import save_markdown_report
from saifguard.skill_loader import load_skill_instructions
from saifguard.skills.saifguard.scripts.gcp_scan import (
    format_gcp_markdown_report,
    scan_gcp_project,
)

LOGGER = logging.getLogger(__name__)

_GENAI_CLIENT = None


def _get_genai_client():
    global _GENAI_CLIENT
    if _GENAI_CLIENT is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if api_key:
            _GENAI_CLIENT = genai.Client(api_key=api_key)
        else:
            _GENAI_CLIENT = genai.Client(
                vertexai=True,
                project=PROJECT_ID,
                location=VERTEX_LOCATION,
            )
    return _GENAI_CLIENT


_FALLBACK_DISCOVERY_PROMPT = """
You are a Principal Cloud & AI Security Architect auditing a GCP project against the Google Secure AI Framework (SAIF).
"""

DISCOVERY_TOOL_SYSTEM_PROMPT = load_skill_instructions(
    "saifguard",
    fallback_prompt=_FALLBACK_DISCOVERY_PROMPT,
    references=["saif_gcp_live_audit.md"],
)

DISCOVERY_TOOL_QUERY_PROMPT = """
Inspect the deterministic GCP scan findings, Audit Coverage map, and compressed cloud topology below.
Generate a comprehensive, production-ready SAIF Security Audit Report in Markdown format.
- Address all deterministic violations first (never drop them).
- Highlight any API visibility gaps from the Audit Coverage table.
- In all remediation steps, provide GA `gcloud` commands or Terraform HCL snippets pre-populated with exact resource names and project ID. Never output `gcloud alpha` or `gcloud beta`.
- Include clickable Google Cloud Console URLs for every resource.
"""


@functools.lru_cache(maxsize=1)
def _get_cached_saif_recommendations() -> str:
    """Retrieve SAIF framework recommendations with disk caching."""
    cache_file = os.path.join(tempfile.gettempdir(), "saif_recommendations_cache.txt")
    if os.path.exists(cache_file):
        try:
            if time.time() - os.path.getmtime(cache_file) < 86400:
                with open(cache_file, "r", encoding="utf-8") as f:
                    content = f.read()
                if content and "An exception occurred" not in content:
                    return content
        except Exception as e:
            LOGGER.warning(f"Could not read SAIF cache: {e}")

    try:
        result = google_search_tool(GOOGLE_SEARCH_SAIF_PROMPT)
        if result and "An exception occurred" not in str(result):
            with open(cache_file, "w", encoding="utf-8") as f:
                f.write(result)
            return result
    except Exception as e:
        LOGGER.warning(f"Google search tool skipped: {e}")
    return "Follow Google Secure AI Framework (SAIF) 6 Pillars: Strong Foundations, Detection & Monitoring, Automated Defenses, Harmonized Controls, Continuous Evaluation, Contextual Governance."


def gcp_project_tool(
    gcp_project_id: str,
    local_repo_path: str = None,
    output_path: str = DEFAULT_REPORT_FILENAME,
    tool_context: ToolContext = None,
) -> str:
    """Audit GCP resources in a target project for SAIF framework security compliance.

    Args:
        gcp_project_id: The target GCP Project ID to scan.
        local_repo_path: Optional local workspace path for Cloud-to-Code drift analysis.
        output_path: Optional filename for saving the Markdown report (default: SAIF_AUDIT_REPORT.md).
    """
    s_id = getattr(getattr(tool_context, "session", None), "id", None)
    LOGGER.info(f"Starting Hybrid GCP Project Security Audit for project: {gcp_project_id} (session: {s_id})")
    start_time = time.time()

    emit_progress(
        f"🔍 [1/3] Executing deterministic GCP sensor (`gcp_scan.py`) on project `{gcp_project_id}`...",
        session_id=s_id,
    )

    # Stage 1: Deterministic Sensor & Payload Compression
    scan_result = scan_gcp_project(project_id=gcp_project_id)
    stats = scan_result.get("stats", {})
    findings = scan_result.get("findings", [])

    emit_progress(
        f"📊 [2/3] Scanned {stats.get('raw_resources_count', 0)} assets ({stats.get('compression_reduction_pct', 0)}% compression). Found {len(findings)} deterministic alerts.",
        session_id=s_id,
    )

    # Check for optional local Terraform / Python drift context
    drift_context = ""
    if local_repo_path and Path(local_repo_path).is_dir():
        try:
            from saifguard.skills.saifguard.scripts.fast_scan import SAIFScanner

            local_scanner = SAIFScanner(local_repo_path)
            local_findings = local_scanner.scan()
            drift_context = f"\n\nLOCAL REPOSITORY DRIFT CONTEXT ({len(local_findings)} local findings):\n" + json.dumps(
                [{"rule_id": lf.rule_id, "file": lf.file_path, "message": lf.message} for lf in local_findings[:15]],
                indent=2,
            )
        except Exception as de:
            LOGGER.debug(f"Could not load local drift context: {de}")

    # Stage 2: LLM Contextual Evaluation (with graceful fallback to deterministic report)
    emit_progress("🧠 [3/3] Evaluating SAIF attack paths & generating remediation report...", session_id=s_id)

    deterministic_markdown = format_gcp_markdown_report(scan_result)

    if os.environ.get("SAIFGUARD_DETERMINISTIC_ONLY", "").lower() in ("1", "true"):
        save_markdown_report(deterministic_markdown, output_path=output_path, session_id=s_id)
        return deterministic_markdown

    try:
        saif_recommendations = _get_cached_saif_recommendations()
        contents = [
            types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT),
            types.Part.from_text(text=f"DETERMINISTIC SCAN REPORT & BASELINE:\n{deterministic_markdown}"),
            types.Part.from_text(
                text=f"COMPRESSED GCP TOPOLOGY & COVERAGE:\n{json.dumps({'coverage': scan_result.get('coverage'), 'topology': scan_result.get('compressed_topology')[:40]}, indent=2)}"
            ),
            types.Part.from_text(text=f"LATEST SAIF RECOMMENDATIONS:\n{saif_recommendations}"),
        ]
        if drift_context:
            contents.append(types.Part.from_text(text=drift_context))

        client = _get_genai_client()
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                temperature=0.1,
            ),
        )
        final_report = response.text or deterministic_markdown
        LOGGER.info(f"LLM evaluation completed in {time.time() - start_time:.2f}s.")
    except Exception as e:
        LOGGER.warning(f"Gemini LLM evaluation unavailable ({e}); using high-precision deterministic SAIF report.")
        final_report = deterministic_markdown

    save_markdown_report(final_report, output_path=output_path, session_id=s_id)
    return final_report
