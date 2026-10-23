import json
import logging
import os
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

try:
    from google.cloud import storage
except ImportError:
    storage = None

from saifguard.config import (
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
from saifguard.skills.saifguard.scripts.fast_scan import (
    Finding,
    format_markdown_summary,
    select_context_files,
)

LOGGER = logging.getLogger(__name__)

_FALLBACK_DISCOVERY_PROMPT = """
You are a Principal Security Architect specializing in AI/ML Systems.
Your task is to perform a thorough security audit on the provided code, infrastructure, or design documents against Google SAIF.
"""

DISCOVERY_TOOL_SYSTEM_PROMPT = load_skill_instructions(
    "saifguard",
    fallback_prompt=_FALLBACK_DISCOVERY_PROMPT,
    references=["saif_design_doc_audit.md"],
)

DISCOVERY_TOOL_QUERY_PROMPT = """
Inspect the files and deterministic SAIF pre-scan findings provided below.
Generate a detailed, actionable SAIF Security Audit Report in Markdown format:
- Address every deterministic finding first with unified git diff blocks or GA remediation steps.
- Inspect the provided code and architecture specifications against all 6 SAIF Pillars and OWASP Top 10 for LLMs.
- Order all findings strictly by severity (🔴 Critical -> 🟠 High -> 🟡 Medium -> 🟢 Low).
"""


def _get_genai_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        return genai.Client(api_key=api_key)
    return genai.Client(
        vertexai=True,
        project=PROJECT_ID,
        location=VERTEX_LOCATION,
    )


from saifguard.skills.saifguard.scripts.fetch_doc import fetch_google_doc_bytes


def analysis_tool(
    target_uri_or_path: str,
    output_path: str = DEFAULT_REPORT_FILENAME,
    max_context_kb: int = 120,
    tool_context: ToolContext = None,
) -> str:
    """Audit local application/Terraform files, local PDFs, Google Docs URLs, OR documents inside a GCS bucket (`gs://`).

    Args:
        target_uri_or_path: Local repository directory/file path (including .pdf), Google Docs URL (`https://docs.google.com/document/d/...`), OR GCS bucket URI (`gs://my-bucket/`).
        output_path: Optional filename to write the Markdown report (default: SAIF_AUDIT_REPORT.md).
        max_context_kb: Context budget ceiling in KB for local repository scanning (default: 120).
    """
    try:
        s_id = getattr(getattr(tool_context, "session", None), "id", None)
        LOGGER.info(f"Calling analysis_tool with '{target_uri_or_path}' (session: {s_id})")

        # Mode 0: Google Docs URL (`https://docs.google.com/document/d/...`)
        if target_uri_or_path.startswith(("http://", "https://")) and "docs.google.com/document" in target_uri_or_path:
            emit_progress(f"📄 [1/2] Exporting Google Doc `{target_uri_or_path}` for SAIF architecture review...", session_id=s_id)
            doc_bytes, mime_type, err = fetch_google_doc_bytes(target_uri_or_path)
            if not doc_bytes:
                return f"Error fetching Google Doc: {err}"
            emit_progress("🧠 [2/2] Auditing Google Doc against Google SAIF 6 Pillars...", session_id=s_id)
            client = _get_genai_client()
            part = (
                types.Part.from_bytes(data=doc_bytes, mime_type=mime_type)
                if mime_type == "application/pdf"
                else types.Part.from_text(text=doc_bytes.decode("utf-8", errors="replace"))
            )
            response = client.models.generate_content(
                model=MODEL,
                contents=[types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT), part],
                config=types.GenerateContentConfig(
                    system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                    temperature=0.1,
                ),
            )
            final_report = response.text or "No findings returned."
            save_markdown_report(final_report, output_path=output_path, session_id=s_id)
            return final_report

        # Mode A: Local File (including .pdf) or Directory Path
        if not target_uri_or_path.startswith("gs://"):
            local_target = Path(target_uri_or_path).resolve()
            if not local_target.exists():
                return f"Error: Local path '{target_uri_or_path}' does not exist."

            # Native Local PDF Design Document Support
            if local_target.is_file() and local_target.suffix.lower() == ".pdf":
                emit_progress(f"📄 [1/2] Reading local PDF design document `{local_target.name}`...", session_id=s_id)
                pdf_bytes = local_target.read_bytes()
                emit_progress(f"🧠 [2/2] Auditing `{local_target.name}` (text & diagrams) against Google SAIF...", session_id=s_id)
                client = _get_genai_client()
                response = client.models.generate_content(
                    model=MODEL,
                    contents=[
                        types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT),
                        types.Part.from_bytes(data=pdf_bytes, mime_type="application/pdf"),
                    ],
                    config=types.GenerateContentConfig(
                        system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                        temperature=0.1,
                    ),
                )
                final_report = response.text or "No findings returned."
                save_markdown_report(final_report, output_path=output_path, session_id=s_id)
                return final_report

            emit_progress(
                f"🔍 [1/2] Running deterministic SAIF pre-scan & smart context router on `{local_target.name}`...",
                session_id=s_id,
            )
            ctx = select_context_files(local_target, max_context_kb=max_context_kb)
            findings_dicts = ctx.get("findings", [])
            findings_objs = [Finding(**f) for f in findings_dicts]
            det_summary = format_markdown_summary(findings_objs)

            if os.environ.get("SAIFGUARD_DETERMINISTIC_ONLY", "").lower() in ("1", "true"):
                save_markdown_report(det_summary, output_path=output_path, session_id=s_id)
                return det_summary

            emit_progress(
                f"🧠 [2/2] Auditing {len(ctx.get('tier1_files', []))} prioritized files ({ctx.get('total_kb', 0)} KB) with Gemini...",
                session_id=s_id,
            )

            contents = [
                types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT),
                types.Part.from_text(text=f"DETERMINISTIC PRE-SCAN SUMMARY:\n{det_summary}"),
            ]
            for f_entry in ctx.get("tier1_files", []):
                contents.append(
                    types.Part.from_text(
                        text=f"\n--- FILE: {f_entry['path']} (Reason: {f_entry['reason']}) ---\n{f_entry['content']}"
                    )
                )
            if ctx.get("tier2_summaries"):
                contents.append(
                    types.Part.from_text(
                        text="\n--- TIER 2 MODULE SIGNATURES ---\n"
                        + json.dumps(ctx["tier2_summaries"], indent=2)
                    )
                )

            try:
                client = _get_genai_client()
                response = client.models.generate_content(
                    model=MODEL,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                        temperature=0.1,
                    ),
                )
                final_report = response.text or det_summary
            except Exception as llm_err:
                LOGGER.warning(f"Gemini LLM evaluation unavailable ({llm_err}); returning deterministic SAIF report.")
                final_report = det_summary

            save_markdown_report(final_report, output_path=output_path, session_id=s_id)
            return final_report

        # Mode B: GCS Bucket URI (`gs://...`)
        emit_progress(
            f"📂 [1/2] Fetching SAIF recommendations & reading design documents from `{target_uri_or_path}`...",
            session_id=s_id,
        )
        try:
            saif_recommendations = google_search_tool(GOOGLE_SEARCH_SAIF_PROMPT)
        except Exception:
            saif_recommendations = "Apply Google Secure AI Framework (SAIF) 6 Pillars."

        storage_client = storage.Client()
        bucket_name = target_uri_or_path.replace("gs://", "").strip("/")
        bucket = storage_client.bucket(bucket_name)
        blobs = list(bucket.list_blobs())

        contents = [types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT)]
        file_count = 0
        for blob in blobs:
            file_uri = f"gs://{bucket_name}/{blob.name}"
            contents.append(types.Part.from_text(text=f"\nDocument name: {blob.name}"))
            contents.append(types.Part.from_uri(file_uri=file_uri, mime_type=None))
            file_count += 1

        contents.append(types.Part.from_text(text=f"LATEST SAIF RECOMMENDATIONS:\n{saif_recommendations}"))
        emit_progress(f"🧠 [2/2] Auditing {file_count} design document(s) against SAIF framework with Gemini...", session_id=s_id)

        client = _get_genai_client()
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                temperature=0.1,
            ),
        )
        final_report = response.text or "No findings returned."
        save_markdown_report(final_report, output_path=output_path, session_id=s_id)
        return final_report

    except Exception as e:
        message = f"An exception occurred while calling analysis_tool: {e}"
        LOGGER.error(message)
        LOGGER.error(f"Traceback: {traceback.format_exc()}")
        return message
