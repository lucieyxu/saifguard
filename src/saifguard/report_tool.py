import logging
import os
from pathlib import Path
from typing import Any, Optional

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any  # Fallback for CLI environments without google-adk installed

from saifguard.config import DEFAULT_REPORT_FILENAME
from saifguard.progress import emit_progress

LOGGER = logging.getLogger(__name__)

# In-memory session-scoped store for stateless Cloud Run / multi-user safety
_SESSION_REPORTS: dict[str, str] = {}


def is_server_mode() -> bool:
    """Detect if running inside Cloud Run or multi-user server runtime."""
    return (
        os.environ.get("SAIFGUARD_RUNTIME", "").lower() == "server"
        or bool(os.environ.get("K_SERVICE"))
    )


def store_session_report(session_id: str, report_markdown: str) -> None:
    """Store Markdown report in session-scoped memory (isolated per user)."""
    key = session_id or "default"
    _SESSION_REPORTS[key] = report_markdown


def get_session_report(session_id: str) -> Optional[str]:
    """Retrieve stored Markdown report for a given session_id."""
    key = session_id or "default"
    return _SESSION_REPORTS.get(key) or _SESSION_REPORTS.get("default")


def save_markdown_report(
    report_markdown: str,
    output_path: str = DEFAULT_REPORT_FILENAME,
    session_id: Optional[str] = None,
) -> str:
    """Save or store the SAIF Markdown Audit Report using Dual-Mode Delivery."""
    store_session_report(session_id or "default", report_markdown)

    if is_server_mode():
        LOGGER.info(f"Server Mode active: stored report in session state for session '{session_id}'.")
        return (
            "Report generated and stored in session state (Server Mode). "
            "Use the 'Download SAIF_AUDIT_REPORT.md' button in the UI or `/report/{session_id}` API endpoint."
        )

    target = Path(output_path).resolve()
    target.write_text(report_markdown, encoding="utf-8")
    LOGGER.info(f"Local Mode: wrote SAIF Audit Report to {target}")
    return f"Saved SAIF Audit Report to [{target.name}](file://{target})"


def save_markdown_report_tool(
    report_markdown: str,
    output_path: str = DEFAULT_REPORT_FILENAME,
    tool_context: ToolContext = None,
) -> str:
    """ADK Tool to save or publish the final Markdown security audit report.

    Args:
        report_markdown: The complete Markdown text of the security audit report.
        output_path: Optional filename (default: SAIF_AUDIT_REPORT.md).
    """
    s_id = getattr(getattr(tool_context, "session", None), "id", None)
    emit_progress("📝 Formatting and saving SAIF Markdown Audit Report...", session_id=s_id)
    return save_markdown_report(
        report_markdown=report_markdown,
        output_path=output_path,
        session_id=s_id,
    )
