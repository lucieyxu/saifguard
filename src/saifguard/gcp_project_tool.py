"""Bridge module linking saifguard.gcp_project_tool to saifguard.skills.gcp_security_audit.gcp_project_tool."""

from saifguard.skills.gcp_security_audit.gcp_project_tool import (
    gcp_project_tool,
    DISCOVERY_TOOL_SYSTEM_PROMPT,
    DISCOVERY_TOOL_QUERY_PROMPT,
)

__all__ = [
    "gcp_project_tool",
    "DISCOVERY_TOOL_SYSTEM_PROMPT",
    "DISCOVERY_TOOL_QUERY_PROMPT",
]
