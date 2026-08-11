import os

PROJECT_ID = os.environ.get("PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT", "saifguard")
REGION = os.environ.get("REGION") or os.environ.get("GOOGLE_CLOUD_LOCATION", "europe-west1")
VERTEX_LOCATION = os.environ.get("VERTEX_LOCATION") or os.environ.get("LOCATION", "global")
MODEL = os.environ.get("MODEL", "gemini-3.6-flash")
GENERATE_DASHBOARD = os.environ.get("GENERATE_DASHBOARD", "True").lower() == "true"
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() in ("true", "1")
DASHBOARD_BQ_PROJECT = os.environ.get("DASHBOARD_BQ_PROJECT") or PROJECT_ID
DASHBOARD_BQ_LOCATION = os.environ.get("DASHBOARD_BQ_LOCATION", "dashboard.vulnerabilities")
DATA_STUDIO_TEMPLATE_REPORT_ID = os.environ.get("DATA_STUDIO_TEMPLATE_REPORT_ID") or os.environ.get("LOOKER_TEMPLATE_REPORT_ID", "08795748-d7d4-44a0-b6f7-272475314ba8")
TIMEZONE = os.environ.get("TZ") or os.environ.get("TIMEZONE", "Europe/Paris")
# Agent Runtime instance ID for Agent Platform sessions
AGENT_RUNTIME_ID = os.environ.get("AGENT_RUNTIME_ID")
APP_NAME = os.environ.get("APP_NAME", "saifguard_app")
GOOGLE_SEARCH_SAIF_PROMPT = """
<Task>
Retrieve the latest, comprehensive documentation for Google's Secure AI Framework (SAIF).
</Task>

<Sources>
Execute searches focused exclusively on the official `saif.google` domain.
Use search queries targeting these specific pages:
1. `site:saif.google/secure-ai-framework/risks`
2. `site:saif.google/secure-ai-framework/controls`
3. `site:saif.google/ai-development-primer`
4. `site:saif.google/secure-ai-framework/components`
5. `site:saif.google/secure-ai-framework/saif-map`
</Sources>

<Instructions>
From the search results of the pages above, find and extract all detailed information for the following topics:
- All core **components** of the SAIF.
- A comprehensive list of identified **risks** related to AI development.
- All specified **controls** and recommended best practices to mitigate those risks.
</Instructions>

<Output>
Return the full, detailed text for components, risks, and controls. The output must be thorough, as it will be used for downstream processing.
</Output>
"""