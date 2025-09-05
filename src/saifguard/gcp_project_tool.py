import json
import logging
import traceback
from typing import List
from google.protobuf import field_mask_pb2
from google.protobuf.json_format import MessageToJson

from google import genai
from google.genai import types
from google.cloud import asset_v1

# Assuming saifguard.config exists and contains these variables
from saifguard.config import MODEL, PROJECT_ID, REGION
from saifguard.google_search_tool import google_search_tool

LOGGER = logging.getLogger(__name__)


DISCOVERY_TOOL_SYSTEM_PROMPT = """
You are an expert Application Security (AppSec) engineer. Your task is to perform a thorough security audit on this application's deployment and generate a detailed report of your findings.

**Methodology:**
You must follow this process step-by-step:
1.  **Asset Analysis:** First, identify and analyze the GCP project's resources 
2.  **Static Code Analysis (SAST):** Scan the GCP project's resources provided in the context. Look specifically for patterns indicating common vulnerabilities based on the OWASP Top 10. Pay close attention to:
    -   **DDoS vulnerability:** Lack of Web Application Firewall (WAF) such as Cloud Armor not configured on Extnerla Load Balancers
    -   **Injection Flaws:** SQL, NoSQL, or command injection where user input is concatenated into queries or commands without proper sanitization or parameterization.
    -   **Hardcoded Secrets:** API keys, passwords, private tokens, or other sensitive credentials committed directly into the source code. Use the `grep` results below as a starting point.
    -   **XSS (Cross-Site Scripting):** Locations where unsanitized user input is rendered directly into HTML templates.
    -   **Insecure Deserialization:** Use of unsafe deserialization methods on untrusted data.
    -   **Security Misconfiguration:** Overly permissive CORS headers (`*`), default credentials, or debug features enabled in production-like configurations.
    -   **Sensitive Data Exposure:** Lack of proper encryption for sensitive data at rest or in transit.
3.  **Context Review:** Use the SAIF framework to identify security risks and recommendations 

---

**Reporting Format:**
Generate your final report in Markdown. For each vulnerability you discover, provide the following details. You must order the findings by severity, from Critical to Medium.

### 🔴 Critical
- **Vulnerability:** [e.g., Hardcoded AWS Secret Access Key]
- **Location:** `[File Path]:[Line Number]`
- **Description:** [Explain the vulnerability in detail and describe the potential impact, such as account takeover or data exfiltration.]
- **Remediation:** [Provide a specific, actionable code example or step-by-step instructions to fix the issue, e.g., "Move the secret to an environment variable and access it via `process.env.AWS_SECRET_KEY`.".]

### 🟠 High
- **Vulnerability:**
- **Location:**
- **Description:**
- **Remediation:**

### 🟡 Medium
- **Vulnerability:**
- **Location:**
- **Description:**
- **Remediation:**
"""

DISCOVERY_TOOL_QUERY_PROMPT = "Inspect the GCP project assets provided and generate detailed recommendations to improve the overall security posture. Use the provided Google Search results for the latest SAIF compliance recommendations as a reference."


def gcp_project_tool(gcp_project_id: str):
    """Analyze a GCP project referenced by a GCP project ID.

    Args:
        gcp_project_id (str): GCP project ID
    """
    try:
        LOGGER.info(f"Calling GCP project tool with project: {gcp_project_id}")

        # Get latest SAIF recommendations from Google Search
        LOGGER.info("Fetching latest SAIF recommendations using Google Search.")
        saif_recommendations = google_search_tool("latest Google SAIF recommendations")

        resources = _get_asset_inventory_resources(gcp_project_id)
        LOGGER.info(f"Asset Inventory found {len(resources)} resources.")

        if resources:
            # Convert each protobuf resource object to a dictionary
            resources_as_dicts = [
                json.loads(MessageToJson(res._pb)) for res in resources
            ]
            # Dump the list of dictionaries into a single, formatted JSON string
            asset_dump_text = json.dumps(resources_as_dicts, indent=2)
        else:
            asset_dump_text = "No resources were found in the project."

        contents = [
            types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT),
            types.Part.from_text(text=asset_dump_text),
            types.Part.from_text(text=f"LATEST SAIF RECOMMENDATIONS:\n{saif_recommendations}"),
        ]

        # write content to file for easier troubleshooting
        with open("asset_dump.txt", "w") as f:
            f.write(asset_dump_text)
        with open("saif_recommendations.txt", "w") as f:
            f.write(saif_recommendations)

        client = genai.Client(
            vertexai=True,
            project=PROJECT_ID,
            location=REGION,
        )
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                max_output_tokens=1000,
                temperature=0.3,
            ),
        )
        LOGGER.info("Successfully received response from the model.")
        return response.text
    except Exception as e:
        message = f"An exception occurred while calling GCP project tool: {e}"
        LOGGER.error(message)
        LOGGER.error(f"Traceback: {traceback.format_exc()}")
        return message


def _get_asset_inventory_resources(project_id: str) -> List[asset_v1.types.ResourceSearchResult]:
    """
    Fetches all resources from GCP Asset Inventory for a given project.
    """

    try:
        client = asset_v1.AssetServiceClient()
        parent_scope = f"projects/{project_id}"
        read_mask = field_mask_pb2.FieldMask(paths=["*"])

        asset_inventory_response = client.search_all_resources(
            request={
                "scope": parent_scope,
                "read_mask": read_mask,
            }
        )
        all_resources = list(asset_inventory_response)
        return all_resources

    except Exception as e:
        LOGGER.error(f"An unexpected error occurred while fetching assets: {e}")
        return []