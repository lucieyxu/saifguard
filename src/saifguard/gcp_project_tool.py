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
from saifguard.config import MODEL, PROJECT_ID, REGION, GOOGLE_SEARCH_SAIF_PROMPT
from saifguard.google_search_tool import google_search_tool

LOGGER = logging.getLogger(__name__)


DISCOVERY_TOOL_SYSTEM_PROMPT = """
<OBJECTIVE_AND_PERSONA>
You are an expert Application Security (AppSec) engineer. 
Your task is to perform a thorough security audit on this application's deployment using the provided GCP resources of this project ID
and generate a detailed report of your findings.
</OBJECTIVE_AND_PERSONA>

<INSTRUCTIONS>
To complete the task, think step by step and print out the thinking process:
Go through the GCP project's resources provided in context via "GCP Asset Inventory export". For each resource:
1. Compare it to the SAIF framework to identify security risks and recommendations. 
2. Look specifically for patterns indicating common vulnerabilities based on the OWASP Top 10. Pay close attention to:
    -   **DDoS vulnerability:** Lack of Web Application Firewall (WAF) such as Cloud Armor not configured on External Load Balancers. Each GCP backend service MUST HAVE a security policy defined.
    -   **Injection Flaws:** SQL, NoSQL, or command injection where user input is concatenated into queries or commands without proper sanitization or parameterization.
    -   **Hardcoded Secrets:** API keys, passwords, private tokens, or other sensitive credentials committed directly into the source code. Use the `grep` results below as a starting point.
    -   **XSS (Cross-Site Scripting):** Locations where unsanitized user input is rendered directly into HTML templates.
    -   **Insecure Deserialization:** Use of unsafe deserialization methods on untrusted data.
    -   **Security Misconfiguration:** Overly permissive CORS headers (`*`), default credentials, or debug features enabled in production-like configurations.
    -   **Sensitive Data Exposure:** Lack of proper encryption for sensitive data at rest or in transit.
Output the resources that contain a security issue with regards to the SAIF framework.
</INSTRUCTIONS>

<EXAMPLE>
This is an example of a critical security issue:

### 🔴 Critical
- **Vulnerability:** Hardcoded AWS Secret Access Key
- **Location:** `[File Path]:[Line Number]`
- **Description:** The secret access key is hardcoded in a script
- **Remediation:** Move the secret to an environment variable and access it via `process.env.AWS_SECRET_KEY`."
</EXAMPLE>

<OUTPUT>
Generate your final report in Markdown. For each vulnerability you discover, provide the following details. You must order the findings by severity, from Critical to Medium.

### 🔴 Critical
- **Vulnerability:** 
- **Location:** 
- **Description:** 
- **Remediation:**

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
</OUTPUT>


<RECAP>
* Do not attempt to answer questions without the GCP resources found, always ground them in the GCP Asset Inventory export and Latest SAIF recommendations.
</RECAP>
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
        saif_recommendations = google_search_tool(GOOGLE_SEARCH_SAIF_PROMPT)

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
            types.Part.from_text(text=f"GCP Asset Inventory export:\n{asset_dump_text}"),
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
                temperature=0.1,
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