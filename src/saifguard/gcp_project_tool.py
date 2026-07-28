import json
import logging
import traceback
import time
from textwrap import dedent
from typing import List

import pandas as pd
from opentelemetry import trace
from google import genai
from google.cloud import asset_v1
from google.genai import types
from google.protobuf import field_mask_pb2
from google.protobuf.json_format import MessageToJson
from models.vulnerability import VulnerabilityList

# Assuming saifguard.config exists and contains these variables
from saifguard.config import (
    DASHBOARD_BQ_LOCATION,
    DASHBOARD_BQ_PROJECT,
    GENERATE_DASHBOARD,
    GOOGLE_SEARCH_SAIF_PROMPT,
    MODEL,
    PROJECT_ID,
    REGION,
    VERTEX_LOCATION,
)
from concurrent.futures import ThreadPoolExecutor
from saifguard.google_search_tool import google_search_tool
from saifguard.dashboard_tool import publish_dashboard_async

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


class MissingPermissionsError(Exception):
    def __init__(self, project_id: str, original_error: str):
        self.project_id = project_id
        self.original_error = original_error
        super().__init__(f"Missing permissions for project {project_id}: {original_error}")


def gcp_project_tool(gcp_project_id: str):
    """Analyze a GCP project referenced by a GCP project ID.

    Args:
        gcp_project_id (str): GCP project ID
    """
    try:
        LOGGER.info(f"Calling GCP project tool with project: {gcp_project_id}")

        start_time = time.time()
        # Run Google Search SAIF fetch & Asset Inventory export concurrently
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_saif = executor.submit(google_search_tool, GOOGLE_SEARCH_SAIF_PROMPT)
            future_assets = executor.submit(_get_asset_inventory_resources, gcp_project_id)
            saif_recommendations = future_saif.result()
            resources = future_assets.result()

        LOGGER.info(f"Parallel data fetching (SAIF & Asset Inventory) took {time.time() - start_time:.2f} seconds.")
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
            types.Part.from_text(
                text=f"GCP Asset Inventory export:\n{asset_dump_text}"
            ),
            types.Part.from_text(
                text=f"LATEST SAIF RECOMMENDATIONS:\n{saif_recommendations}"
            ),
        ]

        # write content to file for easier troubleshooting
        with open("asset_dump.txt", "w") as f:
            f.write(asset_dump_text)
        with open("saif_recommendations.txt", "w") as f:
            f.write(saif_recommendations)

        start_time = time.time()
        client = _get_genai_client()
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                temperature=0.1,
            ),
        )
        LOGGER.info(f"Generating security report took {time.time() - start_time:.2f} seconds.")
        LOGGER.info("Successfully received response from the model.")
        if GENERATE_DASHBOARD:
            LOGGER.info("Triggering async BigQuery dashboard publication.")
            publish_dashboard_async(response.text, gcp_project_id)

        return response.text
    except MissingPermissionsError as e:
        sa_email = f"saifguard-sa@{PROJECT_ID}.iam.gserviceaccount.com"
        error_msg = f"""
⚠️ **Missing Permissions to Access GCP Project `{gcp_project_id}`**

SAIFGuard does not have the required permissions to query Cloud Asset Inventory in project `{gcp_project_id}`, or the `cloudasset.googleapis.com` API is disabled.

### 📋 Instructions to Grant IAM Permissions

To allow SAIFGuard's Service Account (`{sa_email}`) to inspect project `{gcp_project_id}`, execute the following commands in Google Cloud Shell or terminal:

1. **Enable the Cloud Asset API** in project `{gcp_project_id}`:
   ```bash
   gcloud services enable cloudasset.googleapis.com --project={gcp_project_id}
   ```

2. **Grant Cloud Asset Viewer Role** to SAIFGuard's Service Account:
   ```bash
   gcloud projects add-iam-policy-binding {gcp_project_id} \\
     --member="serviceAccount:{sa_email}" \\
     --role="roles/cloudasset.viewer"
   ```

*Error Details:* `{e.original_error}`
"""
        LOGGER.warning(f"Returning missing permissions message for project {gcp_project_id}")
        return error_msg.strip()
    except Exception as e:
        err_str = str(e)
        if any(keyword in err_str.lower() for keyword in ["403", "permission", "forbidden", "denied"]):
            sa_email = f"saifguard-sa@{PROJECT_ID}.iam.gserviceaccount.com"
            return f"""
⚠️ **Missing Permissions to Access GCP Project `{gcp_project_id}`**

SAIFGuard encountered a permission error while analyzing project `{gcp_project_id}`.

### 📋 Instructions to Grant IAM Permissions

Grant the **Cloud Asset Viewer** role to SAIFGuard's Service Account (`{sa_email}`):

```bash
gcloud projects add-iam-policy-binding {gcp_project_id} \\
  --member="serviceAccount:{sa_email}" \\
  --role="roles/cloudasset.viewer"
```

*Error Details:* `{err_str}`
""".strip()
        message = f"An exception occurred while calling GCP project tool: {e}"
        LOGGER.error(message)
        LOGGER.error(f"Traceback: {traceback.format_exc()}")
        return message


def _get_asset_inventory_resources(
    project_id: str,
) -> List[asset_v1.types.ResourceSearchResult]:
    """
    Fetches all resources from GCP Asset Inventory for a given project.
    """
    start_time = time.time()
    try:
        client = _get_asset_client()
        parent_scope = f"projects/{project_id}"
        read_mask = field_mask_pb2.FieldMask(paths=["*"])

        asset_inventory_response = client.search_all_resources(
            request={
                "asset_types": [
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
                ],
                "scope": parent_scope,
                "read_mask": read_mask,
            }
        )
        all_resources = list(asset_inventory_response)
        LOGGER.info(f"Fetching Asset Inventory resources took {time.time() - start_time:.2f} seconds.")
        return all_resources
    except Exception as e:
        err_str = str(e)
        if any(keyword in err_str.lower() for keyword in ["403", "permission", "forbidden", "denied", "not enabled", "has not been used", "not found"]):
            LOGGER.error(f"Permission or API error accessing Cloud Asset Inventory for project {project_id}: {e}")
            raise MissingPermissionsError(project_id=project_id, original_error=err_str)
        LOGGER.error(f"An unexpected error occurred while fetching assets: {e}")
        return []
