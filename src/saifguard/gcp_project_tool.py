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
)
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


DASHBOARD_SYSTEM_PROMPT = """
<OBJECTIVE>
A list of vulnerability descriptions from a GCP project is given to you as text. 
You need to transform it into a dataframe to pass to BigQuery for dashboarding.
You need to extract the google cloud console URL for each vulnerable resources to allow the user to click on it.
</OBJECTIVE>

<INSTRUCTIONS>
Think step by step:
1. Identify the vulnerable GCP resources.
2. For each resource, extract the location given as a the name from asset inventory command and produce the GCP console URL. Extract the vulnerability name, description and remediation.
</INSTRUCTIONS>

<FEW_SHOT_EXAMPLES>
# Example 1
## Input
**Vulnerabilities:** 
\n\n### 🔴 Critical\n\n* Lack of Web Application Firewall (WAF) / DDoS Protection on External Load Balancer\n    *   **Location:** `//compute.googleapis.com/projects/[PROJECT_ID]/global/backendServices/[BACKEND SERVICE NAME]`\n    *   **Description:** The external HTTP(S) Load Balancer\'s backend service (`[BACKEND SERVICE NAME]`) does not have a Cloud Armor security policy attached    *   **Remediation:** Attach a Cloud Armor security policy
\n\n### 🔴 Medium\n\n* Disabled Backups for Cloud SQL Instance\n    *   **Location:** `//cloudsql.googleapis.com/projects/[PROJECT_ID]/instances/[CLOUD SQL INSTANCE NAME]`\n    *   **Description:** The Cloud SQL instance `[CLOUD SQL INSTANCE NAME]` has automated backups disabled *   **Remediation:** Enable automated backups

##Thoughts
1. There are 2 vulnerabilities listed, the first on the external load balancer backend service, the second on Cloud SQL instance
2. //compute.googleapis.com/projects/[PROJECT_ID]/global/backendServices/[BACKEND SERVICE NAME] is mapped to the console URL https://console.cloud.google.com/net-services/loadbalancing/backends/details/backendService/[BACKEND SERVICE NAME]?project=[PROJECT_ID]
//cloudsql.googleapis.com/projects/[PROJECT_ID]/instances/[CLOUD SQL INSTANCE NAME] is mapped to the console URL https://console.cloud.google.com/sql/instances/[CLOUD SQL INSTANCE NAME]/overview?project=[PROJECT_ID]

## Output
[
    {
        severity: "Critical"
        category: "Load Balancer"
        name: "Lack of Web Application Firewall (WAF) / DDoS Protection on External Load Balancer"
        description: "The external HTTP(S) Load Balancer\'s backend service (`[BACKEND SERVICE NAME]`) does not have a Cloud Armor security policy attached"
        remediation: "Attach a Cloud Armor security policy"
        url: "https://console.cloud.google.com/net-services/loadbalancing/backends/details/backendService/[BACKEND SERVICE NAME]?project=[PROJECT_ID]"
    },
    {
        severity: "Medium"
        category: "Cloud SQL"
        name: "Disabled Backups for Cloud SQL Instance"
        description: "The Cloud SQL instance `[CLOUD SQL INSTANCE NAME]` has automated backups disabled"
        remediation: "Enable automated backups"
        url: "https://console.cloud.google.com/sql/instances/[CLOUD SQL INSTANCE NAME]/overview?project=[PROJECT_ID]"
    }
]
</FEW_SHOT_EXAMPLES>


<RECAP>
* Keep the vulnerability name, description and remeidation as is, do not change the text
* Convert the location into a GCP console URL
</RECAP>
"""


def gcp_project_tool(gcp_project_id: str):
    """Analyze a GCP project referenced by a GCP project ID.

    Args:
        gcp_project_id (str): GCP project ID
    """
    try:
        LOGGER.info(f"Calling GCP project tool with project: {gcp_project_id}")

        LOGGER.info("Fetching latest SAIF recommendations using Google Search.")
        start_time = time.time()
        saif_recommendations = google_search_tool(GOOGLE_SEARCH_SAIF_PROMPT)
        LOGGER.info(f"Fetching SAIF recommendations took {time.time() - start_time:.2f} seconds.")

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
        LOGGER.info(f"Generating security report took {time.time() - start_time:.2f} seconds.")
        LOGGER.info("Successfully received response from the model.")
        if GENERATE_DASHBOARD:
            try:
                query = dedent(
                    f"""
                # Vulnerabilities
                {response.text}
                """
                )

                start_time = time.time()
                contents = [
                    types.Part.from_text(text=query),
                ]

                client = genai.Client(
                    vertexai=True,
                    project=PROJECT_ID,
                    location=REGION,
                )
                response = client.models.generate_content(
                    model=MODEL,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=DASHBOARD_SYSTEM_PROMPT,
                        temperature=0.1,
                        response_mime_type="application/json",
                        response_schema=VulnerabilityList,
                    ),
                )
                LOGGER.info(f"Generating dashboard data took {time.time() - start_time:.2f} seconds.")
                vulnerabilities = json.loads(response.text)
                table = pd.DataFrame(vulnerabilities["vulnerabilities"])
                table["project_id"] = PROJECT_ID
                table.to_gbq(
                    f"{DASHBOARD_BQ_PROJECT}.{DASHBOARD_BQ_LOCATION}",
                    project_id=DASHBOARD_BQ_PROJECT,
                    if_exists="replace",
                )
                LOGGER.info(
                    f"Successfully published to dashboard content to BigQuery: {DASHBOARD_BQ_PROJECT}.{DASHBOARD_BQ_LOCATION}"
                )
            except Exception as e:
                LOGGER.warning(f"Error when publishing to dashboard: {e}")

        return response.text
    except Exception as e:
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
        client = asset_v1.AssetServiceClient()
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
        LOGGER.error(f"An unexpected error occurred while fetching assets: {e}")
        return []
