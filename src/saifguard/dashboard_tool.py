import json
import logging
import threading
import time
from textwrap import dedent
import pandas as pd
from google import genai
from google.genai import types

from models.vulnerability import VulnerabilityList
from saifguard.config import (
    DASHBOARD_BQ_LOCATION,
    DASHBOARD_BQ_PROJECT,
    DATA_STUDIO_TEMPLATE_REPORT_ID,
    MODEL,
    PROJECT_ID,
    VERTEX_LOCATION,
)

LOGGER = logging.getLogger(__name__)

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

### 🔴 Critical

* Lack of Web Application Firewall (WAF) / DDoS Protection on External Load Balancer
    *   **Location:** `//compute.googleapis.com/projects/[PROJECT_ID]/global/backendServices/[BACKEND SERVICE NAME]`
    *   **Description:** The external HTTP(S) Load Balancer's backend service (`[BACKEND SERVICE NAME]`) does not have a Cloud Armor security policy attached
    *   **Remediation:** Attach a Cloud Armor security policy

### 🟡 Medium

* Disabled Backups for Cloud SQL Instance
    *   **Location:** `//cloudsql.googleapis.com/projects/[PROJECT_ID]/instances/[CLOUD SQL INSTANCE NAME]`
    *   **Description:** The Cloud SQL instance `[CLOUD SQL INSTANCE NAME]` has automated backups disabled
    *   **Remediation:** Enable automated backups

## Output
[
    {
        "severity": "Critical",
        "category": "Load Balancer",
        "name": "Lack of Web Application Firewall (WAF) / DDoS Protection on External Load Balancer",
        "description": "The external HTTP(S) Load Balancer's backend service (`[BACKEND SERVICE NAME]`) does not have a Cloud Armor security policy attached",
        "remediation": "Attach a Cloud Armor security policy",
        "url": "https://console.cloud.google.com/net-services/loadbalancing/backends/details/backendService/[BACKEND SERVICE NAME]?project=[PROJECT_ID]"
    },
    {
        "severity": "Medium",
        "category": "Cloud SQL",
        "name": "Disabled Backups for Cloud SQL Instance",
        "description": "The Cloud SQL instance `[CLOUD SQL INSTANCE NAME]` has automated backups disabled",
        "remediation": "Enable automated backups",
        "url": "https://console.cloud.google.com/sql/instances/[CLOUD SQL INSTANCE NAME]/overview?project=[PROJECT_ID]"
    }
]
</FEW_SHOT_EXAMPLES>

<RECAP>
* Keep the vulnerability name, description and remediation as is, do not change the text
* Convert the location into a GCP console URL
</RECAP>
"""


def get_data_studio_dashboard_url(gcp_project_id: str = "") -> str:
    """Return the direct Data Studio report URL running under Owner Credentials."""
    return f"https://lookerstudio.google.com/reporting/{DATA_STUDIO_TEMPLATE_REPORT_ID}"


get_looker_dashboard_url = get_data_studio_dashboard_url


def publish_dashboard_tool(report_text: str, gcp_project_id: str = "") -> str:
    """Publish a security report's findings to BigQuery for Data Studio dashboarding.

    Args:
        report_text (str): The security report text containing vulnerability findings.
        gcp_project_id (str): Optional GCP project ID being reported on.
    """
    try:
        LOGGER.info(
            f"Publishing security report findings to BigQuery ({DASHBOARD_BQ_PROJECT}.{DASHBOARD_BQ_LOCATION})..."
        )
        target_project = gcp_project_id or PROJECT_ID
        query = dedent(
            f"""
        # Vulnerabilities
        {report_text}
        """
        )

        start_time = time.time()
        contents = [
            types.Part.from_text(text=query),
        ]

        client = genai.Client(
            vertexai=True,
            project=PROJECT_ID,
            location=VERTEX_LOCATION,
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
        LOGGER.info(
            f"Generating dashboard data took {time.time() - start_time:.2f} seconds."
        )
        vulnerabilities = json.loads(response.text)
        raw_items = vulnerabilities.get("vulnerabilities", [])
        if raw_items:
            from google.cloud import bigquery
            bq_client = bigquery.Client(project=DASHBOARD_BQ_PROJECT)
            table = pd.DataFrame(raw_items)
            table["project_id"] = target_project
            dataset_table = f"{DASHBOARD_BQ_PROJECT}.{DASHBOARD_BQ_LOCATION}"
            job_config = bigquery.LoadJobConfig(write_disposition="WRITE_TRUNCATE")
            job = bq_client.load_table_from_dataframe(
                table, dataset_table, job_config=job_config
            )
            job.result()
            row_count = len(table)
        else:
            row_count = 0

        dashboard_url = get_data_studio_dashboard_url(target_project)
        msg = (
            f"Successfully published {row_count} vulnerability record(s) to BigQuery dashboard table `{DASHBOARD_BQ_PROJECT}.{DASHBOARD_BQ_LOCATION}` for project `{target_project}`.\n\n"
            f"📊 **Data Studio Security Dashboard**: [Open Auto-Populated Dashboard Template]({dashboard_url})"
        )
        LOGGER.info(msg)
        return msg
    except Exception as e:
        err_msg = f"Error when publishing to dashboard: {e}"
        LOGGER.warning(err_msg)
        return err_msg


def publish_dashboard_async(report_text: str, gcp_project_id: str = ""):
    """Helper function to execute dashboard publication asynchronously in a background thread."""
    thread = threading.Thread(
        target=publish_dashboard_tool,
        args=(report_text, gcp_project_id),
        daemon=True,
    )
    thread.start()
    return thread
