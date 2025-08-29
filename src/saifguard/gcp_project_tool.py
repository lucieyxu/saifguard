import json
import logging
import traceback
from typing import List
from google.protobuf.json_format import MessageToJson

from google import genai
from google.genai import types
from google.cloud import asset_v1

# Assuming saifguard.config exists and contains these variables
from saifguard.config import MODEL, PROJECT_ID, REGION
from saifguard.google_search_tool import google_search_tool

LOGGER = logging.getLogger(__name__)


DISCOVERY_TOOL_SYSTEM_PROMPT = """
You are an AI assistant tasked with helping users. When answering, adhere to the following guildelines:
**Accuracy:** Ensure your answers are factually correct and grounded in the documents provided as a list of uris.
**Detail:** Provide comprehensive and informative answers, elaborating on key concepts and providing context. Be detailed and return an exhaustive answer.
**Language:** Strictly identify the language of ther user query and always repond in the same language regardless of the document language.
Now look at these documents and answer the user query. 
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

        asset_inventory_response = client.search_all_resources(
            request={"scope": parent_scope}
        )
        all_resources = list(asset_inventory_response)
        return all_resources

    except Exception as e:
        LOGGER.error(f"An unexpected error occurred while fetching assets: {e}")
        return []