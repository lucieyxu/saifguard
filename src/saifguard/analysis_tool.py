import logging
import traceback

from google.cloud import storage
from google import genai
from google.genai import types
from saifguard.config import MODEL, PROJECT_ID, VERTEX_LOCATION, GOOGLE_SEARCH_SAIF_PROMPT
from saifguard.google_search_tool import google_search_tool
from saifguard.skill_loader import load_skill_instructions

LOGGER = logging.getLogger(__name__)


_FALLBACK_DISCOVERY_PROMPT = """
<OBJECTIVE_AND_PERSONA>
You are a Principal Security Architect specializing in AI/ML Systems.
Your task is to perform a thorough security audit on the provided design documents and generate a detailed report of your findings.
</OBJECTIVE_AND_PERSONA>
"""

DISCOVERY_TOOL_SYSTEM_PROMPT = load_skill_instructions(
    "design_file_audit", _FALLBACK_DISCOVERY_PROMPT
)

DISCOVERY_TOOL_QUERY_PROMPT = """
Inspect the files provided as a GCS bucket URI and generate detailed recommendations to improve the overall security posture.

The GCS bucket URI contains a Technical Design Document (TDD) and a security requirements document.
Use the security requirements document as input to highlight additional security gaps inside the TDD document on top of SAIF recommendations.
Use the provided Google Search results for the latest SAIF compliance recommendations as a reference.
Make sure you show both recommendations related to SAIF compliance recommendations and security requirements. 
"""


def analysis_tool(gcs_uri: str):
    """Analyze the documents within a GCS bucket.

    Args:
        gcs_uri (str): GCS bucket URI (e.g., gs://my-bucket/folder/).
    """
    try:
        LOGGER.info(f"Calling analysis_tool with {gcs_uri}")

        # Get latest SAIF recommendations from Google Search
        LOGGER.info("Fetching latest SAIF recommendations using Google Search.")
        saif_recommendations = google_search_tool(GOOGLE_SEARCH_SAIF_PROMPT)

        contents = []

        # List files in the GCS bucket and add them to the contents
        storage_client = storage.Client()
        bucket_name = gcs_uri.replace("gs://", "").strip("/")
        bucket = storage_client.bucket(bucket_name)        
        LOGGER.info(f"Listing files in bucket '{bucket_name}'.")
        blobs = bucket.list_blobs()

        # Construct the prompt with documents and their names
        contents.append(types.Part.from_text(text=DISCOVERY_TOOL_QUERY_PROMPT))

        for blob in blobs:
            file_uri = f"gs://{bucket_name}/{blob.name}"
            file_name = blob.name
            LOGGER.info(f"Adding file '{file_name}' from {file_uri} to analysis contents.")
            
            # Provide the file name as context for the LLM
            contents.append(types.Part.from_text(text=f"\nDocument name: {file_name}"))
            contents.append(types.Part.from_uri(file_uri=file_uri, mime_type=None))

        contents.append(types.Part.from_text(text=f"LATEST SAIF RECOMMENDATIONS:\n{saif_recommendations}"))

        client = genai.Client(
            vertexai=True,
            project=PROJECT_ID,
            location=VERTEX_LOCATION,
        )
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=DISCOVERY_TOOL_SYSTEM_PROMPT,
                temperature=0.1,
            ),
        )
        LOGGER.info(response)
        return response.text
    except Exception as e:
        message = f"An exception occurred while calling analysis_tool: {e}"
        LOGGER.error(message)
        LOGGER.error(f"Traceback: {traceback.format_exc()}")
        return message
