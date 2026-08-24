import functools
import logging
import traceback

from google import genai
from google.genai import types
from saifguard.config import MODEL, PROJECT_ID, REGION, VERTEX_LOCATION

LOGGER = logging.getLogger(__name__)

_GENAI_CLIENT = None


def _get_genai_client():
    global _GENAI_CLIENT
    if _GENAI_CLIENT is None:
        _GENAI_CLIENT = genai.Client(
            vertexai=True,
            project=PROJECT_ID,
            location=VERTEX_LOCATION,
        )
    return _GENAI_CLIENT


@functools.lru_cache(maxsize=32)
def google_search_tool(query: str):
    """Use Google Search to answer a question. Results are cached in-memory.

    Args:
        query (str): The user's query that will be searched on Google.
    """
    try:
        LOGGER.info(f"Calling Google Search tool with query: {query}")

        client = _get_genai_client()

        # Define the grounding tool
        grounding_tool = types.Tool(google_search=types.GoogleSearch())

        # Configure generation settings
        config = types.GenerateContentConfig(
            tools=[grounding_tool],
            temperature=0.1,
        )

        # Make the request
        response = client.models.generate_content(
            model=MODEL,
            contents=query,
            config=config,
        )

        LOGGER.debug("Successfully received response from the model with Google Search grounding.")
        return response.text
    except Exception as e:
        message = f"An exception occurred while calling Google Search tool: {e}"
        LOGGER.error(message)
        LOGGER.error(f"Traceback: {traceback.format_exc()}")
        return message
