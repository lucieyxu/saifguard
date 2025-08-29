import logging
import traceback

from google import genai
from google.genai import types
from saifguard.config import MODEL, PROJECT_ID, REGION

LOGGER = logging.getLogger(__name__)


# Configure the client
def google_search_tool(query: str):
    """Use Google Search to answer a question.

    Args:
        query (str): The user's query that will be searched on Google.
    """
    try:
        LOGGER.info(f"Calling Google Search tool with query: {query}")

        # Configure the client to use Vertex AI
        client = genai.Client(
            vertexai=True,
            project=PROJECT_ID,
            location=REGION,
        )

        # Define the grounding tool
        grounding_tool = types.Tool(google_search=types.GoogleSearch())

        # Configure generation settings
        config = types.GenerateContentConfig(tools=[grounding_tool])

        # Make the request
        response = client.models.generate_content(
            model=MODEL,
            contents=query,
            config=config,
        )

        LOGGER.info("Successfully received response from the model with Google Search grounding.")
        return response.text
    except Exception as e:
        message = f"An exception occurred while calling Google Search tool: {e}"
        LOGGER.error(message)
        LOGGER.error(f"Traceback: {traceback.format_exc()}")
        return message
