import logging

from google.adk.agents import Agent
from google.cloud import aiplatform
from google.genai import types
from saifguard.analysis_tool import analysis_tool
from saifguard.config import MODEL, PROJECT_ID, REGION
from vertexai.preview.reasoning_engines import AdkApp

LOGGER = logging.getLogger(__name__)


class SAIFGuardAgent:
    """Main class for SAIFGuard Agent definition"""

    def __init__(self):
        aiplatform.init(project=PROJECT_ID, location=REGION)

        safety_settings = [
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                threshold=types.HarmBlockThreshold.OFF,
            ),
        ]
        generate_content_config = types.GenerateContentConfig(
            safety_settings=safety_settings,
            temperature=0.1,
            max_output_tokens=1000,
            top_p=0.95,
        )
        agent = Agent(
            model=MODEL,
            name="SAIFGuard",
            description="SAIFGuard is an agent that helps analyze security documents.",
            generate_content_config=generate_content_config,
            tools=[analysis_tool],  # Add other tools here
        )
        self.app = AdkApp(agent=agent)

    async def invoke(self, user_id: str, message: str):
        LOGGER.info(f"Invoking the agent for {user_id}, {message}")
        async for event in self.app.async_stream_query(
            user_id=user_id,
            message=message,
        ):
            LOGGER.info(event)
            if (
                "content" in event
                and "parts" in event["content"]
                and "text" in event["content"]["parts"][0]
            ):
                yield "/n".join([part["text"] for part in event["content"]["parts"]])
