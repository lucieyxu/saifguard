import logging

from google.adk.agents import Agent
from google.cloud import aiplatform
from google.genai import types
from saifguard.analysis_tool import analysis_tool
from saifguard.gcp_project_tool import gcp_project_tool
from saifguard.config import MODEL, PROJECT_ID, REGION
from vertexai.preview.reasoning_engines import AdkApp

LOGGER = logging.getLogger(__name__)

AGENT_INSTRUCTION_PROMPT = """
<OBJECTIVE_AND_PERSONA>
You are an AI assistant tasked with helping developpers make sure their applications on GCP
follow the SAIF Security framework.
</OBJECTIVE_AND_PERSONA>

<INSTRUCTIONS>
To complete the task, think step by step and print out the thinking process. Use the tools you have available:
* Use the 'analysis_tool' when the user provides a GCS path to analyse
* Use the 'gcp_project_tool' when the user asks to scan a GCP project to check the resources created
</INSTRUCTIONS>
"""


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
            description="SAIFGuard helps you secure your apps on GCP.",
            instruction=AGENT_INSTRUCTION_PROMPT,
            generate_content_config=generate_content_config,
            tools=[analysis_tool, gcp_project_tool],  # Add other tools here
        )
        self.app = AdkApp(agent=agent)

    def invoke(self, user_id: str, message: str):
        LOGGER.info(f"Invoking the agent for user {user_id}, with message: {message}")
        for event in self.app.stream_query(
            user_id=user_id,
            message=message,
        ):
            LOGGER.info("**** START EVENT *****")
            LOGGER.info(event)
            LOGGER.info("**** END EVENT *****")
            if (
                "content" in event
                and "parts" in event["content"]
                and "text" in event["content"]["parts"][0]
            ):
                yield "\n".join([part["text"] for part in event["content"]["parts"]])
            
            if (
                "content" in event
                and "parts" in event["content"]
                and "function_response" in event["content"]["parts"][0]
            ):
                # Yield tool message to pass in conversation history
                yield f'*tool*: {"\n".join([part["function_response"]["response"]["result"] for part in event["content"]["parts"]])}'
