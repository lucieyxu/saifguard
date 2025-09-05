import os
import asyncio
import logging
import time

from google.adk.agents import Agent
from google.adk.events import Event, EventActions
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.memory import InMemoryMemoryService
from google.cloud import aiplatform
from google.genai import types
from google.genai.types import Content, Part
from saifguard.analysis_tool import analysis_tool
from saifguard.gcp_project_tool import gcp_project_tool
from google.adk.tools import load_memory



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
        aiplatform.init(project=os.getenv("GOOGLE_CLOUD_PROJECT"), location=os.getenv("GOOGLE_CLOUD_LOCATION"))
        self.name = "SAIFGuard"
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

        self.agent = Agent(
            model=os.getenv("MODEL"),
            name="SAIFGuard",
            description="SAIFGuard helps you secure your apps on GCP.",
            generate_content_config=generate_content_config,
            instruction=AGENT_INSTRUCTION_PROMPT,
            tools=[analysis_tool, gcp_project_tool],  # Add other tools here
            # output_key="last_message"

        )
    

    async def create_session(self, user_id: str, session_id: str):
        self.user_id = user_id
        self.session_id = session_id
        self.session_service = InMemorySessionService()
        # self.memory_service = InMemoryMemoryService() 
        self.runner = Runner(
            agent=self.agent, app_name=self.name, session_service=self.session_service,
            # memory_service=self.memory_service 
        )
        self.session = await self.session_service.create_session(
            app_name=self.name, user_id=self.user_id, session_id=self.session_id,
            state={"task_status": "idle"}
        )
        print(f"Initial session created. State: {self.session.state}")
        print(f"Events: {self.session.events}")

    async def call_session(self):
        updated_session = await self.session_service.get_session(
            app_name=self.name, user_id=self.user_id, session_id=self.session_id
        )
        print(f"State after agent run: {updated_session.state}")
        print("%%%%%%%%%%%%%%%%%%%%%%%")
        for event in updated_session.events:
            print("******************")
            print(event)
        print("%%%%%%%%%%%%%%%%%%%%%%%")
         # Add this session's content to the Memory Service
        # await self.memory_service.add_session_to_memory(updated_session)
        # print(f"State after agent run: {self.session.state}")
    
    async def update_session(self, event: Event):
        await self.session_service.append_event(self.session, event)

    def invoke(self, message: str):
        LOGGER.info(f"Invoking the agent for {self.user_id}, {message}")
        user_message = Content(parts=[Part(text=message)])
        state_changes = {
            "user:message": message
        }
        actions_with_update = EventActions(state_delta=state_changes)
        user_event = Event(
            invocation_id="inv_login_update",
            author="user", # Or 'agent', 'tool' etc.
            actions=actions_with_update,
            timestamp=time.time()
        )
        asyncio.run(self.update_session(user_event))

        for event in self.runner.run(
            user_id=self.user_id, session_id=self.session_id, new_message=user_message
        ):
            LOGGER.info(event)
            if event.is_final_response() and event.content and event.content.parts:
                response = "\n".join(part.text for part in event.content.parts)
                yield response
        
        state_changes = {
            "agent:message": response
        }
        actions_with_update = EventActions(state_delta=state_changes)
        user_event = Event(
            invocation_id="inv_login_update",
            author="agent", # Or 'agent', 'tool' etc.
            actions=actions_with_update,
            timestamp=time.time()
        )
        asyncio.run(self.update_session(user_event))
       
        asyncio.run(self.call_session())
