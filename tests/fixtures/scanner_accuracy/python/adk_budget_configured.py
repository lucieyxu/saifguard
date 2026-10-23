"""Regression fixture: ADK runner with an explicit RunConfig(max_llm_calls) budget."""
from google.adk.agents.run_config import RunConfig
from google.adk.runners import Runner


def run(agent, session_service, message):
    runner = Runner(app_name="app", agent=agent, session_service=session_service)
    return runner.run(
        user_id="u",
        session_id="s",
        new_message=message,
        run_config=RunConfig(max_llm_calls=50),
    )
