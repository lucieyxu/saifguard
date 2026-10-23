"""Regression fixture: ADK RunConfig with max_llm_calls <= 0 disables the LLM-call ceiling."""
from google.adk.agents.run_config import RunConfig
from google.adk.runners import InMemoryRunner


def run(agent, message):
    runner = InMemoryRunner(agent=agent)
    return runner.run(user_id="u", session_id="s", new_message=message, run_config=RunConfig(max_llm_calls=0))
