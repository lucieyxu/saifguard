"""Regression fixture: ADK budget set through the ADK_MAX_LLM_CALLS environment variable."""
import os

os.environ.setdefault("ADK_MAX_LLM_CALLS", "40")

from google.adk.runners import InMemoryRunner  # noqa: E402

runner = InMemoryRunner(agent=None)
