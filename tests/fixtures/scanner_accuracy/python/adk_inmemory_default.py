"""Regression fixture: ADK InMemoryRunner relying on the default ceiling of 500 LLM calls."""
from google.adk import runners

runner = runners.InMemoryRunner(agent=None)
