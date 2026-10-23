"""Regression fixture: agent runtimes that PY_AGENT_NO_MAX_ITER must (not) flag outside ADK."""
from langchain.agents import AgentExecutor
from langgraph.prebuilt import create_react_agent
from mylib.jobs import Runner


def build(model, tools, agent):
    graph = create_react_agent(model, tools)
    job = Runner(name="nightly")
    default_executor = AgentExecutor(agent=agent, tools=tools)
    timed_executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None, max_execution_time=60)
    unbounded_executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None)
    unbounded_factory = AgentExecutor.from_agent_and_tools(agent=agent, tools=tools, max_iterations=None)
    return graph, job, default_executor, timed_executor, unbounded_executor, unbounded_factory
