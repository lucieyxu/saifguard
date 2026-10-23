"""Regression fixture: async tools, keyword-only / positional-only parameters, self / cls."""
import subprocess

from langchain.tools import tool


@tool
async def run_shell(cmd):
    return subprocess.run(cmd, shell=True)


@tool
def search_docs(query: str, *, limit):
    return query[:limit]


@tool
def lookup_user(user_id, /, verbose: bool = False):
    return {"id": user_id, "verbose": verbose}


@tool
def typed_tool(query: str, *, limit: int = 5) -> str:
    return query[:limit]


class Toolbox:
    @tool
    def method_tool(self, query: str) -> str:
        return query

    @classmethod
    @tool
    def class_tool(cls, query: str) -> str:
        return query
