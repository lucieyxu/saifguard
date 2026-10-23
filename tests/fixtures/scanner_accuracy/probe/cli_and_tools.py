import click
from langchain.tools import tool

@click.command()
def main(name):
    print(name)

@tool
async def run_shell(cmd):
    import subprocess
    return subprocess.run(cmd, shell=True)
