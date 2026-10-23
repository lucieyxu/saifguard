"""Regression fixture: CLI command decorators (click / Typer) are not agent tools."""
import click
import typer

app = typer.Typer()


@click.command()
@click.option("--name")
def main(name):
    print(name)


@app.command()
def run(path, verbose=False):
    print(path, verbose)


@click.group()
def cli():
    pass
