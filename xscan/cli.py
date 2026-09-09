from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from xscan import __version__
from xscan.http import build_client
from xscan.modules import ALL_MODULES
from xscan.output import render_json, render_rich
from xscan.runner import run_scan

app = typer.Typer(
    help="xscan — analyse de sécurité web agent-first (sortie Rich ou JSON).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _print_version(value: bool) -> None:
    if value:
        console.print(f"xscan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_print_version, is_eager=True, help="Affiche la version."),
) -> None:
    """xscan — analyse de sécurité web. N'analyser que des cibles autorisées."""


def _normalize(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    parsed = httpx.URL(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.host:
        raise typer.BadParameter(f"URL invalide : {url}")
    return str(parsed)


async def _scan(target: str, timeout: float, passive_only: bool):
    async with build_client(timeout) as client:
        return await run_scan(client, target, passive_only=passive_only)


@app.command()
def scan(
    url: str = typer.Argument(..., help="Cible à analyser (ex: exemple.com)."),
    passive: bool = typer.Option(False, "--passive", help="Modules passifs uniquement."),
    json_output: bool = typer.Option(False, "--json", help="JSON pur sur stdout (agents / pipelines)."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Écrit aussi le JSON dans ce fichier."),
    timeout: float = typer.Option(10.0, help="Timeout réseau (secondes)."),
) -> None:
    """Scanne une cible et affiche les findings."""
    target = _normalize(url)
    if json_output:
        result = asyncio.run(_scan(target, timeout, passive))
        text = render_json(result)
        if output:
            output.write_text(text, encoding="utf-8")
        typer.echo(text)
        return

    console.print("[bold]xscan[/] — rappel : n'analyser que des cibles autorisées.")
    console.print(f"Cible : [cyan]{target}[/] | modules : {'passifs' if passive else 'tous'}")
    with console.status("Scan en cours…"):
        result = asyncio.run(_scan(target, timeout, passive))
    if output:
        output.write_text(render_json(result), encoding="utf-8")
        console.print(f"[dim]JSON écrit dans {output}[/]")
    render_rich(result, console)


@app.command("modules")
def modules_list() -> None:
    """Liste les modules disponibles."""
    table = Table(title="Modules xscan")
    for column in ("Nom", "Passif", "Description"):
        table.add_column(column)
    for module in ALL_MODULES:
        table.add_row(module.name, "oui" if module.passive else "non", module.DESCRIPTION)
    console.print(table)


if __name__ == "__main__":
    app()
