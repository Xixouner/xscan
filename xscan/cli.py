from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from xscan import __version__
from xscan.diff import diff_results
from xscan.http import build_client
from xscan.modules import ALL_MODULES
from xscan.output import render_diff, render_json, render_rich
from xscan.report_html import render_html
from xscan.runner import load_modules, run_scan
from xscan.sarif import to_sarif
from xscan.setup_nuclei import install as install_nuclei_binary

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


async def _scan(target: str, timeout: float, passive_only: bool,
                extra_headers: dict[str, str] | None = None, only: list[str] | None = None):
    async with build_client(timeout, extra_headers) as client:
        return await run_scan(client, target, passive_only=passive_only, only=only)


def _maybe_write_html(result, html_output: Path | None) -> None:
    if html_output is not None:
        html_output.write_text(render_html(result), encoding="utf-8")


@app.command()
def scan(
    url: str = typer.Argument(..., help="Cible à analyser (ex: exemple.com)."),
    passive: bool = typer.Option(False, "--passive", help="Modules passifs uniquement."),
    modules: str | None = typer.Option(None, "--modules", "-m",
                                       help="Modules à lancer, séparés par des virgules (ex: headers,dns)."),
    json_output: bool = typer.Option(False, "--json", help="JSON pur sur stdout (agents / pipelines)."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Écrit aussi le JSON dans ce fichier."),
    html_output: Path | None = typer.Option(None, "--html", help="Écrit un rapport HTML autonome dans ce fichier."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Rapport SARIF 2.1.0 (GitHub Code Scanning)."),
    cookie: str | None = typer.Option(None, "--cookie", help="Cookie de session pour scanner authentifié."),
    header: list[str] = typer.Option([], "--header", "-H", help="En-tête supplémentaire (répétable, 'Nom: valeur')."),
    timeout: float = typer.Option(10.0, help="Timeout réseau (secondes)."),
) -> None:
    """Scanne une cible et affiche les findings."""
    target = _normalize(url)
    extra_headers: dict[str, str] = {}
    if cookie:
        extra_headers["Cookie"] = cookie
    for raw_header in header:
        if ":" in raw_header:
            key, value = raw_header.split(":", 1)
            extra_headers[key.strip()] = value.strip()
    only = [name_value.strip() for name_value in modules.split(",")] if modules else None
    if only:
        try:
            load_modules(False, only)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    if json_output:
        result = asyncio.run(_scan(target, timeout, passive, extra_headers or None, only))
        text = render_json(result)
        if output:
            output.write_text(text, encoding="utf-8")
        _maybe_write_sarif(result, sarif_output)
        typer.echo(text)
        return

    console.print("[bold]xscan[/] — rappel : n'analyser que des cibles autorisées.")
    console.print(f"Cible : [cyan]{target}[/] | modules : {'passifs' if passive else 'tous'}"
                  f"{' | authentifié' if extra_headers else ''}")
    with console.status("Scan en cours…"):
        result = asyncio.run(_scan(target, timeout, passive, extra_headers or None, only))
    if output:
        output.write_text(render_json(result), encoding="utf-8")
        console.print(f"[dim]JSON écrit dans {output}[/]")
    _maybe_write_sarif(result, sarif_output)
    if sarif_output:
        console.print(f"[dim]SARIF écrit dans {sarif_output}[/]")
    _maybe_write_html(result, html_output)
    if html_output:
        console.print(f"[dim]Rapport HTML écrit dans {html_output}[/]")
    render_rich(result, console)


def _maybe_write_sarif(result, sarif_output: Path | None) -> None:
    if sarif_output is not None:
        sarif_output.write_text(json.dumps(to_sarif(result), indent=2, ensure_ascii=False), encoding="utf-8")


@app.command("install-nuclei")
def install_nuclei() -> None:
    """Télécharge et installe nuclei (binaire officiel + templates)."""
    existing = shutil.which("nuclei")
    if existing:
        console.print(f"[green]nuclei déjà installé :[/] {existing}")
        return
    console.print("Téléchargement de la dernière release nuclei (projectdiscovery)…")
    try:
        path = install_nuclei_binary()
    except (RuntimeError, httpx.HTTPError) as exc:
        console.print(f"[red]Échec de l'installation :[/] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Binaire installé :[/] {path}")
    if path.rsplit("/", 1)[0] not in __import__("os").environ.get("PATH", ""):
        console.print(f"[yellow]Attention : {path.rsplit('/', 1)[0]} n'est pas dans le PATH — "
                      f"ajoute-le (export PATH=$PATH:~/.local/bin).[/]")
    console.print("Téléchargement des templates (peut prendre une minute)…")
    result = subprocess.run([path, "-ut", "-silent"], capture_output=True, text=True, timeout=300, check=False)
    if result.returncode != 0:
        console.print(f"[yellow]Templates : le téléchargement a signalé un problème[/] "
                      f"({result.stderr.strip()[:120]}) — réessaie plus tard avec `nuclei -ut`.")
        return
    console.print("[green]Templates installés.[/] Le module nuclei est maintenant actif dans les scans.")


def _load_report(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(f"Fichier illisible ou JSON invalide : {path} ({exc})") from exc
    if not isinstance(data, dict) or "modules" not in data:
        raise typer.BadParameter(f"{path} n'est pas un rapport xscan (généré avec `xscan scan --json -o fichier.json`).")
    return data


@app.command()
def diff(
    old: Path = typer.Argument(..., help="Ancien rapport JSON."),
    new: Path = typer.Argument(..., help="Nouveau rapport JSON."),
    json_output: bool = typer.Option(False, "--json", help="Résultat du diff en JSON."),
) -> None:
    """Compare deux rapports JSON de xscan (nouveaux / résolus / score)."""
    report = diff_results(_load_report(old), _load_report(new))
    if json_output:
        typer.echo(json.dumps(report, indent=2, ensure_ascii=False))
        return
    render_diff(report, console)


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
