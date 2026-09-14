"""Interface graphique xscan : la GUI habille le moteur, elle ne réinvente rien.

Le scan tourne dans un thread, le moteur émet des événements (on_event) et
l'interface se met à jour à chaque événement — le même contrat que --stream.
"""
from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

import flet as ft

from xscan import __version__, web
from xscan.http import build_client
from xscan.models import ScanResult
from xscan.modules import ALL_MODULES
from xscan.output import result_to_dict
from xscan.report_html import render_html
from xscan.runner import run_scan
from xscan.sarif import to_sarif

_RAPPORTS_DIR = Path(__file__).resolve().parent.parent / "rapports"
_SEV_COLORS = {
    "critical": "0xFFB91C1C", "high": "0xFFDC2626", "medium": "0xFFD97706",
    "low": "0xFF0891B2", "info": "0xFF6B7280",
}


def _score_color(score: int) -> str:
    if score >= 85:
        return "0xFF16A34A"
    return "0xFFD97706" if score >= 60 else "0xFFDC2626"


def _safe_name(target: str) -> str:
    try:
        import httpx as _httpx
        return (_httpx.URL(target if "://" in target else f"https://{target}").host or "scan").replace(".", "_")
    except Exception:  # noqa: BLE001
        return "scan"


def _finding_row(finding: dict) -> ft.Row:
    severity = finding.get("severity", "info")
    return ft.Row([
        ft.Container(
            ft.Text(severity, color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
            bgcolor=_SEV_COLORS.get(severity, "0xFF6B7280"), padding=4, border_radius=4,
        ),
        ft.Text(finding.get("title", "—"), expand=True, size=13),
    ])


class XscanGui:
    """Fenêtre principale : formulaire, progression live, findings, exports."""

    def __init__(self, page: ft.Page) -> None:
        self.page = page
        self.state: dict = {"result": None, "scanning": False}
        page.title = f"xscan {__version__} — analyse de sécurité web"
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 24
        page.window.width = 1080
        page.window.height = 760
        self._build()

    def _build(self) -> None:
        self.url = ft.TextField(label="Cible", hint_text="exemple.com", expand=True)
        self.module_dd = ft.Dropdown(
            label="Module (tous si vide)",
            options=[ft.DropdownOption(key=m.name, text=m.name) for m in ALL_MODULES],
            width=300,
        )
        self.passive_sw = ft.Switch(label="Passif uniquement", value=False)
        self.cookie = ft.TextField(label="Cookie de session (optionnel)", width=340, hint_text="session=...")
        self.timeout = ft.TextField(label="Timeout (s)", value="10", width=100)
        self.run_btn = ft.ElevatedButton("Lancer le scan", on_click=self._run_clicked,
                                         icon=ft.Icons.PLAY_ARROW, height=48)
        self.progress = ft.ProgressBar(visible=False, expand=True)
        self.status = ft.Text("Prêt. N'analyser que des cibles autorisées.", size=13)
        self.score_text = ft.Text("—", size=30, weight=ft.FontWeight.BOLD)
        self.score_box = ft.Container(self.score_text, bgcolor="0xFF374151", padding=12,
                                      border_radius=8, width=130, alignment=ft.Alignment.CENTER)
        self.findings_view = ft.ListView(expand=True, spacing=6, height=340)
        self.json_btn = ft.ElevatedButton("JSON", on_click=lambda e: self._export("json"), disabled=True)
        self.html_btn = ft.ElevatedButton("HTML", on_click=lambda e: self._export("html"), disabled=True)
        self.sarif_btn = ft.ElevatedButton("SARIF", on_click=lambda e: self._export("sarif"), disabled=True)
        header = ft.Row([
            ft.Text(f"xscan {__version__}", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            self.score_box,
        ])
        self.page.add(
            header,
            ft.Divider(),
            ft.Row([self.url, self.run_btn]),
            ft.Row([self.module_dd, self.passive_sw, self.cookie, self.timeout]),
            ft.Row([self.progress]),
            self.status,
            ft.Divider(),
            ft.Row([ft.Text("Constats", size=16, weight=ft.FontWeight.BOLD),
                    ft.Container(expand=True),
                    self.json_btn, self.html_btn, self.sarif_btn]),
            self.findings_view,
        )

    # ---------- scan ----------

    def _run_clicked(self, _event=None) -> None:
        if self.state["scanning"]:
            return
        raw = (self.url.value or "").strip()
        try:
            target = web.normalize_target(raw)
        except ValueError as exc:
            self.status.value = str(exc)
            self.page.update()
            return
        if not target:
            self.status.value = "Renseigne une cible (ex: exemple.com)."
            self.page.update()
            return
        self.state["scanning"] = True
        self.state["result"] = None
        self.run_btn.disabled = True
        self.progress.visible = True
        self.findings_view.controls.clear()
        self.page.update()
        threading.Thread(target=self._worker, args=(target,), daemon=True).start()

    def _worker(self, target: str) -> None:
        only = [self.module_dd.value] if self.module_dd.value else None
        extra = {"Cookie": self.cookie.value.strip()} if (self.cookie.value or "").strip() else None
        try:
            timeout_value = float(self.timeout.value or 10)
        except ValueError:
            timeout_value = 10.0

        async def job() -> ScanResult:
            async with build_client(timeout_value, extra) as client:
                return await run_scan(client, target, passive_only=self.passive_sw.value,
                                      only=only, on_event=self._handle_event)

        try:
            self.state["result"] = asyncio.run(job())
        except Exception as exc:  # noqa: BLE001
            self.status.value = f"Échec : {exc}"
        finally:
            self.state["scanning"] = False
            self.progress.visible = False
            self.run_btn.disabled = False
            for button in (self.json_btn, self.html_btn, self.sarif_btn):
                button.disabled = self.state["result"] is None
            self.page.update()

    def _handle_event(self, event: dict) -> None:
        kind = event["event"]
        if kind == "scan_started":
            self.status.value = f"Scan de {event['target']} — {len(event['modules'])} modules en parallèle…"
        elif kind == "module_started":
            self.status.value = f"module {event['module']} en cours…"
        elif kind == "module_done":
            for finding in event["findings"]:
                self.findings_view.controls.append(_finding_row(finding))
            suffix = f" — erreur : {event['error']}" if event["error"] else ""
            self.status.value = f"module {event['module']} : {event['count']} constat(s){suffix}"
        elif kind == "scan_done":
            self.score_text.value = f"{event['score']}/100"
            self.score_box.bgcolor = _score_color(event["score"])
            self.status.value = f"Terminé en {event['duration_s']}s — exports disponibles."
        elif kind == "scan_interrupted":
            self.status.value = "Scan interrompu."
        self.page.update()

    # ---------- exports ----------

    def _export(self, kind: str) -> None:
        result: ScanResult | None = self.state.get("result")
        if result is None:
            return
        _RAPPORTS_DIR.mkdir(exist_ok=True)
        base = _safe_name(result.target)
        if kind == "json":
            path = _RAPPORTS_DIR / f"{base}.json"
            path.write_text(json.dumps(result_to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")
        elif kind == "html":
            path = _RAPPORTS_DIR / f"{base}.html"
            path.write_text(render_html(result), encoding="utf-8")
        else:
            path = _RAPPORTS_DIR / f"{base}.sarif"
            path.write_text(json.dumps(to_sarif(result), indent=2, ensure_ascii=False), encoding="utf-8")
        self.status.value = f"Exporté : {path}"
        self.page.update()


def main() -> None:
    ft.app(target=XscanGui)


if __name__ == "__main__":
    main()
