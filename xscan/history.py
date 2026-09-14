"""Historique des scans : sauvegarde horodatée, liste, rechargement.

Chaque scan est stocké en JSON dans rapports/ (dossier ignoré par git —
données confidentielles client). La GUI liste, recharge et supprime.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from xscan.models import Finding, ModuleResult, ScanResult, Severity
from xscan.output import result_to_dict


def slugify_target(target: str) -> str:
    """Nom de fichier sûr dérivé de la cible (ex: exemple_com)."""
    try:
        import httpx as _httpx
        host = (_httpx.URL(target if "://" in target else f"https://{target}").host or "scan")
        return host.replace(".", "_")
    except Exception:  # noqa: BLE001
        return "scan"


def save_scan(result: ScanResult, directory: Path) -> Path:
    """Sauvegarde horodatée du scan. Retourne le chemin écrit."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(tz=UTC).strftime("%Y-%m-%d_%H%M%S")
    path = directory / f"{stamp}_{slugify_target(result.target)}.json"
    path.write_text(json.dumps(result_to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def list_scans(directory: Path) -> list[tuple[Path, dict]]:
    """Tous les scans sauvegardés (JSON valides), du plus récent au plus ancien."""
    scans: list[tuple[Path, dict]] = []
    for path in sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and "modules" in data:
            scans.append((path, data))
    return scans


def load_scan(path: Path) -> ScanResult:
    """Reconstruit un ScanResult depuis un JSON sauvegardé."""
    return result_from_dict(json.loads(path.read_text(encoding="utf-8")))


def delete_scan(path: Path) -> None:
    path.unlink(missing_ok=True)


def result_from_dict(data: dict) -> ScanResult:
    """Reconstruit un ScanResult depuis le dict produit par result_to_dict."""
    results: list[ModuleResult] = []
    for module in data.get("modules", []):
        findings = [
            Finding(f["id"], module["name"], Severity(f["severity"]), f["title"],
                    f.get("evidence", ""), f.get("remediation", ""))
            for f in module.get("findings", [])
        ]
        results.append(ModuleResult(module["name"], findings, module.get("error")))
    return ScanResult(target=data.get("target", ""),
                      duration_s=float(data.get("duration_s") or 0.0), results=results)
