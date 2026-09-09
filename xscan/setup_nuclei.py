from __future__ import annotations

import platform
import stat
import zipfile
from pathlib import Path

import httpx

_GITHUB_API = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"
_DEFAULT_DIR = Path.home() / ".local" / "bin"


def asset_needle(platform_name: str, machine: str) -> str | None:
    """Logique pure (testée) : suffixe d'asset nuclei pour cette machine."""
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    os_name = {"Linux": "linux", "Darwin": "darwin"}.get(platform_name)
    if arch is None or os_name is None:
        return None
    return f"{os_name}_{arch}.zip"


def pick_asset(assets: list[dict], needle: str) -> str | None:
    """Logique pure (testée) : URL de l'asset binaire dans une release nuclei."""
    for asset in assets:
        asset_name = str(asset.get("name", ""))
        if asset_name.endswith(needle) and "checksums" not in asset_name:
            return str(asset.get("browser_download_url"))
    return None


def install(target_dir: Path | None = None) -> str:
    """Télécharge la dernière release nuclei et installe le binaire. Retourne son chemin."""
    directory = target_dir or _DEFAULT_DIR
    needle = asset_needle(platform.system(), platform.machine())
    if needle is None:
        raise RuntimeError(f"Plateforme non supportée : {platform.system()} {platform.machine()}")
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        release = client.get(_GITHUB_API, headers={"Accept": "application/vnd.github+json"})
        release.raise_for_status()
        url = pick_asset(release.json().get("assets", []), needle)
        if url is None:
            raise RuntimeError(f"Aucun asset nuclei « {needle} » dans la dernière release")
        directory.mkdir(parents=True, exist_ok=True)
        zip_path = directory / "nuclei_download.zip"
        zip_path.write_bytes(client.get(url).content)
    destination = _extract(zip_path, directory)
    zip_path.unlink()
    destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(destination)


def _extract(zip_path: Path, directory: Path) -> Path:
    with zipfile.ZipFile(zip_path) as archive:
        member = next(name for name in archive.namelist()
                      if name == "nuclei" or name.endswith("/nuclei"))
        destination = directory / "nuclei"
        destination.write_bytes(archive.read(member))
    return destination
