from __future__ import annotations


def diff_results(old: dict, new: dict) -> dict:
    """Compare deux rapports JSON xscan : constats ajoutés, résolus, inchangés, score.

    Clé d'identité d'un constat : (module, id, titre) — stable d'un scan à l'autre
    pour la même cible. Les constats de même identité répétés (ex: plusieurs cookies)
    sont comptés une seule fois.
    """
    old_map = _findings_map(old)
    new_map = _findings_map(new)
    old_score, new_score = int(old.get("score") or 0), int(new.get("score") or 0)
    return {
        "targets": {"old": old.get("target"), "new": new.get("target")},
        "old_score": old_score,
        "new_score": new_score,
        "delta": new_score - old_score,
        "added": [item for key, item in new_map.items() if key not in old_map],
        "resolved": [item for key, item in old_map.items() if key not in new_map],
        "kept_count": sum(1 for key in new_map if key in old_map),
    }


def _findings_map(scan: dict) -> dict:
    items: dict[tuple, dict] = {}
    for module in scan.get("modules", []):
        for finding in module.get("findings", []):
            key = (module.get("name"), finding.get("id"), finding.get("title"))
            items[key] = {**finding, "module": module.get("name")}
    return items
