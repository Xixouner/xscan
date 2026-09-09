from __future__ import annotations


def diff_results(old: dict, new: dict) -> dict:
    """Compare deux rapports JSON xscan : constats ajoutés, résolus, aggravés, inchangés, score.

    Clé d'identité d'un constat : (module, id, titre) — stable d'un scan à l'autre
    pour la même cible. Un constat dont la sévérité évolue est signalé dans `changed`
    (ex: low -> medium = aggravation) plutôt que compté comme ajouté/résolu.
    """
    old_map = _findings_map(old)
    new_map = _findings_map(new)
    old_score, new_score = int(old.get("score") or 0), int(new.get("score") or 0)
    added: list[dict] = []
    changed: list[dict] = []
    kept_count = 0
    for key, item in new_map.items():
        before = old_map.get(key)
        if before is None:
            added.append(item)
            continue
        kept_count += 1
        if before.get("severity") != item.get("severity"):
            changed.append({"before": before, "after": item})
    resolved = [item for key, item in old_map.items() if key not in new_map]
    return {
        "targets": {"old": old.get("target"), "new": new.get("target")},
        "old_score": old_score,
        "new_score": new_score,
        "delta": new_score - old_score,
        "added": added,
        "resolved": resolved,
        "changed": changed,
        "kept_count": kept_count,
    }


def _findings_map(scan: dict) -> dict:
    items: dict[tuple, dict] = {}
    for module in scan.get("modules", []):
        for finding in module.get("findings", []):
            key = (module.get("name"), finding.get("id"), finding.get("title"))
            items[key] = {**finding, "module": module.get("name")}
    return items
