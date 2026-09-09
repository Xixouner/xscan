# AGENTS.md — xscan

## Purpose
CLI d'analyse de sécurité web agent-first : modules passifs/actifs, findings avec IDs stables, sortie Rich (humain) + JSON (agent). Projet vitrine sécurité d'Alexis Trechot.

## Stack
Python 3.13, typer (CLI), rich (rendu), httpx[http2] (async), pytest. Pas d'ORM, pas de config externe.

## Commands
```bash
pip install -e ".[dev]"          # install dev
pytest                           # tests
ruff check xscan                 # lint
xscan scan <url> --json          # usage agent
xscan scan <url>                 # usage humain
```

## Architecture
- `xscan/models.py` : Finding (id stable, sévérité, preuve, remédiation), ScanResult (score)
- `xscan/modules/` : un module = un fichier avec `name`, `passive`, `DESCRIPTION`, `run(client, base_url)`. Registry dans `__init__.py` (ALL_MODULES)
  - phase 1 : transport, headers, fingerprint, exposure
  - phase 2 : subdomains (crt.sh + DNS), endpoints (JS), forms (HTMLParser stdlib)
  - phase 3 : nuclei (subprocess optionnel), report_html (échappé), diff (clé module+id+titre)
  - expert : dns (DoH Cloudflare JSON), tls_deep (handshakes legacy), http_deep (TRACE/Host reflection), sri, ports (TCP connect)
- `xscan/doh.py` : helper DNS-over-HTTPS (Cloudflare, JSON, zéro dépendance)
- `xscan/runner.py` : exécution parallèle (gather, return_exceptions) — un module qui plante ne casse pas le scan
- `xscan/output.py` : rendu Rich + dict JSON stable
- `xscan/cli.py` : typer ; `--json` => JSON pur sur stdout, rien d'autre

## Conventions
- Logique d'analyse dans des fonctions pures testables (`evaluate`, `detect`, `find_secrets`, `plausible_content`) ; `run` ne fait que le network
- Sévérités : info/low/medium/high/critical ; IDs : `XSCAN-<MODULE>-<num>` jamais réutilisés
- Secrets jamais en clair dans les rapports (masquage 6 premiers caractères)
- Tests : httpx.MockTransport, pas de réseau réel dans pytest

## Gotchas
- Les SPA renvoient 200 (index.html) sur n'importe quel chemin → toujours filtrer par `plausible_content` (pattern de contenu ou content-type) avant de crier au fichier exposé
- `vi.clearAllMocks`-style pollution : chaque module doit repartir d'un état propre (leçon Facture-X)
- MockTransport ignore http2 : ne pas tester la version HTTP en unitaire
