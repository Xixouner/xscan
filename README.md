# xscan

CLI d'analyse de sécurité web, conçu **agent-first** : sortie JSON déterministe pour être piloté par un agent (Cline, script, CI), rapport lisible `rich` pour l'humain.

> **Avertissement** : n'analyser que des cibles sur lesquelles tu as une autorisation explicite (ton site, un programme de bug bounty dans son scope, un client avec mandat). Scanner sans autorisation est illégal.

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
xscan scan exemple.com              # analyse complète (passif + actif léger)
xscan scan exemple.com --passive    # modules passifs uniquement
xscan scan exemple.com --json       # sortie JSON pure (stdout)
xscan scan exemple.com -o rapport.json
xscan scan exemple.com --html rapport.html   # rapport HTML autonome (pour un client)
xscan diff ancien.json recent.json  # nouveaux constats / résolus / évolution du score
xscan modules                       # liste des modules
```

## Modules

| Module | Passif | Contenu |
|---|---|---|
| `transport` | oui | TLS (version, expiration de certificat), chaîne de redirection, HTTP/1.1 vs HTTP/2 |
| `headers` | oui | CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy, flags des cookies, CORS |
| `fingerprint` | oui | Serveur, framework (Next.js, WordPress…), CDN/analytics, meta generator |
| `subdomains` | oui | Sous-domaines via certificate transparency (crt.sh), résolution DNS, noms d'environnements sensibles |
| `endpoints` | oui | Chemins et endpoints extraits du JavaScript livré (api, admin, config…) |
| `forms` | oui | Formulaires : CSRF absent, password en GET/HTTP, action cross-origin |
| `exposure` | non | `.env`, `.git/HEAD`, `.DS_Store`, `server-status`, `/actuator/health`, secrets (AWS, Stripe, GitHub, Slack, Resend, Google) dans les pages et scripts JS — requêtes parallèles (semaphore) |
| `nuclei` | non | Orchestration optionnelle de [nuclei](https://github.com/projectdiscovery/nuclei) si installé (désactivé proprement sinon) |

Chaque finding porte un **ID stable** (`XSCAN-<MODULE>-<num>`), une sévérité, une preuve et une remédiation. Le score global part de 100 et baisse selon les sévérités (critique −30, high −20, medium −10, low −5).

## Exemple de sortie JSON

```json
{
  "tool": "xscan",
  "version": "0.3.0",
  "target": "https://exemple.com",
  "score": 78,
  "summary": {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
  "modules": [
    {
      "name": "headers",
      "error": null,
      "findings": [
        {"id": "XSCAN-HEADERS-001", "severity": "medium", "title": "Content-Security-Policy absente", "evidence": "en-tête 'content-security-policy' absent", "remediation": "Définir une CSP..."}
      ]
    }
  ]
}
```

## Garde-fous

- `--passive` : aucune requête inhabituelle (aucune probing de fichiers)
- Délai de 100 ms entre chaque requête du module `exposure`
- Les secrets détectés sont **masqués** dans les rapports (jamais le token complet)
- Timeout par requête : 10 s (configurable)

## Roadmap

- ~~Phase 2 — Recon~~ **fait** : sous-domaines (crt.sh + DNS), endpoints du JS, formulaires, parallélisme
- ~~Phase 3 — Pro~~ **fait** : rapport HTML autonome, orchestration nuclei, diff entre deux scans

## Développement

```bash
pytest            # suite de tests (parsers testés sans réseau via httpx.MockTransport)
ruff check xscan  # lint
```

## Licence

[MIT](LICENSE)
