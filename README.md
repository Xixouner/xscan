# xscan

[![CI](https://github.com/Xixouner/xscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Xixouner/xscan/actions/workflows/ci.yml)

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
xscan scan exemple.com --sarif rapport.sarif # SARIF 2.1.0 (GitHub Code Scanning)
xscan scan app.exemple.com --cookie "session=abc"    # scan authentifié
xscan scan app.exemple.com -H "Authorization: Bearer xxx"
xscan diff ancien.json recent.json  # nouveaux constats / résolus / évolution du score
xscan modules                       # liste des modules
```

### nuclei (optionnel)

Le module `nuclei` ajoute ~10 000 templates de détection communautaires (CVE, panneaux exposés, misconfigurations). Un seul appel l'installe :

```bash
xscan install-nuclei    # binaire officiel (~/.local/bin) + templates
```

Sans nuclei, le module se désactive proprement (finding info) — tous les autres modules continuent de fonctionner.

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
| `dns` | oui | Usurpation d'email : SPF absent ou `+all`, DMARC absent, CAA, DNSSEC — via DNS-over-HTTPS |
| `sri` | oui | Scripts tiers sans Subresource Integrity (risque supply chain) |
| `tls_deep` | oui | Protocoles TLS 1.0/1.1 encore acceptés, chaîne de certificats invalide, ciphers faibles |
| `http_deep` | non | Méthode TRACE (XST), PUT/DELETE annoncés, Host header reflection, security.txt absent (RFC 9116) |
| `ports` | non | Services sensibles exposés publiquement : Redis, MongoDB, MySQL, PostgreSQL, RDP, SMB, Elasticsearch, FTP, Telnet |
| `waf` | oui | Détection du WAF/CDN en amont (Cloudflare, Akamai, Sucuri, Imperva, Fastly...) |
| `csp_deep` | oui | Qualité de la CSP : `unsafe-inline`, `unsafe-eval`, sources wildcard/plain-HTTP |
| `pages` | non | Crawl interne (~12 pages) : contenu mixte HTTPS, stack traces exposées (Python, PHP, SQL, Java, .NET, Django/Rails) |
| `takeover` | oui | Subdomain takeover : CNAME orphelin vers S3, GitHub Pages, Heroku, Azure, Shopify... |
| `redirects_open` | non | Open redirects : injection d'une URL de sonde dans les paramètres de redirection (next=, url=, redirect=...) |
| `xss_probe` | non | Réflexion brute de paramètres (marqueur avec quotes non échappé) — candidats XSS à vérifier |
| `sourcemaps` | non | Fichiers `.map` exposés : code source original téléchargeable (chunks JS) |
| `xsleaks` | oui | Politiques d'isolation cross-origin : COOP, COEP, CORP (XS-Leaks) |
| `privacy` | oui | Trackers tiers (GTM, GA, Facebook, Hotjar, TikTok, Clarity...) et cookies — transparence RGPD |
| `nuclei` | non | Orchestration optionnelle de [nuclei](https://github.com/projectdiscovery/nuclei) si installé (désactivé proprement sinon) |

Chaque finding porte un **ID stable** (`XSCAN-<MODULE>-<num>`), une sévérité, une preuve et une remédiation. Le score global part de 100 et baisse selon les sévérités (critique −30, high −20, medium −10, low −5).

## Exemple de sortie JSON

```json
{
  "tool": "xscan",
  "version": "0.8.0",
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
