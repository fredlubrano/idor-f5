# DarkMoon — usage correct (lab pfcorp)

Source: `Dark-Moon/docs/full.md` §II.7.c + agent `pentest`.

## Ne pas faire

- Prompts de 80 lignes avec phases curl/ffuf micro-gérées
- Forcer uniquement `execute_command` (ignorer `run_workflow`)
- Relancer `tokenize_prompt` à la main (le plugin privacy le fait)

## Faire

```bash
cd /opt/Dark-Moon
./darkmoon.sh 'TARGET: https://on.pfcorp.eu/ PROGRAM="pfcorp-transfer-lab" FOCUS=upload,misconfig,idor,path-traversal,waf-bypass EXCLUDE=brute-force,dos NOISE=moderate FORMAT=standard SAFE_HARBOR=yes RULES="..."'
```

Flags utiles : `PROGRAM` `FOCUS` `EXCLUDE` `NOISE` (`stealth|low|moderate`) `FORMAT` `RULES` `SAFE_HARBOR`.

## Suivi

```bash
./darkmoon.sh --log <session_id>   # logs MCP temps réel
# ou
tail -f reports/<fichier>.log
```

## Workflows MCP à laisser l’agent appeler

- `web_crawler` / `vulnerability_scan` / `port_scan` / `subdomain_discovery`
- Dashboard : `dashboard_init_campaign` → `push_finding` → `finalize_campaign`

## Contexte WAF lab (mettre dans RULES=)

ASM répond **HTTP 404** = **blocage**, pas « path missing ». Body typique : `Erreur 404 - Oups.` (CL≈3821). GET `/` peut être **APP** (texte transfer.sh) avec status 404.

### Fingerprint headers page de blocage (confirmé)

```
HTTP/1.1 404 Not Found
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
Pragma: no-cache
Connection: close
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'none'; style-src 'sha256-hnXXUHaMx+GhCp6ukMH1b671JjYTLSNC2q7WA2SZ9rU='; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

Notes : via HTTP/2 le status reste 404 avec le même set. Hash vérifié live 2026-09-21 (MATCH body `<style>`). Plus de `unsafe-inline`.
