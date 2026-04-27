# Data Acquisition

Tutto ciò che serve per riprodurre il paper è registrato in `sources.json` e scaricato da `fetch.py`. Niente URL hard-coded sparsi nel codice.

## Inventario (v1)

**Target apps (≥5 richiesti):**
- Juice Shop, WebGoat, DVWA, NodeGoat, bWAPP, VAmPI

**Pentester tools (≥4 richiesti per Rank A\*):**
- Shannon, PentestGPT, HackingBuddyGPT, Vulnhuntr, AutoPenBench

**Ground truth:**
- CISA KEV (live feed)
- NVD recent CVE (live feed)
- Juice Shop challenges YAML (in-repo, canonical per quel target)

**Literature:**
- 4 paper arXiv per related-work anchor + defense comparison

## Comandi

```bash
# tutto
.venv/bin/python -m data.fetch

# solo i target
.venv/bin/python -m data.fetch --category target-app

# solo una risorsa
.venv/bin/python -m data.fetch --id tool-shannon

# dry-run (mostra cosa farebbe, niente disco)
.venv/bin/python -m data.fetch --dry-run
```

Output finisce sotto `data/_cache/` (gitignored).

## Convenzioni

- **Pinning.** Ogni `git` resource ha un `ref` (tag, branch o commit SHA). I `docker` hanno digest. Gli `http` con contenuto stabile hanno `sha256`; i feed live (KEV, NVD) usano la sentinella `REFRESH_PER_RUN`.
- **Idempotenza.** `fetch_one` su una risorsa già scaricata: `skipped` se sha256 match, `updated` se git checkout cambia ref, `fetched` se nuova.
- **Determinismo riproducibilità.** Prima di ogni esperimento committare l'output di `git rev-parse HEAD` per ogni tool/target — vedi `paper/results/lab-digests.txt` (creato dal runner).

## Cosa NON è ancora qui

- **Docker images dei target** — il pull è fatto da `make lab-up` (richiede daemon), `fetch.py` registra solo i digest in `data/_cache/docker-manifest.txt`.
- **Modelli LLM** — non li scarichiamo: usiamo Anthropic API con `model` pinnato per esperimento.
- **Dati privati / contractor** — non previsti (vedi `feedback_phd_scope`: paper UnivAQ pure-academic).
