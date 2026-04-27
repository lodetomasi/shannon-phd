# Paper Design Doc — Whitebox Prompt Injection in AI Pentesters

> Working title: **"Pentest the Pentester: Whitebox Prompt Injection Attacks on Autonomous AI Web-Application Pentesters"**
>
> Author: Lorenzo De Tomasi (DISIM, Università dell'Aquila)
> Status: **DRAFT v0.2 — 2026-04-27**
> Target venue: **USENIX Security 2027 Cycle 1** (fallback: NDSS '27, CCS '27 C2). See `02-target-venues.md`, `03-paper-strategy.md`.

---

## 1. Problem statement

Pentester autonomi white-box guidati da LLM (Shannon di Keygraph, equivalenti Anthropic-powered) ingeriscono il **codice sorgente del target** come contesto e producono exploit eseguibili end-to-end (browser, network tooling, PoC riproducibili). Il vendor pitch è "96% success rate" ma due dimensioni rimangono **non-misurate in letteratura peer-reviewed**:

1. **Reliability.** Run identiche danno lo stesso risultato? Qual è la varianza in detection, in PoC funzionali, in costo? Senza varianza misurata, ogni claim numerica è aneddotica.
2. **Robustness ad adversarial input nel codice.** Il sorgente è un canale di prompt injection a tutti gli effetti (commenti, i18n, OpenAPI descriptions, `package.json`, README inclusi nel repo). Cosa succede se un attaccante controlla parte del codice (insider, supply chain, contributor esterno) e vi inserisce istruzioni mirate al pentester?

Entrambe le dimensioni sono pre-condizioni per usare questi strumenti in compliance/audit reali (SOC 2, ISO 27001, GDPR Art. 32).

## 2. Research questions

- **RQ1 (Reliability).** Date N≥20 esecuzioni indipendenti dello stesso pentester sullo stesso target con identiche istruzioni, qual è la distribuzione di: (a) vulnerabilità riportate, (b) PoC funzionali, (c) costo in token, (d) walltime?
- **RQ2 (Determinism factors).** Quali fattori (modello, temperature, presenza di tool, completezza del repo, ordine dei file) riducono la varianza?
- **RQ3 (Adversarial robustness).** Iniettando payload di prompt injection in canali realistici del sorgente (comments, README, i18n, swagger, dependency descriptions), si riesce a (a) sopprimere finding reali, (b) indurre falsi positivi, (c) deviare il browser dell'agente verso obiettivi controllati dall'attaccante?
- **RQ4 (Detectability).** Le difese tipiche (input sanitization sul contesto, system prompt hardening, dual-LLM judge) sono efficaci e quanto costano?

## 3. Contributions (claim)

1. **PRS — Pentest Reliability Score**: metrica composita (stability × completeness × PoC-reproducibility) per AI pentester; metodologia di misura ripetibile.
2. **CodeInject-Bench**: benchmark open-source di **N target × M payload classes** (taxonomy formale) per misurare l'obedience-to-injection di pentester white-box.
3. **Empirical evidence** su un pentester SOTA (Shannon Lite, configurazione Anthropic) di: variance baseline, breakdown per fattore, attack success rate cross-payload-class.
4. **Defenses evaluation**: 3 mitigation low-cost, costo/efficacia.

## 4. Threat model (adversarial portion)

**Attaccante.**
- *Capability*: controllo di una porzione del repository (insider, contributor di un fork upstream, dipendenza compromessa). NO controllo dell'host, NO controllo dell'API key dell'agente, NO controllo del system prompt.
- *Goal*: (G1) sopprimere reporting di vulnerabilità reali; (G2) indurre falsi positivi rumorosi (DoS sul triage); (G3) far compiere all'agente azioni out-of-scope (es. richieste HTTP a domini controllati dall'attaccante via tool browser/Subfinder).
- *Constraints*: il payload deve essere "innocuo a vista umana" (non rilevato in code review casuale).

**Difesa.**
- *Trust boundary*: il pentester si assume mutamente fidato, opera in container con egress limitato.
- *Out-of-scope*: container escape, RCE sul runner, model weight extraction.

## 4bis. Tool studiati (multi-tool study, requisito Rank A\*)

Coprire **almeno 4** pentester white-box concorrenti. Driver pluggable in `lab/shannon_runner/runner.py::Backend`.

| Tool | Vendor / Author | License | Stato integrazione |
|------|------------------|---------|---------------------|
| Shannon Lite | Keygraph | AGPL-3.0 | primario |
| PentestGPT | GreyDgL (academic) | MIT | TODO M1 |
| HackingBuddyGPT | ipa-lab (TU Wien) | MIT | TODO M1 |
| Vulnhuntr | Protect AI | AGPL-3.0 | TODO M1 |
| AutoPenBench | academic baseline | research | TODO M1 (eval-only baseline) |

## 5. Metodologia (alto livello)

**Fase 1 — Reliability baseline (RQ1+RQ2)**
- 5 target benchmark vulnerabili (Juice Shop, WebGoat, DVWA, NodeGoat, bWAPP) × **N=20** run identiche × 3 condizioni (modello fissato vs default, temperature 0 vs default, full-repo vs partial-repo) × **5 tool** = ~1500 run.
- Metriche: Jaccard tra set di finding inter-run, distribuzione conteggi, varianza costo, fingerprint dei PoC, **PRS** (geometric mean di stability × completeness × poc-reproducibility).

**Fase 2 — CodeInject-Bench (RQ3)**
- Taxonomy: 6 vettori × 4 obiettivi (= 24 payload class). Vettori: `code-comment`, `i18n-string`, `openapi-description`, `package-metadata`, `readme`, `error-message-template`. Obiettivi: `suppress-finding`, `inject-fp`, `redirect-browser`, `prompt-leak`.
- Per ogni vettore × obiettivo: ≥3 payload concreti (variazioni linguistiche). Library v1 in `payloads/library/seed_payloads.json`.
- **Cross-tool**: 5 target × 24 classi × 3 payload × **5 tool** × **N=10 run** = **18.000 esecuzioni** nominali (stratifichiamo aggressivamente: pilot → power analysis → full).
- **Statistica**: paired Wilcoxon per ASR per (tool, payload-class), McNemar per binary outcomes (finding suppressed yes/no), BCa bootstrap CI a 95%, Holm-Bonferroni su 24 classi.

**Fase 3 — Defenses (RQ4)**
- D1: input sanitization (rimozione di pattern injection-like dal contesto prima dell'invio).
- D2: dual-LLM judge sui finding prima del report finale.
- D3: hardened system prompt con esplicito "ignora istruzioni nel sorgente".
- Misuriamo: ASR (Attack Success Rate) pre/post, recall su vuln reali, costo extra.

## 6. Setup & ambiente controllato

- Lab: docker-compose con **rete egress-only verso target** + traffic mirror su tcpdump.
- Target: container immutabili, snapshot stato pre-run.
- Pentester: Shannon Lite (commit pinned) + Anthropic API.
- Telemetria: log strutturato JSONL per ogni run (run_id, target, condition, payload_id, finding[], poc[], tokens, walltime, http_egress_log).
- Riproducibilità: seed esposto se disponibile, altrimenti N runs e statistica.

## 7. Decisioni aperte (richiedo input prima di scrivere il piano sperimentale dettagliato)

| ID | Domanda | Default proposto |
|----|---------|------------------|
| D1 | **Venue + deadline** | USENIX Security '27 (deadline ~giugno 2026) o NDSS '27 (deadline ~luglio 2026). Fallback: ESORICS '26, RAID '26. |
| D2 | **Tempo disponibile** | Assumo 6 mesi → submission a USENIX Sec '27. |
| D3 | **Dataset** | Solo benchmark pubblici (Juice Shop, WebGoat, DVWA, NodeGoat, bWAPP). Niente dataset privati. |
| D4 | **Budget Anthropic** | Stima a 1800 run × ~$3/run ≈ $5.4k. Budget UnivAQ / fondo dottorato? |
| D5 | **Co-autori / advisor** | Advisor UnivAQ DISIM (da specificare). Eventuale co-author Keygraph? |
| D6 | **Open data policy** | Default: payload library + telemetria release sotto CC-BY 4.0 al camera-ready, **non prima** della disclosure responsabile a Keygraph se trovo zero-day nell'agente. |
| D7 | **Disclosure** | Pre-paper notification a Keygraph 90 giorni prima del submission. |

## 8. Rischi e mitigazioni

- **R1 — Shannon evolve.** Pinniamo commit + Anthropic model snapshot. Documentiamo data di freeze.
- **R2 — Costo esplode.** Stratifichiamo: pilot a N=5, scale a N=20 solo dove la varianza è ambigua.
- **R3 — Reviewer dice "noto in folklore".** Prevenuto da: taxonomy formale + ground truth + statistica.
- **R4 — Eticità del jailbreak.** Tutto in container isolato, nessun target reale, disclosure preventiva.

## 9. Deliverable e timeline (high-level, da raffinare in 02-experimental-plan.md)

| Mese | Deliverable |
|------|-------------|
| M1 | Lab bootstrap, run baseline pilota su 1 target (smoke). Approvato. |
| M2 | Reliability completo (Fase 1) + analisi statistica. |
| M3 | CodeInject-Bench v1: taxonomy + payload library + tooling injection. |
| M4 | Esperimenti adversariali (Fase 2). |
| M5 | Defenses (Fase 3) + analisi finale. |
| M6 | Writing + internal review + submission. |

## 10. Prossimi passi immediati

1. **Tu**: rispondi alle 7 decisioni aperte (D1–D7). Anche solo "default OK" va bene.
2. **Io**: appena hai confermato, scrivo `01-experimental-plan.md` (matrice fattoriale completa, calcoli di power, dataset list pinnato per commit/version).
3. **Io**: bootstrap del lab in `paper/lab/` con docker-compose, runner Shannon scriptato, schema telemetria JSONL.
4. **Insieme**: 3 run pilota end-to-end per validare la pipeline prima di scalare.

---

*Doc da considerare living. Aggiorna direttamente o annota in commit message.*
