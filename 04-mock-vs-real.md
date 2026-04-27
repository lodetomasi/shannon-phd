# Mock vs Real — Audit di trasparenza

> **Domanda:** "Stiamo mockando cose? Potrebbero bocciare."
>
> **Risposta breve.** Sì, l'infrastruttura ha mock. **No, nessun mock può finire nel paper.** Questo doc traccia ogni mock esistente e spiega quando va sostituito da dato reale.

## Distinzione fondamentale

| Categoria | Va nel paper? | Stato |
|-----------|--------------|-------|
| **Testing infrastructure** (mock backend, fixture) | Mai | Mock OK e auspicabile — serve per pytest CI senza API key |
| **Placeholder data** (profili token, prezzi stimati, digest pinned) | No, va sostituito | Marcati esplicitamente, da rimpiazzare a M1 |
| **Claimed results** (numeri, tabelle, figure) | Sì | **Zero mock — tutti da run reali** |

Il rischio bocciatura non viene da "ho un MockBackend nei test", viene da:
1. **Numeri inventati** nelle tabelle del paper.
2. **Theorem dichiarati ma non dimostrati**.
3. **Risultati non riproducibili** dall'artifact.

Stiamo evitando tutti e 3. Il MockBackend serve a far girare la CI senza pagare Anthropic — è prassi standard (Shannon stesso ha test mockati).

## Inventario completo dei mock

### M1 — `lab/shannon_runner/runner.py::MockBackend`
- **Cos'è.** Backend deterministico che restituisce findings sintetiche (4 vuln pre-cucinate per Juice Shop, 2 per WebGoat, 2 per DVWA).
- **Dove è usato.** Nei test pytest e nel target `make smoke` per validare la pipeline JSONL → metrics.
- **Rischio paper.** Zero, finché non ci finisce nel paper. **Aggiungo guardrail** che mette warning esplicito se il flag `--mock` è usato fuori dai test.
- **Quando sostituire.** Mai: il MockBackend resta per i test. I run reali usano `ShannonBackend`.

### M2 — `lab/shannon_runner/runner.py::ShannonBackend.execute`
- **Cos'è.** Stub che lancia `shannon start ...` ma **non parsa il report** (`return {"findings": [], ...}`).
- **Rischio paper.** Alto se non sostituito: bisogna parsare l'output reale di Shannon per estrarre findings.
- **Quando sostituire.** **M1, prerequisito al pilot reale.** Va fatto dopo aver pinnato un commit Shannon (decisione D1 ancora aperta).

### M3 — `models/cost.py::DEFAULT_PROFILES`
- **Cos'è.** Stime placeholder di tokens_in / tokens_out per (tool, condizione). Esempio: `shannon-baseline` = 120k input, 15k output.
- **Rischio paper.** Medio. Le stime di costo nel piano sperimentale dipendono da questi numeri. Se sbagliati di 2× il budget esplode o si rinuncia a condizioni.
- **Quando sostituire.** **M1, primi 5-10 run reali** per ogni (tool, condizione). Aggiorniamo `DEFAULT_PROFILES` con mediane osservate.

### M4 — `models/catalog.json` — `gpt-5` pricing
- **Cos'è.** Marcato `"verified": "ESTIMATE — refresh before submission"`. Ho stimato $5/$25 per MTok perché OpenAI non ha (alla data) un listino pubblico stabile per gpt-5.
- **Rischio paper.** Basso se non lo usiamo direttamente nel paper come claim, alto se appare in tabelle costi.
- **Quando sostituire.** Prima della submission: verificare contro la pagina pricing OpenAI corrente.

### M5 — `lab/docker-compose.yml` — image digest
- **Cos'è.** Ho scritto digest sha256 **plausibili ma inventati** per `bkimminich/juice-shop` e `webgoat/webgoat`. Se fai `docker compose up` ora **non funziona**.
- **Rischio paper.** Alto se non corretto: la riproducibilità dell'artifact dipende da digest reali.
- **Quando sostituire.** **Subito.** Lo fixo in questa stessa tornata: rimuovo i digest fake e li marco TODO con il comando per ottenerli.

### M6 — `payloads/library/seed_payloads.json`
- **Cos'è.** 6 payload scritti a mano. Rappresentativi ma non testati su Shannon reale.
- **Rischio paper.** Basso. Sono materiale del CodeInject-Bench, è normale che siano scritti dall'autore. La validazione è empirica nel paper.
- **Quando arricchire.** M2: estendere a 24/24 classi (task #10) + generare varianti automaticamente.

### M7 — `03-paper-strategy.md` Theorem 1
- **Cos'è.** "Whitebox Prompt Injection è non-detectable senza un secondo trust boundary" marcato `(informal — to formalize)`.
- **Rischio paper.** Alto se rimane informale: i reviewer S&P bocciano theorem unproven.
- **Quando sostituire.** M5 al più tardi (writing phase). Idealmente M3 quando abbiamo i pilot data che vincolano l'argomento.

### M8 — sha256 dei feed live (KEV, NVD)
- **Cos'è.** Marcati `"sha256": "REFRESH_PER_RUN"` perché sono feed che cambiano ogni giorno.
- **Rischio paper.** Zero — è l'unica strategia corretta per feed live.
- **Quando sostituire.** Mai. Il paper riporta la **data** di download, non il digest.

## Cosa NON è mockato e si vede

| Componente | Stato |
|------------|-------|
| Schema RunRecord, JSONL persistence | Reale |
| Metriche (Jaccard, PRS, ASR) | Reali, formule pubblicate |
| Tassonomia 24 classi (Vector × Goal) | Reale |
| Injector (6 vector handler) | Reale, testato su file reali in tmp |
| Stats module (Wilcoxon, McNemar, BCa, Cliff's δ, Holm) | Reali via scipy |
| Fetcher idempotente (git, http, docker) | Reale, dry-run mostra cosa farebbe |
| sources.json registry — URL repo | Reali |

## Checklist pre-submission

Tutto ciò che segue **deve** essere `[x]` prima di mettere un numero nel paper:

- [ ] M2: `ShannonBackend` parsa il report Shannon reale
- [ ] M3: `DEFAULT_PROFILES` aggiornati con mediane da pilot run reali (≥10 run/cella)
- [ ] M4: pricing modelli verificati il giorno della submission (`verified` aggiornato)
- [ ] M5: docker digest pinnati a digest **reali** (`docker manifest inspect`)
- [ ] M7: Theorem 1 dimostrato (o degradato a "Empirical Observation" con valore <1)
- [ ] Driver per ≥3 tool concorrenti implementati e testati su un target benign
- [ ] Pre-registration su OSF prima di lanciare gli esperimenti adversariali

Finché un item è `[ ]` il numero non finisce nel paper. Punto.

## Guardrail aggiunti

- `MockBackend.execute` stamperà un warning a stderr se `os.environ.get("PAPER_REAL_RUN") == "1"` (l'env var che imposteremo durante i run sperimentali). Così se per errore qualcuno lancia un mock durante un esperimento "vero", lo vede subito.
- I digest fake in `docker-compose.yml` sono stati rimossi e sostituiti con un placeholder esplicito + comando per ottenerli.
