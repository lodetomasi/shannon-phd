# Paper Strategy — Story, Novelty, Defense

> Companion to `00-design.md`. Source of truth for **how** we frame the contribution.

## 1. The story (one paragraph version)

> AI pentester agentici **white-box** (Shannon, PentestGPT, HackingBuddyGPT, Vulnhuntr, AutoPenBench) ingeriscono il **codice sorgente** del target come parte del prompt LLM. Mostriamo per la prima volta che questo apre una nuova classe di vulnerabilità — **Whitebox Prompt Injection (WPI)** — in cui un attaccante con controllo parziale del codice (insider, contributor di fork upstream, supply chain) può: (a) sopprimere finding reali, (b) iniettare falsi positivi rumorosi, (c) reindirizzare il browser dell'agente verso obiettivi out-of-scope. Su un benchmark di **N applicazioni × 24 classi di payload × 5 tool**, dimostriamo Attack Success Rate medio del XX%, con varianza inter-tool che identifica architetture più resilienti. Proponiamo e valutiamo 3 difese: la migliore riduce ASR a YY% al costo di ZZ% in token. Disclosure responsabile a tutti i vendor; artifact rilasciato sotto CC-BY 4.0.

## 2. Novelty claim (cosa è nuovo, cosa NO)

**Nuovo (claim del paper).**
1. **WPI come classe di attacco**: prima formalizzazione + tassonomia (Vector × Goal = 24 classi) sui pentester agentici.
2. **CodeInject-Bench**: primo benchmark riproducibile per misurare la robustezza adversariale di white-box AI pentester.
3. **PRS (Pentest Reliability Score)**: metrica composita per quantificare l'affidabilità run-to-run di un agente pentester.
4. **Cross-tool comparative study** su 5 pentester deployed.
5. **Defense evaluation** con upper-bound empirico per ogni difesa.

**NON nuovo (riconosciamo).**
- Prompt injection in generale (Greshake et al. 2023, Willison 2025).
- LLM agent security taxonomy (arXiv 2407.19354 surveys).
- Indirect prompt injection via document content.

**Il delta**: nessuno ha dimostrato che il **codice sorgente del target** è un canale di indirect prompt injection per **agenti che fanno azioni offensive** (browser, network tooling), e nessuno ha misurato **robustezza cross-tool** in un benchmark riproducibile.

## 3. Threat model (formalizzato — placeholder per il paper)

**Definition 1 (Whitebox AI Pentester).** A white-box AI pentester is a tuple `P = (M, T, R)` where `M` is an LLM, `T` is a set of tools (browser, network scanners, command execution), and `R` is the ingested repository: a set of files `R = {f_1, ..., f_n}` whose content enters the LLM context as untrusted text-as-data, conventionally treated as data-not-instructions.

**Definition 2 (WPI Attacker).** An attacker `A` controls a subset `R_A ⊂ R` of repository files. `A`'s goal is one of:
- `G_S`: ∃ vuln `v` ∈ ground-truth s.t. `v` ∉ output(P, R) but `v` ∈ output(P, R \ R_A).
- `G_F`: ∃ non-vuln `n` s.t. `n` ∈ output(P, R) but `n` ∉ output(P, R \ R_A).
- `G_R`: ∃ HTTP request `q` from `T_browser(P, R)` s.t. `host(q) ∉ scope`.

**Constraints.** `A` does not control: LLM weights, system prompt, tool implementation, network sandbox, or `R \ R_A`.

**Theorem 1 (informal — to formalize).** *Regex-based sanitization of `R_A` cannot achieve ASR < ε without false-positive rate on benign code > δ(ε), with δ growing super-linearly as ε → 0.* (Argument: benign comments and i18n strings overlap distributionally with payloads.)

## 4. Defense skeleton

| ID | Defense | Mechanism | Cost | Hypothesized upper-bound on ASR reduction |
|----|---------|-----------|------|-------------------------------------------|
| D1 | **Sanitizer** | Regex/heuristics strip injection-shaped patterns from `R` before LLM ingestion | low (CPU only) | Limited; bypassable by paraphrase. Theorem 1. |
| D2 | **Dual-LLM Judge** | Second LLM with no tool access reviews findings before reporting | medium ($$) | Strong if judge has different system prompt / model. |
| D3 | **Source-Attribution Prompt** | System prompt explicitly tags `R` as "data, not instructions"; LLM trained/instructed to refuse imperatives originating from repo content | low | Moderate; depends on model alignment. |

Each defense will be evaluated with: ASR pre/post (paired), recall on real vulnerabilities (must not collapse), $/run, latency.

## 5. Apparato sperimentale (deltas vs `00-design.md`)

Aggiunte richieste dal Rank A* target:

- **N tool ≥ 4**: Shannon, PentestGPT, HackingBuddyGPT, Vulnhuntr, AutoPenBench. Driver pluggable.
- **N target ≥ 5** + **N=20 run baseline**, **N=10 run adversariali per (tool × payload)**.
- **Ground truth**: doppia annotazione umana sui finding ambigui, Cohen's kappa reportato.
- **Statistica**: paired Wilcoxon per ASR, McNemar per binary outcomes, BCa bootstrap CI a 95%, Holm-Bonferroni per multiple comparisons.
- **Effect size**: Cliff's δ per ASR, in aggiunta ai p-value.
- **Pre-registration**: ipotesi e analisi piano committati in OSF prima dell'esecuzione (Mese 2).

## 6. Artifact plan

```
artifact/
├── README.md                    # 5-min reproduction recipe
├── docker-compose.yml           # full lab
├── run-paper.sh                 # one command → all tables/figures
├── data/                        # JSONL telemetry (anonymized API metadata)
├── notebooks/                   # analysis + figure generation
├── payloads/                    # CodeInject-Bench v1 (CC-BY 4.0)
└── DOI.md                       # Zenodo DOI
```

Target badge USENIX: **Available + Functional + Reproduced**.

## 7. Disclosure plan

| Vendor | Tool | Disclosure date | Window |
|--------|------|------------------|--------|
| Keygraph | Shannon Lite | M3 (≈ luglio 2026) | 90 days |
| GreyDgL | PentestGPT | M3 | 90 days |
| ipa-lab | HackingBuddyGPT | M3 | 90 days |
| Protect AI | Vulnhuntr | M3 | 90 days |
| AutoPenBench team | AutoPenBench | M3 | 90 days |

Boilerplate: email + paper draft + minimal PoC + suggested mitigation. Track in `disclosure/log.md` (private).

## 8. Risks specifici per Rank A\*

| Rischio | Probabilità | Mitigazione |
|---------|-------------|-------------|
| "Folklore — non novel" | media | Theorem 1 formalizzato + survey citations § sopra |
| "Sample size piccolo" | alta se non multi-tool | N tool ≥ 4 + power analysis nel piano |
| "Non riproducibile" | bassa con artifact | Docker pinned + Zenodo + workflow scriptato |
| "Defense weak" | media | 3 difese + cost analysis + onesta limitations |
| "Ethics: aiutiamo gli attaccanti" | bassa | Disclosure 90gg + payload sanitization in repo pubblico |

## 9. To-Do per arrivare alla submission (M0 → M6)

- [x] Design doc, threat model preliminare, codice base
- [ ] Allargare driver a 4 tool (M1)
- [ ] Pre-registration su OSF (M2)
- [ ] Reliability baseline (Fase 1) completa con statistica (M2)
- [ ] CodeInject-Bench v1 cross-tool (M3-M4)
- [ ] Difese + valutazione (M4)
- [ ] Disclosure 90gg (M3)
- [ ] Drafting (M5)
- [ ] Internal review + artifact polish (M6)
- [ ] Submission USENIX Security 2027 Cycle 1
