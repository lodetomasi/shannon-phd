# Target Venue Strategy

> Goal: massimizzare probabilità di accettazione a una conferenza **CORE Rank A o A\***.
> Working assumption: paper sub-mittibile entro **6 mesi** dal kickoff (2026-04-27).

## Tier 1 — primary targets (A\*)

| Venue | Tier | Cycle / Deadline (storico) | Fit per il paper | Note tattiche |
|-------|------|----------------------------|-------------------|----------------|
| **USENIX Security** | A\* | Rolling: cicli summer/fall/winter; deadline ~giugno (Cycle 1), ~ottobre (Cycle 2) | **Massimo**: empirical security, agentic AI, large-scale study | Cycle 1 2027 (≈ giugno 2026) è il target realistico se freezo lo scope a M2. Reviewers premiano: dataset rilasciato, disclosure, artifact badge. |
| **IEEE S&P (Oakland)** | A\* | Deadline ~giugno (Round 2), ~dicembre (Round 1) | **Alto**: novel attack class + defense formale | Più sensibile a teoria/formalismo. Serve almeno un theorem o impossibility result. |
| **NDSS** | A\* | Summer cycle ~aprile/luglio | **Alto**: applicazioni reali, network/system threats | Apprezza disclosure responsabile + impatto su tool deployed. |
| **ACM CCS** | A\* | Cycle 1 ~gennaio, Cycle 2 ~maggio | Buono | Più "system security" — il nostro paper è un buon fit second choice. |

**Decisione operativa (default).** Target primario: **USENIX Security 2027 Cycle 1**. Se la submission richiede più tempo, rebound su **NDSS 2027** (deadline lug-2026) o **CCS 2027 Cycle 2** (mag-2027).

## Tier 2 — fallback (A)

| Venue | Note |
|-------|------|
| **RAID** | Empirical evaluation friendly; deadline mag-giu 2026. |
| **ESORICS** | Solid Rank A europeo; deadline apr-2026 (probabilmente già out of window); 2027 a giu. |
| **DSN** | Fit moderato; più resilience-oriented. |
| **ACSAC** | Industrial track ottimo per la sezione "deployment study". |

## Tier 3 — preview / co-located workshop

Strategia: pre-pubblicare **solo i risultati preliminari** a un workshop affiliato per:
- Raccogliere feedback prima della submission Tier 1.
- Costruire visibility nella community.
- **NB**: alcune conferenze (es. USENIX) richiedono che workshop preview NON sia un "prior publication". Workshops senza atti formali (extended abstract, poster) sono safe.

| Workshop | Co-located | Quando | Modalità safe |
|----------|------------|--------|----------------|
| **WOOT** (Workshop on Offensive Tech) | USENIX Security | Aug 2026 | 6-page short paper, atti — **rischio prior publication** se il main paper va a USENIX. Skip. |
| **AISec** | ACM CCS | Oct 2026 | OK come preview se main va a USENIX/NDSS |
| **DLS @ S&P** | IEEE S&P | May 2026 | Deep Learning Security workshop |
| **SOUPS poster** | USENIX | Aug 2026 | Poster non conta come pubblicazione |

## Cosa premiano i reviewer A\* su un paper come il nostro

Lista da PC bias osservato negli ultimi 3-5 anni (USENIX/Oakland/NDSS):

1. **Novel threat that wasn't on the radar** > evaluation of known issue.
2. **Multi-system breadth** (≥ 3 tool studiati) > singolo case study.
3. **Disclosure timeline + CVE** se possibile.
4. **Formalismo**: definizione formale, threat model in notazione, almeno un argomento di sufficiency/necessity.
5. **Artifact** con badge "Available + Functional + Reproduced".
6. **Statistical rigor**: paired tests, multiple comparisons correction, effect sizes — non solo medie.
7. **Open dataset** rilasciato sotto licenza permissiva (CC-BY 4.0 o MIT).
8. **Honest limitations**: una sezione che dichiara cosa NON dimostriamo.
9. **Defense** valutata, non solo attacco. Ideale: defense con guarantee + cost.
10. **Storytelling**: hook nelle prime 2 pagine, esempio concreto, "if you remember one thing..."

## Implicazioni sul nostro piano

- Scope: passa da "case study Shannon" → **systematic study di N≥4 pentester agentici** (vedi `00-design.md` aggiornato).
- Theorem placeholder: "Whitebox Prompt Injection è non-detectable senza un secondo trust boundary" — proveremo upper-bound dell'efficacia di sanitization regex-based.
- Disclosure: pre-paper notification a Keygraph + altri vendor entro M3.
- Pre-registrazione delle ipotesi a M2 (timestamp pubblico via OSF o Zenodo).
- Artifact: Docker `--reproduce-paper` flag + Zenodo DOI prima del submission.
