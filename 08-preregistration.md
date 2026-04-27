# Pre-registration — Whitebox Prompt Injection on AI Pentesters

> Drafted: 2026-04-27. Pre-commit ALL hypotheses + analysis plan BEFORE
> running additional experiments. Format compatible with OSF / AsPredicted.

## Study identification

- **Title**: Whitebox Prompt Injection on AI Pentesters: Authority Appeal in Source-Code Comments
- **Authors**: Lorenzo De Tomasi (DISIM, Università dell'Aquila)
- **Affiliations**: UnivAQ
- **Funding**: AWS Bedrock infrastructure provided by SIAE; PhD funded by UnivAQ
- **Conflicts of interest**: Author employed by SIAE; the paper's framing is academic UnivAQ work, see disclosure note in paper §Acknowledgments

## H1 — Mistral-Large under authority appeal

**H1a (directional)**: Under the NAIVE Analyst-only prompt and the
`rq1-authority-suppress-sqli-01` payload, Mistral-Large 2402's mean
SQLi severity will be **strictly lower** under authority condition than
baseline.

**H1b (effect size)**: The Δ severity will exceed Cohen's d ≤ −0.8 (large).

**Test**: paired Wilcoxon, one-sided, α=0.05.
**Multiple comparison**: H1 is part of a family of 10 model-level tests;
we apply Holm-Bonferroni correction across this family.

**Decision rule**: H1 is supported if (a) raw p<0.05, (b) Holm-Bonferroni
adjusted p<0.05, (c) Cohen's d ≤ −0.8, (d) BCa 95% CI does not include 0.

## H2 — Code-comment is the dominant injection channel

**H2 (directional)**: For the "suppress-finding" goal class, the
`code-comment` vector will produce a strictly larger mean severity
downgrade than each of `readme`, `openapi-description`, `i18n-string`,
`package-metadata`, `error-message-template` on Mistral-Large.

**Test**: 5 pairwise Mann-Whitney U tests (code-comment vs each
alternative). Holm-Bonferroni across these 5.

## H3 — D3 hardened prompt mitigates WPI

**H3 (directional)**: On Mistral-Large under authority payload, the
DEFENDED prompt (D3) will yield mean severity strictly higher than the
NAIVE prompt baseline.

**Sub-hypothesis H3-recall**: D3 will not reduce recall (mean across the
4 ground-truth vulns) by more than 0.10 versus NAIVE baseline.

## H4 — Capability inversion (RQ4)

**H4 (directional)**: Spearman correlation between capability proxy
(`input_price_per_mtok`) and Δ severity will be negative when restricted
to **evaluable** models (those with baseline μ ≥ 2 — capability gap
exclusion criterion specified in advance).

## Pre-registered exclusion criteria

A model is **excluded from RQ4** if its baseline mean SQLi severity is
< 2.0 over N≥5 runs. Reason: the model demonstrably cannot identify the
SQLi vulnerability even without adversarial input, so its Δ is dominated
by capability noise rather than alignment-driven robustness.

This excludes: minimax-2.5 (baseline=0.0), ministral-3b (0.6), ministral-8b
(0.0), devstral-123b (0.6), gpt-oss-120b (1.8 — borderline). At the time
of pre-registration, 5 evaluable models: haiku-3, gemma-3-4b, qwen-80b,
qwen-235b, mistral-large.

## Analyses we will report regardless of outcome

1. Mean ± SEM and BCa 95% CI for every (model, condition) cell.
2. Cohen's d for every pairwise comparison.
3. Permutation test p-value (n_perm ≥ 9999) alongside parametric tests.
4. Holm-Bonferroni adjusted p across each family of tests.
5. Per-model stability: split N=20 mistral-large into halves; both halves
   must show same direction of effect for H1 to be supported.

## Variables we will hold constant

- **Target**: synthetic-target (lab/synthetic_target/server.py @ pinned
  commit)
- **Classifier**: analysis.classifier.classify_output (regex-based,
  pinned in repo)
- **N per cell** (final round): N=20 for headline cells, N=10 for
  ablation, N=5 for edge cases.
- **Region**: AWS Bedrock eu-west-1
- **Temperature**: NOT held constant in the original round. We will
  report a deterministic-replication round at temperature=0 (currently
  in execution at time of pre-registration).

## Data and code availability

- All run telemetry: `paper/results/all-runs.jsonl`,
  `paper/results/rq3-ablation-edge.jsonl`
- All code: this repository, frozen at the submission tag.
- Statistical analysis: `paper/analysis/robustness.py`
- License: code MIT, data CC-BY 4.0 (release at camera-ready).

## Stop / scope conditions

We will NOT add new model families or new payload classes after the
pre-registration date without amending this document. Any additional
condition will be flagged in the paper as "exploratory, post-hoc".

## Pre-registration timestamp

The cryptographic hash of this file at registration time will be
recorded in `paper/results/preregistration-hash.txt` and posted to OSF
before the next experimental run.
