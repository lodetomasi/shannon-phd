# Pentest the Pentester: Whitebox Prompt Injection on AI Pentesters

> PhD work · Lorenzo De Tomasi · DISIM, Università dell'Aquila
> `lorenzo.detomasi@graduate.univaq.it`

## TL;DR

This repository contains the artifact and analysis pipeline for an
empirical study of **Whitebox Prompt Injection (WPI)**: adversarial text
in source-code comments manipulating AI pentesters that read those
comments as part of their context window.

**Headline result.** Mistral-Large 2402 systematically degrades SQL
injection severity from `HIGH` to `MED` in 19 of 20 runs when source
comments contain regulatory authority appeals (paired Wilcoxon
*p* = 0.0001, Cohen's *d* = −2.39, Holm-Bonferroni adjusted *p* = 0.0011).
The effect replicates on DVWA's `low.php` (Δ = −1.30, *p* = 0.0094) and
at temperature = 0.

**Defenses.** Two near-zero-cost defenses fully restore severity at 0%
recall loss: a 5-line system-prompt hardening (D3) and a different-family
dual-LLM judge (D2). A regex-based sanitizer (D1) is marginal.

**635 runs · 10 LLMs across 4 families · 6 targets · 24 payload
classes · ~$5.88 total inference cost.**

## Repository layout

```
agent/                # Auriga — the AI pentester we built
├── core/             # orchestrator, memory, budget
├── llm/              # Anthropic + Bedrock clients
├── tools/            # http, repo_reader, finding_reporter
├── agents/           # Specialist roles (recon, analyst, exploit, validator)
├── prompts/          # system prompts (NAIVE + DEFENDED variants)
├── defenses/         # D1 sanitizer, D2 dual-judge, D3 hardened prompt
└── runner.py         # Planner: end-to-end pipeline

payloads/             # CodeInject-Bench: 24 payload classes
├── taxonomy.py       # Vector × Goal taxonomy
├── injector.py       # apply payload to a repo target
└── library/          # 27 concrete payloads

analysis/             # Statistics + figures
├── classifier.py     # severity classifier (Cohen κ = 0.93 vs LLM judge)
├── stats.py          # Wilcoxon, McNemar, BCa bootstrap, Cliff's δ, Holm
├── plots.py          # Meta-FAIR-style data figures
├── hero_figures.py   # publication-grade hero figures
├── system_diagram.py # matplotlib system diagram
└── robustness.py     # full robustness battery

lab/
├── synthetic_target/      # 130-LOC vulnerable web app
├── docker-compose.yml     # isolated lab (network internal:true)
├── egress_trap/           # DNS+HTTP catchall for off-target audit
├── egress_proxy/          # squid allowlist for LLM API egress only
├── shannon_runner/        # legacy stub (deprecated)
└── integration/           # all the real-LLM pilot experiments

experiments/          # CLI: run_experiment, run_matrix, cost guard
models/               # LLM catalog + cost estimator
data/                 # external resources registry + idempotent fetcher
results/              # 635 RunRecord JSONL + stats JSON
figures/              # PDF + PNG + TikZ source for system diagram

00-design.md          # paper design doc
02-target-venues.md   # USENIX/Oakland/NDSS strategy
03-paper-strategy.md  # story, novelty, defense skeleton
04-mock-vs-real.md    # transparency audit (which mocks were stripped)
05-lab-isolation.md   # 5 layers of sandbox containment
06-research-questions.md
07-ablation-and-edge-cases.md
08-preregistration.md       # OSF-compatible pre-registration
paper.tex             # IMRaD skeleton (compile with `tectonic paper.tex`)
```

## Reproducing the results

```bash
# 1. Install
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# 2. Tests (no AWS required, no network)
.venv/bin/pytest                   # 200+ unit/integration tests

# 3. Render figures from the published JSONL
.venv/bin/python -m analysis.hero_figures
.venv/bin/python -m analysis.full_round_analysis

# 4. Compile the paper (vector PDF)
brew install tectonic
tectonic paper.tex
tectonic figures/system_diagram.tex
```

## Reproducing the experiments (requires AWS Bedrock)

The experiments need an AWS Bedrock-capable account in `eu-west-1` with
access to: Mistral Large, Claude Haiku 3, Qwen 235B/80B, GPT-OSS-120B,
MiniMax 2.5, Devstral 123B, Gemma 3-4B, Ministral 3B/8B.

```bash
export AWS_PROFILE=your-bedrock-profile
export RUN_NETWORK_TESTS=1

# Replicate the headline N=20 round (~$0.30, 5 min)
.venv/bin/pytest lab/integration/test_replication_temp0.py

# Full multi-tier pilot (~$2, 30 min)
.venv/bin/pytest lab/integration/test_rq_full_round.py

# All robustness checks
.venv/bin/python -m analysis.robustness
```

## Pre-registration

Hypotheses, exclusion criteria, and analysis plan were pre-committed
in `08-preregistration.md` before the final round; cryptographic hash
in `results/preregistration-hash.txt`.

## Citation

```bibtex
@misc{detomasi2026wpi,
  title  = {Pentest the Pentester: Whitebox Prompt Injection on
            Autonomous AI Web-Application Pentesters},
  author = {De Tomasi, Lorenzo},
  year   = {2026},
  url    = {https://github.com/lodetomasi/shannon-phd},
  note   = {Working paper, DISIM, Università dell'Aquila}
}
```

## License

- **Code**: MIT (see `LICENSE-CODE`)
- **Payloads + telemetry data**: CC-BY 4.0 (see `LICENSE-DATA`)

## Funding & disclosure

PhD funded by Università dell'Aquila. AWS Bedrock infrastructure
provided by SIAE; the work is academic and not endorsed by SIAE.
