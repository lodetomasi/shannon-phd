# RQ Results Summary (auto-generated)

## RQ1 — Paired Wilcoxon baseline vs authority (per model)

| Model | N | μ baseline | μ authority | Δ | W | p | sig |
|-------|---|-----------|-------------|----|---|---|-----|
| mistral-large | 20 | 3.00 | 2.25 | -0.75 | 0.0 | 0.0001 | *** |
| qwen-235b | 10 | 2.80 | 2.10 | -0.70 | 2.5 | 0.1573 | ns |
| devstral-123b | 5 | 0.60 | 0.00 | -0.60 | 0.0 | 0.3173 | ns |
| ministral-3b | 10 | 0.60 | 0.10 | -0.50 | 1.0 | 0.2763 | ns |
| gemma-3-4b | 10 | 3.00 | 3.00 | +0.00 | 0.0 | 1.0000 | ns |
| haiku-3 | 10 | 3.00 | 3.00 | +0.00 | 0.0 | 1.0000 | ns |
| ministral-8b | 10 | 0.00 | 0.00 | +0.00 | 0.0 | 1.0000 | ns |
| qwen-80b | 10 | 3.00 | 3.00 | +0.00 | 0.0 | 1.0000 | ns |
| gpt-oss-120b | 5 | 1.80 | 2.40 | +0.60 | 2.0 | 0.5637 | ns |
| minimax-2.5 | 5 | 0.00 | 1.80 | +1.80 | 0.0 | 0.0833 | ns |

## RQ2 — Channel comparison on Mistral-Large

Baseline mean SQLi severity: **3.00**

| Vector | N | μ severity | Δ vs baseline |
|--------|---|-----------|----------------|
| code-comment | 20 | 2.25 | -0.75 |
| readme | 5 | 3.00 | +0.00 |
| openapi | 5 | 3.00 | +0.00 |
| i18n | 5 | 3.00 | +0.00 |
| errortpl | 5 | 3.00 | +0.00 |

## RQ4 — Capability proxy vs severity Δ (Spearman)

Spearman ρ = **-0.474**, p = **0.167**, N = 10 models

| Model | Capability ($/MTok in) | Δ severity |
|-------|-----------------------|------------|
| gemma-3-4b | 0.05 | +0.00 |
| ministral-3b | 0.05 | -0.50 |
| ministral-8b | 0.10 | +0.00 |
| haiku-3 | 0.25 | +0.00 |
| gpt-oss-120b | 0.50 | +0.60 |
| minimax-2.5 | 1.00 | +1.80 |
| qwen-80b | 1.50 | +0.00 |
| qwen-235b | 2.00 | -0.70 |
| devstral-123b | 2.50 | -0.60 |
| mistral-large | 4.00 | -0.75 |
