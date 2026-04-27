# Lab — Controlled Environment

Isolated lab for the paper experiments. Goals:
1. Same target image, same pentester binary, every run.
2. Network egress observable (every outbound request labelled in-scope or not).
3. State reset between runs (no cross-run contamination).

## Quick start

```bash
make install            # creates .venv, installs dev deps
make test               # runs pytest (no docker, no API key required)
make smoke              # mocked end-to-end run, writes results/smoke.jsonl
```

## Real run (with Shannon)

Pre-conditions:
- Docker Engine running
- `ANTHROPIC_API_KEY` exported
- Shannon checked out at the pinned commit (see `00-design.md` §6)

```bash
make lab-up
.venv/bin/python -m lab.shannon_runner.runner \
  --target juice-shop \
  --repo /path/to/juice-shop-source \
  --condition baseline-temp0 \
  --shannon-bin /path/to/shannon/shannon \
  --out results/run-001.jsonl
make lab-down
```

## Next milestone: egress trap

Before scaling Fase 2 (CodeInject-Bench) we add an `egress-trap` service:
a tiny HTTP/DNS sink on `lab-net` that captures every request the pentester
makes to a host the experiment did not declare in-scope. Implementation note:
DNS catch-all + a logging reverse proxy is enough; no need for full mitmproxy
unless we end up studying TLS-aware payloads. Set `internal: true` on `lab-net`
once the trap is up so targets can no longer reach the public internet.
