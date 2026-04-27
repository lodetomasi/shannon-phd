# Auriga container — runs the Planner end-to-end inside the lab sandbox.
#
# Two networks at runtime (compose):
#   - lab-net:   internal=true, joined with the target. Auriga reaches the
#                target here. No public egress.
#   - agent-net: non-internal. Auriga reaches the egress-proxy here. The
#                proxy is the ONLY route to the public internet, and it
#                filters by allowlist (api.anthropic.com:443 etc.).
#
# Everything in this image is best-effort minimal: no shell, no extra tools,
# no network utilities. The image bundles the paper code so reviewers can
# rebuild it from this Dockerfile + the repo at the pinned tag.

FROM python:3.12-slim AS base

# Non-root from the start.
RUN useradd -r -u 1100 -m auriga && \
    mkdir -p /work /results && chown -R auriga /work /results

WORKDIR /work
COPY pyproject.toml ./
COPY conftest.py ./
COPY agent ./agent
COPY analysis ./analysis
COPY data ./data
COPY experiments ./experiments
COPY lab ./lab
COPY models ./models
COPY payloads ./payloads

RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir anthropic httpx httpx-socks

USER auriga

# Default: run a single experiment. Compose overrides as needed.
ENTRYPOINT ["python", "-m", "experiments.run_experiment"]
