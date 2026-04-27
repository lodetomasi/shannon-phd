# Lab Isolation — How the Sandbox Actually Works

> Reviewer concern: "you're running an autonomous AI pentester on real
> code — what stops it from doing damage?". This doc is the answer.

## Trust boundaries (from least to most trusted)

```
┌─────────────────────────────────────────────────────────────────────┐
│ Public internet                                                     │
│   ↑ ONLY via egress-proxy, allowlist: api.anthropic.com,            │
│     api.openai.com, generativelanguage.googleapis.com, openrouter.ai│
└─────────────────────────────────────────────────────────────────────┘
                                ↑
        (egress-net — proxy only ↑)
                                ↑
   ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
   │   egress-proxy   │    │      auriga     │◀──▶│  egress-trap    │
   │   squid+allowlist│◀──▶│  (ai pentester) │    │ DNS+HTTP sink   │
   │                  │    │                 │    │ logs everything │
   └──────────────────┘    └────────┬────────┘    └─────────────────┘
   on agent-net                     │             on lab-net
                                    │             (catchall via *)
                            (lab-net—internal:true)
                                    │
                            ┌───────▼─────────┐
                            │   juice-shop    │
                            │  (target app)   │
                            └─────────────────┘
                            on lab-net only
```

## Five layers of containment

| Layer | What it stops | Where in code |
|-------|---------------|---------------|
| **L1 — Network** | Target reaches public internet | `lab-net: internal: true` in compose |
| **L2 — Egress trap** | Off-target requests on lab-net are captured (audit) | `lab/egress_trap/server.py` (DNS + HTTP catchall) |
| **L3 — Egress allowlist** | Auriga reaches anything except whitelisted LLM APIs | `lab/egress_proxy/squid.conf` (HTTPS CONNECT only, dstdomain allowlist) |
| **L4 — In-scope check** | Auriga's own HTTP tool refuses off-target hosts before transport | `agent/tools/http_client.py` (`OUT_OF_SCOPE` early return) |
| **L5 — Filesystem sandbox** | Auriga reads outside the target repo | `agent/tools/repo_reader.py` (traversal/symlink/binary refused) |

The reviewer asks "what if L4 fails?" → L3 + L2 catch it. "What if L3 fails?" → L1 isolates the target. Defense in depth.

## Container hardening (compose-level)

Every service:
- `cap_drop: [ALL]` — no privileged operations
- `security_opt: [no-new-privileges:true]` — escalation paths disabled
- `read_only: true` — rootfs immutable
- `tmpfs: [/tmp, …]` — writable scratch only where needed
- `deploy.resources.limits.{cpus, memory}` — runaway protection
- runs as non-root user (Auriga = uid 1100, trap = uid 1001)

## What's NOT in the sandbox (and why)

- **Anthropic API egress**: required for the LLM. Locked down to a single
  CONNECT destination via squid. Reviewer-acceptable: this is the cloud-LLM
  trade-off and we make the constraint explicit.
- **Image pulls on first `compose up`**: the lab needs to download Juice Shop
  + ubuntu/squid + python:3.12-slim once. Once cached, everything works
  with `internal: true` in steady state.
- **Anthropic API itself**: it's a third party. We don't control them. We
  log every call locally in `egress_proxy_logs/access.log` for audit.

## How to verify the sandbox works (reviewer-grade evidence)

`lab/integration/test_isolation.py` runs 7 invariants against the live lab:

1. Target → `example.com` times out (L1).
2. Auriga → arbitrary public host returns 403 (L3 squid denial).
3. Auriga → `juice-shop:3000` returns 2xx (in-scope works).
4. Auriga → `api.anthropic.com` succeeds via proxy (L3 allowlist).
5. Auriga → off-target on lab-net is logged in `egress_trap_logs/events.jsonl` (L2 audit).
6. Target rootfs is immutable (`touch /` blocked).
7. Auriga runs as non-root (`id -u != 0`).

Run with:

```bash
docker compose -f lab/docker-compose.yml up -d
RUN_DOCKER_TESTS=1 .venv/bin/pytest lab/integration
docker compose -f lab/docker-compose.yml down -v
```

These integration tests are skipped in normal CI (no Docker), and run
explicitly before each experimental freeze. Their output goes into the
artifact bundle as evidence for the AE committee.
