"""Aggregate the ablation + edge-case JSONL into a results table."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats as scistats


def load_jsonl(p: Path) -> list[dict]:
    out = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def main() -> None:
    paper = Path(__file__).resolve().parents[1]
    abl = load_jsonl(paper / "results" / "rq3-ablation-edge.jsonl")
    # Pull the original Mistral N=20 authority from the merged dataset for A0 reference
    merged = load_jsonl(paper / "results" / "all-runs.jsonl")
    a0_auth = [r for r in merged
               if r.get("label") == "mistral-large"
               and r.get("condition") == "authority"]
    a0_base = [r for r in merged
               if r.get("label") == "mistral-large"
               and r.get("condition") == "baseline"]

    cells: dict[str, list[dict]] = defaultdict(list)
    for r in abl:
        cells[r["cell"]].append(r)

    def _sev(records, key="sqli_severity"):
        return [r["classification"][key] for r in records]

    print("=" * 86)
    print("RQ3 DEFENSE ABLATION  (all on Mistral Large, payload="
          "rq1-authority-suppress-sqli-01)")
    print("=" * 86)
    print(f"  {'cell':22s}  {'n':>3s}  {'sqli_μ':>6s}  {'auth_μ':>6s}  "
          f"{'idor_μ':>6s}  {'xss_μ':>6s}  {'$/run':>7s}")

    def row(name, runs):
        if not runs:
            return None
        sqli = _sev(runs, "sqli_severity")
        auth = _sev(runs, "auth_severity")
        idor = _sev(runs, "idor_severity")
        xss = _sev(runs, "xss_severity")
        cost = sum(r["usd_spent"] for r in runs) / len(runs)
        print(f"  {name:22s}  {len(runs):>3d}  {np.mean(sqli):>6.2f}  "
              f"{np.mean(auth):>6.2f}  {np.mean(idor):>6.2f}  "
              f"{np.mean(xss):>6.2f}  ${cost:>6.4f}")
        return {"name": name, "n": len(runs),
                "mean_sqli": float(np.mean(sqli)),
                "mean_auth": float(np.mean(auth)),
                "mean_idor": float(np.mean(idor)),
                "mean_xss": float(np.mean(xss)),
                "mean_cost_usd": cost,
                "sqli_values": sqli}

    rows = []
    rows.append(row("A0-NAIVE-baseline (ref)", a0_base))
    rows.append(row("A0-NAIVE-authority (ref)", a0_auth))
    rows.append(row("A1-D1-only", cells.get("A1-D1-only", [])))
    rows.append(row("A2-D3-only", cells.get("A2-D3-only", [])))
    rows.append(row("A3-D1+D3", cells.get("A3-D1+D3", [])))

    print()
    print("=" * 86)
    print("EDGE CASES  (all on Mistral Large NAIVE prompt)")
    print("=" * 86)
    print(f"  {'cell':22s}  {'n':>3s}  {'sqli_μ':>6s}  {'auth_μ':>6s}  "
          f"{'idor_μ':>6s}  {'xss_μ':>6s}  {'$/run':>7s}")
    for tag in ["EC1-position-bottom", "EC2-short", "EC3-multi-payload",
                "EC4-paraphrase", "EC4-paraphrase+D1", "EC5-benign-audit"]:
        rows.append(row(tag, cells.get(tag, [])))

    print()
    print("=" * 86)
    print("DEFENSE EFFECT SIZE  vs A0-NAIVE-authority")
    print("=" * 86)

    auth_baseline_sev = [r["classification"]["sqli_severity"] for r in a0_auth]
    print(f"  {'comparison':30s}  {'Δ_sqli':>7s}  {'p (Mann-Whit)':>13s}")
    for tag in ["A1-D1-only", "A2-D3-only", "A3-D1+D3"]:
        treat = [r["classification"]["sqli_severity"] for r in cells.get(tag, [])]
        if not (auth_baseline_sev and treat):
            continue
        d = np.mean(treat) - np.mean(auth_baseline_sev)
        try:
            stat, p = scistats.mannwhitneyu(treat, auth_baseline_sev,
                                             alternative="two-sided")
        except ValueError:
            p = float("nan")
        print(f"  {tag:30s}  {d:>+7.2f}  {p:>13.4f}")

    print()
    print("=" * 86)
    print("EDGE CASE EFFECT  vs A0-NAIVE-authority (positive Δ = more degradation)")
    print("=" * 86)
    print(f"  {'cell':30s}  {'Δ_sqli vs auth':>14s}")
    for tag in ["EC1-position-bottom", "EC2-short", "EC3-multi-payload",
                "EC4-paraphrase", "EC4-paraphrase+D1", "EC5-benign-audit"]:
        treat = [r["classification"]["sqli_severity"] for r in cells.get(tag, [])]
        if not (auth_baseline_sev and treat):
            continue
        d = np.mean(treat) - np.mean(auth_baseline_sev)
        sign = "↓ more vulnerable" if d < 0 else "↑ less vulnerable" if d > 0 else "≈"
        print(f"  {tag:30s}  {d:>+14.2f}  {sign}")

    out_path = paper / "results" / "rq3-ablation-summary.json"
    out_path.write_text(json.dumps(rows, indent=2, default=str))
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
