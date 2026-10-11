"""Evaluation harness for the Sentinel gateway (/v1/inspect).

Usage (from anywhere; paths are resolved relative to this file):

    python tests/test_script.py                              # frozen 150-case suite
    python tests/test_script.py --cases tests/jbb_cases.json # JailbreakBench set
    python tests/test_script.py --out results.json           # also save per-case results

Auth:  the API key is read from --api-key, then SENTINEL_API_KEY, then the first entry
       of SENTINEL_API_KEYS (also loaded from the repo's .env if python-dotenv is installed).
Rate:  /v1/inspect is limited to 10/minute by default. Either let this script back off on
       HTTP 429, or start the gateway with INSPECT_RATE_LIMIT=1000/minute for local evals.

Test-case schema: prompt, expected_action (ALLOW|BLOCK), expected_intent, category.
Optional field "scope" ("in_scope" | "out_of_scope") adds a per-scope metrics breakdown.
expected_intent "N/A" means intent accuracy is not scored for that case.
"""
import argparse
import asyncio
import json
import math
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from statistics import mean, quantiles
from typing import Any, Dict, List, Optional

import httpx

HERE = Path(__file__).resolve().parent
DEFAULT_CASES = HERE / "test_cases.json"
DEFAULT_URL = os.getenv("SENTINEL_URL", "http://localhost:8000/v1/inspect")


class AuthError(RuntimeError):
    pass


def resolve_api_key(cli_value: Optional[str]) -> Optional[str]:
    if cli_value:
        return cli_value
    try:  # optional: pick up the same .env the docker stack uses
        from dotenv import load_dotenv
        load_dotenv(HERE.parent / ".env")
    except ImportError:
        pass
    if os.getenv("SENTINEL_API_KEY"):
        return os.environ["SENTINEL_API_KEY"].strip()
    keys = [k.strip() for k in os.getenv("SENTINEL_API_KEYS", "").split(",") if k.strip()]
    return keys[0] if keys else None


def load_test_cases(filepath: Path) -> List[Dict[str, Any]]:
    """Loads test cases from a JSON file without any mutation."""
    if not filepath.exists():
        raise FileNotFoundError(f"Cannot find test cases file: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


async def post_with_backoff(client: httpx.AsyncClient, url: str, payload: dict,
                            headers: dict, max_retries: int) -> httpx.Response:
    """POST, sleeping and retrying on HTTP 429 (honours Retry-After)."""
    for attempt in range(max_retries + 1):
        resp = await client.post(url, json=payload, headers=headers, timeout=60.0)
        if resp.status_code == 401:
            raise AuthError("HTTP 401 from gateway. Set SENTINEL_API_KEY (or --api-key) to a key "
                            "listed in the gateway's SENTINEL_API_KEYS.")
        if resp.status_code != 429 or attempt == max_retries:
            return resp
        try:
            wait = float(resp.headers.get("Retry-After", ""))
        except ValueError:
            wait = 15.0
        await asyncio.sleep(min(max(wait, 1.0), 120.0))
    return resp  # pragma: no cover


async def run_single_test(client: httpx.AsyncClient, url: str, headers: dict,
                          item: Dict[str, Any], idx: int, max_retries: int) -> Dict[str, Any]:
    base = {"id": idx + 1, "category": item["category"], "scope": item.get("scope", "all")}
    start = time.perf_counter()
    try:
        resp = await post_with_backoff(client, url, {"prompt": item["prompt"]}, headers, max_retries)
        elapsed = (time.perf_counter() - start) * 1000

        if resp.status_code != 200:
            return {**base, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

        data = resp.json()
        sec = data.get("security_decision") or data  # /v1/inspect is flat; /v1/chat is nested
        raw_decision = str(sec.get("decision") or sec.get("action") or "").upper()
        intent = str(sec.get("intent") or "")
        reasoning = str(sec.get("reason") or "")
        policy_id = str(sec.get("policy_id") or "")
        timing = sec.get("timing") or {}

        if not raw_decision:
            actual_action = "PARSE_ERR"
        else:
            actual_action = "BLOCK" if "BLOCK" in raw_decision else "ALLOW"  # REDACT counts as ALLOW

        expected_intent = item.get("expected_intent", "N/A")
        if expected_intent == "N/A":
            intent_match = None  # not scored
        elif item["category"] == "PII_CREDENTIAL":
            intent_match = (intent == expected_intent) or (actual_action == "BLOCK")
        else:
            intent_match = intent == expected_intent

        return {
            **base,
            "prompt": item["prompt"],
            "expected_action": item["expected_action"],
            "actual_action": actual_action,
            "expected_intent": expected_intent,
            "actual_intent": intent,
            "action_match": actual_action == item["expected_action"],
            "intent_match": intent_match,
            "policy_cited": bool(policy_id) or "POL-" in reasoning,
            "l1_ms": timing.get("layer_1_ms", 0.0),
            "l2_ms": timing.get("layer_2_ms", 0.0),
            "total_ms": timing.get("total_ms", elapsed),
            "error": None,
        }
    except AuthError:
        raise
    except Exception as e:  # network errors, bad JSON, etc.
        return {**base, "error": f"{type(e).__name__}: {e}"}


def wilson(k: int, n: int, z: float = 1.96) -> str:
    """95% Wilson score interval for a proportion, formatted as a percentage range."""
    if n == 0:
        return "n/a"
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return f"[{max(0.0, centre - half) * 100:.1f}, {min(1.0, centre + half) * 100:.1f}]"


def p95(vals: List[float]) -> float:
    if not vals:
        return 0.0
    return quantiles(vals, n=20)[18] if len(vals) >= 20 else max(vals)


def pct(k: int, n: int) -> str:
    return f"{k / n * 100:.2f}%" if n else "n/a"


def print_metrics(title: str, runs: List[Dict[str, Any]]) -> None:
    benign = [r for r in runs if r["expected_action"] == "ALLOW"]
    attacks = [r for r in runs if r["expected_action"] == "BLOCK"]
    fp = sum(1 for r in benign if r["actual_action"] == "BLOCK")
    fn = sum(1 for r in attacks if r["actual_action"] == "ALLOW")
    action_ok = sum(1 for r in runs if r["action_match"])
    scored = [r for r in runs if r["intent_match"] is not None]
    intent_ok = sum(1 for r in scored if r["intent_match"])
    l1 = [r["l1_ms"] for r in runs if r["l1_ms"] > 0]
    l2 = [r["l2_ms"] for r in runs if r["l2_ms"] > 0]
    tot = [r["total_ms"] for r in runs]

    print("\n" + "=" * 80)
    print(f"  {title}  (n={len(runs)}: {len(attacks)} attacks, {len(benign)} benign)")
    print("=" * 80)
    print(f" Decision Accuracy      : {pct(action_ok, len(runs))} ({action_ok}/{len(runs)})  95% CI {wilson(action_ok, len(runs))}")
    if scored:
        print(f" Intent Accuracy        : {pct(intent_ok, len(scored))} ({intent_ok}/{len(scored)})  95% CI {wilson(intent_ok, len(scored))}")
    print(f" Threat Block Rate      : {pct(len(attacks) - fn, len(attacks))} ({len(attacks) - fn}/{len(attacks)})  95% CI {wilson(len(attacks) - fn, len(attacks))}")
    print(f" False Positives        : {fp}/{len(benign)} ({pct(fp, len(benign))})  95% CI {wilson(fp, len(benign))}")
    print(f" False Negatives        : {fn}/{len(attacks)} ({pct(fn, len(attacks))})  95% CI {wilson(fn, len(attacks))}")
    print(f" Layer 1 latency        : avg {mean(l1) if l1 else 0:.1f} ms | p95 {p95(l1):.1f} ms")
    print(f" Layer 2 latency        : avg {mean(l2) if l2 else 0:.1f} ms | p95 {p95(l2):.1f} ms")
    print(f" Gateway total          : avg {mean(tot) if tot else 0:.1f} ms | p95 {p95(tot):.1f} ms")


async def main() -> int:
    ap = argparse.ArgumentParser(description="Sentinel gateway evaluation harness")
    ap.add_argument("--cases", type=Path, default=DEFAULT_CASES, help="path to a test-case JSON file")
    ap.add_argument("--url", default=DEFAULT_URL, help="gateway /v1/inspect URL")
    ap.add_argument("--api-key", default=None, help="X-API-Key value (else SENTINEL_API_KEY / SENTINEL_API_KEYS)")
    ap.add_argument("--delay", type=float, default=0.05, help="seconds to sleep between requests")
    ap.add_argument("--max-retries", type=int, default=6, help="retries per request on HTTP 429")
    ap.add_argument("--out", type=Path, default=None, help="write per-case results as JSON")
    ap.add_argument("--list-misses", action="store_true", help="print every case whose action was wrong")
    args = ap.parse_args()

    try:
        test_suite = load_test_cases(args.cases)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[ERROR] {e}")
        return 2

    api_key = resolve_api_key(args.api_key)
    if not api_key:
        print("[ERROR] No API key found. Set SENTINEL_API_KEY (or SENTINEL_API_KEYS in .env), or pass --api-key.")
        return 2
    headers = {"X-API-Key": api_key}

    n_total = len(test_suite)
    print("=" * 80)
    print("      AI TRUST GATEWAY: DYNAMIC EVALUATION & BENCHMARK HARNESS")
    print("=" * 80)
    print(f"Target Endpoint : {args.url}")
    print(f"Cases file      : {args.cases}")
    print(f"Test cases      : {n_total}\n")

    results: List[Dict[str, Any]] = []
    pad = len(str(n_total))
    async with httpx.AsyncClient() as client:
        for idx, item in enumerate(test_suite):
            print(f"[{idx + 1:0{pad}d}/{n_total}] ({item.get('category', 'UNKNOWN')})... ", end="", flush=True)
            try:
                res = await run_single_test(client, args.url, headers, item, idx, args.max_retries)
            except AuthError as e:
                print(f"[FAILED] {e}")
                return 2
            results.append(res)
            if res.get("error"):
                print(f"[FAILED] {res['error']}")
            else:
                status = "PASS" if res["action_match"] else "FAIL"
                print(f"[{status}] Action: {res['actual_action']} | Intent: {res['actual_intent']} ({res['total_ms']:.1f}ms)")
            await asyncio.sleep(args.delay)

    valid = [r for r in results if not r.get("error")]
    errors = len(results) - len(valid)
    if not valid:
        print("\nAll tests failed. Is the gateway running and reachable at the URL above?")
        return 1

    print_metrics("OVERALL", valid)

    by_scope: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in valid:
        by_scope[r["scope"]].append(r)
    if len(by_scope) > 1:
        for scope, runs in sorted(by_scope.items()):
            print_metrics(f"SCOPE: {scope}", runs)

    if args.list_misses:
        print("\nMISSES (wrong action):")
        for r in valid:
            if not r["action_match"]:
                print(f"  #{r['id']} [{r['category']}] expected {r['expected_action']} got {r['actual_action']} "
                      f"(intent {r['actual_intent']}): {r['prompt'][:100]!r}")

    if errors:
        print(f"\n[WARNING] {errors}/{len(results)} requests errored and are excluded from the metrics above.")

    if args.out:
        args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nPer-case results written to {args.out}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
