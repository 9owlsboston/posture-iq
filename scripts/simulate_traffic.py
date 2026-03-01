#!/usr/bin/env python3
"""PostureIQ — Configurable traffic simulator for App Insights telemetry.

Sends realistic chat and probe traffic to a PostureIQ deployment over a
configurable duration, with periodic bursts at a settable interval.

Usage examples:

  # Quick smoke — one burst of 10 requests
  python scripts/simulate_traffic.py

  # 30-minute sustained load, burst every 5 minutes, 20 requests per burst
  python scripts/simulate_traffic.py --duration 30 --interval 5 --burst-size 20

  # Heavy load for 1 hour, burst every 2 minutes, 50 requests, concurrency 10
  python scripts/simulate_traffic.py --duration 60 --interval 2 --burst-size 50 --concurrency 10

  # Target a different endpoint
  python scripts/simulate_traffic.py --url https://my-app.azurecontainerapps.io

  # Only exercise specific tools
  python scripts/simulate_traffic.py --tools secure_score,defender,entra

  # Include health probes in each burst
  python scripts/simulate_traffic.py --probes

  # Verbose mode — print every request
  python scripts/simulate_traffic.py -v
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
import time
from datetime import UTC, datetime

import httpx

# ── Prompt catalogue ──────────────────────────────────────────────────────
# Each entry: (tool_tag, message)
# tool_tag is used for --tools filtering
PROMPT_CATALOGUE: list[tuple[str, str]] = [
    # query_secure_score
    ("secure_score", "What is our current secure score?"),
    ("secure_score", "Show me the Microsoft Secure Score for this tenant"),
    ("secure_score", "How does our secure score compare to industry average?"),
    # assess_defender_coverage
    ("defender", "How is our Defender coverage looking?"),
    ("defender", "Check endpoint device onboarding status"),
    ("defender", "Show Defender for Identity deployment status"),
    # check_purview_policies
    ("purview", "Show me Purview DLP compliance policies"),
    ("purview", "Are our sensitivity labels and retention policies configured?"),
    ("purview", "What's the status of Insider Risk Management?"),
    # get_entra_config
    ("entra", "Review our Entra conditional access and MFA setup"),
    ("entra", "What does the identity protection and PIM config look like?"),
    ("entra", "Are access reviews configured for privileged roles?"),
    # generate_remediation_plan
    ("remediation", "Generate a remediation plan to get to green"),
    ("remediation", "What fixes should we prioritise to remediate gaps?"),
    ("remediation", "Create a prioritized fix list for the security gaps"),
    # create_adoption_scorecard
    ("scorecard", "Create an adoption scorecard dashboard"),
    ("scorecard", "Show me the scorecard for our ME5 adoption"),
    ("scorecard", "Generate an executive summary with RAG status per workload"),
    # get_project479_playbook
    ("playbook", "Show me the Project 479 Foundry playbook"),
    ("playbook", "What's in the get to green playbook and onboarding checklist?"),
    ("playbook", "Map our gaps to the Project 479 offer catalog"),
    # full assessment (triggers 4 tools)
    ("full", "Run a full assessment of this tenant"),
    ("full", "Do a full posture assessment for my tenant"),
    ("full", "Assess this tenant's ME5 security posture"),
]

ALL_TOOL_TAGS = sorted({tag for tag, _ in PROMPT_CATALOGUE})

PROBE_PATHS = ["/health", "/ready", "/version"]

DEFAULT_URL = "https://postureiq-dev-app.redrock-8f5cd3d2.centralus.azurecontainerapps.io"


# ── HTTP helpers ──────────────────────────────────────────────────────────


async def send_chat(
    client: httpx.AsyncClient,
    url: str,
    message: str,
    verbose: bool,
) -> dict:
    """POST /chat and return a result dict."""
    start = time.perf_counter()
    try:
        resp = await client.post(
            f"{url}/chat",
            json={"message": message},
            timeout=45.0,
        )
        elapsed = time.perf_counter() - start
        tools = resp.json().get("tools_called", []) if resp.status_code == 200 else []
        result = {
            "endpoint": "POST /chat",
            "message": message[:60],
            "status": resp.status_code,
            "latency_ms": round(elapsed * 1000),
            "tools": tools,
        }
    except Exception as exc:
        elapsed = time.perf_counter() - start
        result = {
            "endpoint": "POST /chat",
            "message": message[:60],
            "status": f"ERR:{exc.__class__.__name__}",
            "latency_ms": round(elapsed * 1000),
            "tools": [],
        }
    if verbose:
        tools_str = ",".join(result["tools"]) or "-"
        print(f"  [{result['status']}] {result['latency_ms']:>6}ms  {result['message'][:45]}  → {tools_str}")
    return result


async def send_probe(
    client: httpx.AsyncClient,
    url: str,
    path: str,
    verbose: bool,
) -> dict:
    """GET a health/readiness probe and return a result dict."""
    start = time.perf_counter()
    try:
        resp = await client.get(f"{url}{path}", timeout=10.0)
        elapsed = time.perf_counter() - start
        result = {
            "endpoint": f"GET {path}",
            "message": "-",
            "status": resp.status_code,
            "latency_ms": round(elapsed * 1000),
            "tools": [],
        }
    except Exception as exc:
        elapsed = time.perf_counter() - start
        result = {
            "endpoint": f"GET {path}",
            "message": "-",
            "status": f"ERR:{exc.__class__.__name__}",
            "latency_ms": round(elapsed * 1000),
            "tools": [],
        }
    if verbose:
        print(f"  [{result['status']}] {result['latency_ms']:>6}ms  {path}")
    return result


# ── Burst logic ───────────────────────────────────────────────────────────


async def run_burst(
    client: httpx.AsyncClient,
    url: str,
    prompts: list[str],
    burst_size: int,
    concurrency: int,
    include_probes: bool,
    verbose: bool,
) -> list[dict]:
    """Fire one burst of requests and return results."""
    sem = asyncio.Semaphore(concurrency)
    results: list[dict] = []

    async def _chat(msg: str) -> None:
        async with sem:
            await asyncio.sleep(random.uniform(0.1, 1.5))  # noqa: S311
            r = await send_chat(client, url, msg, verbose)
            results.append(r)

    async def _probe(path: str) -> None:
        async with sem:
            await asyncio.sleep(random.uniform(0.05, 0.5))  # noqa: S311
            r = await send_probe(client, url, path, verbose)
            results.append(r)

    tasks: list[asyncio.Task] = []
    for _ in range(burst_size):
        tasks.append(asyncio.create_task(_chat(random.choice(prompts))))  # noqa: S311

    if include_probes:
        probe_count = max(3, burst_size // 4)
        for _ in range(probe_count):
            tasks.append(asyncio.create_task(_probe(random.choice(PROBE_PATHS))))  # noqa: S311

    await asyncio.gather(*tasks)
    return results


# ── Summary ───────────────────────────────────────────────────────────────


def print_summary(all_results: list[dict], wall_time: float, burst_count: int) -> None:
    """Print a formatted summary of the simulation run."""
    ok = sum(1 for r in all_results if r["status"] == 200)
    errs = len(all_results) - ok
    latencies = [r["latency_ms"] for r in all_results if isinstance(r["status"], int)]
    avg_lat = round(sum(latencies) / len(latencies)) if latencies else 0
    sorted_lat = sorted(latencies) if latencies else [0]
    p50 = sorted_lat[len(sorted_lat) // 2]
    p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
    p99 = sorted_lat[int(len(sorted_lat) * 0.99)]

    all_tools: dict[str, int] = {}
    for r in all_results:
        for t in r["tools"]:
            all_tools[t] = all_tools.get(t, 0) + 1

    endpoints: dict[str, int] = {}
    for r in all_results:
        endpoints[r["endpoint"]] = endpoints.get(r["endpoint"], 0) + 1

    print()
    print("=" * 72)
    print("  PostureIQ Traffic Simulation Summary")
    print("=" * 72)
    print(f"  Bursts completed : {burst_count}")
    print(f"  Total requests   : {len(all_results)}")
    print(f"  Successes (200)  : {ok}")
    print(f"  Errors           : {errs}")
    print(f"  Wall time        : {wall_time:.1f}s ({wall_time / 60:.1f} min)")
    print(f"  Avg latency      : {avg_lat} ms")
    print(f"  p50 / p95 / p99  : {p50} / {p95} / {p99} ms")
    print()
    print("  Endpoints:")
    for ep, cnt in sorted(endpoints.items(), key=lambda x: -x[1]):
        print(f"    {ep:<20s} ×{cnt}")
    print()
    print("  Tools exercised:")
    for tool, cnt in sorted(all_tools.items(), key=lambda x: -x[1]):
        print(f"    {tool:<40s} ×{cnt}")
    print("=" * 72)


# ── Main ──────────────────────────────────────────────────────────────────


async def async_main(args: argparse.Namespace) -> None:
    # Filter prompts by --tools selection
    if args.tools:
        selected_tags = {t.strip().lower() for t in args.tools.split(",")}
        prompts = [msg for tag, msg in PROMPT_CATALOGUE if tag in selected_tags]
        if not prompts:
            print(f"ERROR: No prompts match --tools={args.tools}")
            print(f"  Available tags: {', '.join(ALL_TOOL_TAGS)}")
            sys.exit(1)
    else:
        prompts = [msg for _, msg in PROMPT_CATALOGUE]

    url = args.url.rstrip("/")
    duration_s = args.duration * 60
    interval_s = args.interval * 60
    burst_count = max(1, int(duration_s / interval_s)) if duration_s > 0 else 1

    print("🚀 PostureIQ Traffic Simulator")
    print(f"   Target       : {url}")
    print(f"   Duration     : {args.duration} min ({burst_count} burst(s))")
    print(f"   Interval     : {args.interval} min")
    print(f"   Burst size   : {args.burst_size} chat requests" + (" + probes" if args.probes else ""))
    print(f"   Concurrency  : {args.concurrency}")
    print(f"   Prompt pool  : {len(prompts)} messages")
    print()

    all_results: list[dict] = []
    t0 = time.perf_counter()

    async with httpx.AsyncClient() as client:
        for i in range(burst_count):
            burst_start = datetime.now(UTC).strftime("%H:%M:%S")
            print(f"── Burst {i + 1}/{burst_count} at {burst_start} ──")

            results = await run_burst(
                client=client,
                url=url,
                prompts=prompts,
                burst_size=args.burst_size,
                concurrency=args.concurrency,
                include_probes=args.probes,
                verbose=args.verbose,
            )
            all_results.extend(results)

            ok = sum(1 for r in results if r["status"] == 200)
            print(f"   ✓ {ok}/{len(results)} succeeded\n")

            # Sleep until next burst (skip after last burst)
            if i < burst_count - 1:
                elapsed = time.perf_counter() - t0
                next_burst_at = (i + 1) * interval_s
                sleep_for = max(0, next_burst_at - elapsed)
                if sleep_for > 0:
                    print(f"   ⏳ Sleeping {sleep_for:.0f}s until next burst…\n")
                    await asyncio.sleep(sleep_for)

    wall = time.perf_counter() - t0
    print_summary(all_results, wall, burst_count)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PostureIQ traffic simulator — generate App Insights telemetry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick smoke test (one burst, 10 requests)
  python scripts/simulate_traffic.py

  # 30-min sustained load, burst every 5 min, 20 requests/burst
  python scripts/simulate_traffic.py --duration 30 --interval 5 --burst-size 20

  # Heavy 1-hour run with probes
  python scripts/simulate_traffic.py --duration 60 --interval 2 --burst-size 50 --concurrency 10 --probes

  # Only test Secure Score and Defender tools
  python scripts/simulate_traffic.py --tools secure_score,defender

Available tool tags for --tools:
  secure_score, defender, purview, entra, remediation, scorecard, playbook, full
""",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Base URL of the PostureIQ deployment (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        metavar="MINS",
        help="Total simulation duration in minutes. 0 = single burst (default: 0)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5,
        metavar="MINS",
        help="Minutes between bursts (default: 5)",
    )
    parser.add_argument(
        "--burst-size",
        type=int,
        default=10,
        metavar="N",
        help="Number of chat requests per burst (default: 10)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        metavar="N",
        help="Max simultaneous requests (default: 5)",
    )
    parser.add_argument(
        "--tools",
        type=str,
        default="",
        metavar="TAGS",
        help=f"Comma-separated tool tags to exercise (default: all). Available: {', '.join(ALL_TOOL_TAGS)}",
    )
    parser.add_argument(
        "--probes",
        action="store_true",
        help="Include /health, /ready, /version probes in each burst",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print each request as it completes",
    )
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
