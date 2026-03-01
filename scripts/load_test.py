#!/usr/bin/env python3
"""Mild load test for PostureIQ agent — exercises all tools via /chat.

Sends ~50 requests over ~60 seconds with randomised delays to simulate
realistic multi-user traffic.  Prints a summary table at the end.
"""

from __future__ import annotations

import asyncio
import random
import time

import httpx

BASE_URL = "https://postureiq-dev-app.redrock-8f5cd3d2.centralus.azurecontainerapps.io"

# Messages designed to trigger each tool via the keyword-based intent classifier
PROMPTS: list[dict[str, str]] = [
    # query_secure_score
    {"message": "What is our current secure score?"},
    {"message": "Show me the Microsoft Secure Score for this tenant"},
    # assess_defender_coverage
    {"message": "How is our Defender coverage looking?"},
    {"message": "Check endpoint device onboarding status"},
    # check_purview_policies
    {"message": "Show me Purview DLP compliance policies"},
    {"message": "Are our sensitivity labels and retention policies configured?"},
    # get_entra_config
    {"message": "Review our Entra conditional access and MFA setup"},
    {"message": "What does the identity protection and PIM config look like?"},
    # generate_remediation_plan
    {"message": "Generate a remediation plan to get to green"},
    {"message": "What fixes should we prioritise to remediate gaps?"},
    # create_adoption_scorecard
    {"message": "Create an adoption scorecard dashboard"},
    {"message": "Show me the scorecard for our ME5 adoption"},
    # get_project479_playbook
    {"message": "Show me the Project 479 Foundry playbook"},
    {"message": "What's in the get to green playbook and onboarding checklist?"},
    # full assessment (triggers 4 tools at once)
    {"message": "Run a full assessment of this tenant"},
    {"message": "Do a full posture assessment for my tenant"},
]

# Also hit health/readiness probes
PROBE_PATHS = ["/health", "/ready", "/version"]

TOTAL_CHAT_REQUESTS = 40
TOTAL_PROBE_REQUESTS = 12
CONCURRENCY = 5  # max simultaneous requests


async def send_chat(
    client: httpx.AsyncClient,
    prompt: dict[str, str],
    results: list[dict],
) -> None:
    """Send a single /chat request and record the outcome."""
    start = time.perf_counter()
    try:
        resp = await client.post(
            f"{BASE_URL}/chat",
            json=prompt,
            timeout=30.0,
        )
        elapsed = time.perf_counter() - start
        results.append(
            {
                "endpoint": "POST /chat",
                "message": prompt["message"][:50],
                "status": resp.status_code,
                "latency_ms": round(elapsed * 1000),
                "tools": resp.json().get("tools_called", []) if resp.status_code == 200 else [],
            }
        )
    except Exception as exc:
        elapsed = time.perf_counter() - start
        results.append(
            {
                "endpoint": "POST /chat",
                "message": prompt["message"][:50],
                "status": f"ERR: {exc.__class__.__name__}",
                "latency_ms": round(elapsed * 1000),
                "tools": [],
            }
        )


async def send_probe(
    client: httpx.AsyncClient,
    path: str,
    results: list[dict],
) -> None:
    """Send a health/readiness probe and record the outcome."""
    start = time.perf_counter()
    try:
        resp = await client.get(f"{BASE_URL}{path}", timeout=10.0)
        elapsed = time.perf_counter() - start
        results.append(
            {
                "endpoint": f"GET {path}",
                "message": "-",
                "status": resp.status_code,
                "latency_ms": round(elapsed * 1000),
                "tools": [],
            }
        )
    except Exception as exc:
        elapsed = time.perf_counter() - start
        results.append(
            {
                "endpoint": f"GET {path}",
                "message": "-",
                "status": f"ERR: {exc.__class__.__name__}",
                "latency_ms": round(elapsed * 1000),
                "tools": [],
            }
        )


async def main() -> None:
    results: list[dict] = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async with httpx.AsyncClient() as client:

        async def throttled_chat(prompt: dict[str, str]) -> None:
            async with sem:
                await asyncio.sleep(random.uniform(0.3, 2.0))  # noqa: S311
                await send_chat(client, prompt, results)

        async def throttled_probe(path: str) -> None:
            async with sem:
                await asyncio.sleep(random.uniform(0.1, 1.0))  # noqa: S311
                await send_probe(client, path, results)

        # Build task list
        tasks: list[asyncio.Task] = []

        # Chat requests — pick randomly from PROMPTS pool
        for _ in range(TOTAL_CHAT_REQUESTS):
            prompt = random.choice(PROMPTS)  # noqa: S311
            tasks.append(asyncio.create_task(throttled_chat(prompt)))

        # Probe requests
        for _ in range(TOTAL_PROBE_REQUESTS):
            path = random.choice(PROBE_PATHS)  # noqa: S311
            tasks.append(asyncio.create_task(throttled_probe(path)))

        print(f"🚀 Sending {len(tasks)} requests (concurrency={CONCURRENCY})…\n")
        t0 = time.perf_counter()
        await asyncio.gather(*tasks)
        wall = time.perf_counter() - t0

    # ── Summary ────────────────────────────────────────────────────────
    ok = sum(1 for r in results if r["status"] == 200)
    errs = len(results) - ok
    latencies = [r["latency_ms"] for r in results if isinstance(r["status"], int)]
    avg_lat = round(sum(latencies) / len(latencies)) if latencies else 0
    p50 = sorted(latencies)[len(latencies) // 2] if latencies else 0
    p95_idx = int(len(latencies) * 0.95) if latencies else 0
    p95 = sorted(latencies)[p95_idx] if latencies else 0

    # Collect all tools triggered
    all_tools: dict[str, int] = {}
    for r in results:
        for t in r["tools"]:
            all_tools[t] = all_tools.get(t, 0) + 1

    print("=" * 72)
    print("  PostureIQ Load-Test Summary")
    print("=" * 72)
    print(f"  Total requests : {len(results)}")
    print(f"  Successes (200): {ok}")
    print(f"  Errors         : {errs}")
    print(f"  Wall time      : {wall:.1f}s")
    print(f"  Avg latency    : {avg_lat} ms")
    print(f"  p50 latency    : {p50} ms")
    print(f"  p95 latency    : {p95} ms")
    print()
    print("  Tools exercised:")
    for tool, count in sorted(all_tools.items(), key=lambda x: -x[1]):
        print(f"    {tool:40s} ×{count}")
    print("=" * 72)

    # Detail table
    print(f"\n{'#':>3}  {'Endpoint':<16} {'Status':>7} {'Latency':>8}  {'Message / Tools'}")
    print("-" * 90)
    for i, r in enumerate(results, 1):
        tools_str = ", ".join(r["tools"]) if r["tools"] else ""
        label = tools_str or r["message"]
        print(f"{i:>3}  {r['endpoint']:<16} {str(r['status']):>7} {r['latency_ms']:>6} ms  {label}")


if __name__ == "__main__":
    asyncio.run(main())
