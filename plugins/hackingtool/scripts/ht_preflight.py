#!/usr/bin/env python3
"""
ht_preflight.py — Capability check + setup recommendations.

Wraps `ht_env.describe()`, adds disk + internet checks, and returns a
`verdict` (ready | partial | blocked) plus a list of `recommendations`.

The skill calls this once at the start of a session and surfaces the
recommendations to the user before doing any manual probing.

Output is JSON on stdout. Always exit 0 — the model parses the verdict.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import ht_env  # noqa: E402

_MIN_FREE_GB = 5


def _disk_free_gb() -> float:
    try:
        return round(shutil.disk_usage(_HERE).free / (1024 ** 3), 1)
    except OSError:
        return -1.0


def _internet_ok() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            return True
    except (OSError, socket.timeout):
        return False


def _recommendations(env: dict, disk_gb: float, net_ok: bool) -> list[dict]:
    recs: list[dict] = []
    backend = env["preferred_backend"]
    host = env["host"]

    if not net_ok:
        recs.append({
            "priority": "critical",
            "action": "Restore internet connectivity",
            "why": "Image pulls and template updates require it.",
        })

    if backend == "fallback":
        if host == "windows":
            recs.append({
                "priority": "critical",
                "action": "Install Docker Desktop OR enable WSL2 (`wsl --install -d Ubuntu`)",
                "why": "Without one, Linux-only tools (nmap, nuclei, subfinder, ffuf) cannot run — only manual curl probes remain.",
            })
        else:
            recs.append({
                "priority": "critical",
                "action": "Install Docker, or run on Linux/macOS",
                "why": "No usable backend detected.",
            })

    if 0 <= disk_gb < _MIN_FREE_GB and (env["docker"] or backend == "fallback"):
        recs.append({
            "priority": "high",
            "action": f"Free disk space (currently {disk_gb} GB)",
            "why": f"Pentest Docker images can total several GB; {_MIN_FREE_GB}+ recommended.",
        })

    return recs


def _verdict(env: dict, recs: list[dict]) -> str:
    if env["preferred_backend"] == "fallback":
        return "blocked"
    if any(r["priority"] == "critical" for r in recs):
        return "blocked"
    if any(r["priority"] == "high" for r in recs):
        return "partial"
    return "ready"


def _summary(env: dict, verdict: str, recs: list[dict]) -> str:
    head = {
        "ready":   f"Ready — backend={env['preferred_backend']}.",
        "partial": f"Partial — backend={env['preferred_backend']}. Some workflows limited.",
        "blocked": f"Blocked — backend={env['preferred_backend']}. Real tools cannot run here.",
    }[verdict]
    if not recs:
        return head
    bullets = "\n".join(f"  [{r['priority']}] {r['action']} — {r['why']}" for r in recs)
    return f"{head}\nSetup:\n{bullets}"


def main() -> int:
    env = ht_env.describe()
    disk_gb = _disk_free_gb()
    net_ok = _internet_ok()
    recs = _recommendations(env, disk_gb, net_ok)
    verdict = _verdict(env, recs)
    json.dump({
        "env": env,
        "disk_free_gb": disk_gb,
        "internet": net_ok,
        "verdict": verdict,
        "recommendations": recs,
        "summary_for_user": _summary(env, verdict, recs),
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
