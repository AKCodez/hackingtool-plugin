#!/usr/bin/env python3
"""
ht_preflight.py — Capability check + setup recommendations.

Wraps `ht_env.describe()`, adds disk + internet checks, probes a small
set of canonical tool binaries on PATH, and returns a `verdict`
(ready | partial | blocked) plus an ordered `recommendations` list.

The skill calls this once per session and surfaces recommendations to
the user before doing any manual probing.

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

# Tools that cover the most common asks. Used only when the backend is
# native/wsl — Docker can substitute for any of them via ht_run.py.
_CORE_BINARIES = ["nmap", "nuclei", "subfinder", "httpx", "ffuf"]


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


def _native_tools_present() -> list[str]:
    return [t for t in _CORE_BINARIES if shutil.which(t) is not None]


def _install_hint(host: str) -> str:
    """OS-specific install command for a few core tools."""
    if host == "macos":
        return "`brew install nmap nuclei subfinder httpx ffuf`"
    if host == "linux":
        return ("`sudo apt install nmap` + Go tools "
                "(`go install github.com/projectdiscovery/{nuclei,subfinder,httpx,ffuf}/...@latest`)")
    if host == "windows":
        return "Install Docker Desktop OR enable WSL2 (`wsl --install -d Ubuntu`)"
    return "Install the tools natively or use Docker"


def _recommendations(env: dict, disk_gb: float, net_ok: bool,
                     native_tools: list[str]) -> list[dict]:
    recs: list[dict] = []
    backend = env["preferred_backend"]
    host = env["host"]
    docker = env["docker"]

    if not net_ok:
        recs.append({
            "priority": "critical",
            "action": "Restore internet connectivity",
            "why": "Image pulls (Docker Hub) and template updates (nuclei-templates) require it.",
        })

    if backend == "fallback":
        # Genuinely no usable backend (Windows w/o Docker AND w/o WSL, or unknown OS).
        recs.append({
            "priority": "critical",
            "action": _install_hint(host),
            "why": "No usable backend detected. Without one, Linux-only tools (nmap, nuclei, subfinder, ffuf) cannot run — only manual probes remain.",
        })
    elif backend in ("native", "wsl") and not native_tools and not docker:
        # Linux/macOS/WSL with neither native pentest tools nor Docker.
        # The skill is technically "able to run" but has nothing to invoke.
        recs.append({
            "priority": "critical",
            "action": f"Install pentest tools natively ({_install_hint(host)}) OR install Docker",
            "why": "Backend works but no core tools (nmap/nuclei/subfinder/httpx/ffuf) are on PATH and Docker is unavailable, so wrappers will fail.",
        })
    elif backend in ("native", "wsl") and len(native_tools) < len(_CORE_BINARIES) and not docker:
        # Some native tools missing; no Docker fallback.
        missing = [t for t in _CORE_BINARIES if t not in native_tools]
        recs.append({
            "priority": "high",
            "action": f"Install missing tools ({', '.join(missing)}) or start Docker as fallback",
            "why": f"Have {', '.join(native_tools)} natively; {', '.join(missing)} missing and no Docker fallback available.",
        })

    if 0 <= disk_gb < _MIN_FREE_GB and (docker or backend == "fallback"):
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


def _summary(env: dict, verdict: str, recs: list[dict],
             native_tools: list[str]) -> str:
    backend = env["preferred_backend"]
    docker = env["docker"]

    if verdict == "ready":
        if backend in ("native", "wsl") and native_tools:
            head = (f"Ready — backend={backend}, "
                    f"{len(native_tools)}/{len(_CORE_BINARIES)} core tools on PATH"
                    f"{' (Docker fallback available)' if docker else ''}.")
        elif backend == "docker":
            head = f"Ready — backend={backend} (tools run in containers)."
        else:
            head = f"Ready — backend={backend}."
    elif verdict == "partial":
        head = f"Partial — backend={backend}. Some workflows limited."
    else:
        head = f"Blocked — backend={backend}. Real tools cannot run here."

    if not recs:
        return head
    bullets = "\n".join(f"  [{r['priority']}] {r['action']} — {r['why']}" for r in recs)
    return f"{head}\nSetup:\n{bullets}"


def main() -> int:
    env = ht_env.describe()
    disk_gb = _disk_free_gb()
    net_ok = _internet_ok()
    native_tools = _native_tools_present() if env["preferred_backend"] in ("native", "wsl") else []
    recs = _recommendations(env, disk_gb, net_ok, native_tools)
    verdict = _verdict(env, recs)
    json.dump({
        "env": env,
        "disk_free_gb": disk_gb,
        "internet": net_ok,
        "native_tools_present": native_tools,
        "verdict": verdict,
        "recommendations": recs,
        "summary_for_user": _summary(env, verdict, recs, native_tools),
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
