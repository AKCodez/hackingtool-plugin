#!/usr/bin/env python3
"""
ht_env.py — Detect execution environment.

Prints JSON describing:
  - host OS (linux/macos/windows/unknown)
  - whether this Python is running inside WSL
  - on Windows: available WSL distros
  - whether Docker is available and responsive
  - preferred_backend: native | wsl | docker | fallback

Downstream (ht_run.py) uses preferred_backend to pick a runner.
"""

import json
import os
import platform
import shutil
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _detect_host() -> str:
    # When the scripts are bootstrapped inside a container (e.g. a Windows
    # host with no native Python), platform.system() reports the container's
    # OS, not the host's. The launcher passes the real host via HT_FORCE_HOST.
    forced = os.environ.get("HT_FORCE_HOST", "").strip().lower()
    if forced in ("linux", "macos", "windows", "unknown"):
        return forced
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s in ("linux", "windows"):
        return s
    return "unknown"


def _is_wsl() -> bool:
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError, OSError):
        return False


# Internal WSL distros used by Docker Desktop / Rancher / Podman — not full Linux envs.
_SYSTEM_WSL_DISTROS = {
    "docker-desktop", "docker-desktop-data",
    "rancher-desktop", "rancher-desktop-data",
    "podman-machine-default",
}


def _wsl_distros() -> list[str]:
    if _detect_host() != "windows" or not _has("wsl"):
        return []
    try:
        r = subprocess.run(
            ["wsl", "-l", "-q"],
            capture_output=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        raw = r.stdout
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        text = text.replace("\x00", "")
        distros = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return [d for d in distros if d.lower() not in _SYSTEM_WSL_DISTROS]
    except (subprocess.TimeoutExpired, OSError):
        return []


def _docker_ready() -> bool:
    # The launcher already confirmed the host daemon before bootstrapping into
    # a container, and the docker CLI may be absent inside that container even
    # though the socket is mounted. HT_FORCE_DOCKER carries that verdict in.
    forced = os.environ.get("HT_FORCE_DOCKER", "").strip().lower()
    if forced in ("1", "true", "yes"):
        return True
    if forced in ("0", "false", "no"):
        return False
    if not _has("docker"):
        return False
    # Probe the daemon with `docker version` rather than `docker info`:
    # it is much lighter (no image/network/plugin enumeration) yet still
    # round-trips to the daemon, so it returns non-zero when the daemon is
    # down. On Windows Docker Desktop `docker info` frequently exceeds a
    # short timeout on a cold or busy daemon, yielding a false negative that
    # collapses the backend to `fallback`. A generous timeout absorbs the
    # cold-start delay without hanging.
    try:
        r = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=15,
        )
        # Server section only renders when the daemon answered; a client-only
        # response (daemon unreachable) exits non-zero.
        return r.returncode == 0 and bool(r.stdout.strip())
    except (subprocess.TimeoutExpired, OSError):
        return False


def describe() -> dict:
    host = _detect_host()
    in_wsl = (host == "linux") and _is_wsl()
    wsl_distros = _wsl_distros()
    docker = _docker_ready()

    if host in ("linux", "macos"):
        backend = "native"
    elif host == "windows":
        if wsl_distros:
            backend = "wsl"
        elif docker:
            backend = "docker"
        else:
            backend = "fallback"
    else:
        backend = "fallback"

    return {
        "host": host,
        "arch": platform.machine(),
        "in_wsl": in_wsl,
        "wsl_distros": wsl_distros,
        "docker": docker,
        "preferred_backend": backend,
    }


if __name__ == "__main__":
    json.dump(describe(), sys.stdout, indent=2)
    sys.stdout.write("\n")
