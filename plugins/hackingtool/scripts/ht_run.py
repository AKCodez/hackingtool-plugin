#!/usr/bin/env python3
"""
ht_run.py — Try-first runner for hackingtool tools.

Philosophy: Claude Code runs locally on the user's machine. It has real Bash,
real filesystem, and can launch real processes. So we attempt the tool
immediately — no preemptive handoffs based on capability flags. Handoff only
after the actual run fails, and only for errors a one-shot retry can't fix.

The only true pre-block is `interactive` — tools that read from stdin mid-run
can't be answered through Bash's captured pipes.

Output: JSON on stdout. Stderr reserved for diagnostics.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from ht_env import describe


DEFAULT_TIMEOUT = 180
DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "tools.json"


# ── Docker image overrides ────────────────────────────────────────────────────
# For tools where a purpose-built image is faster/cleaner than pulling Kali
# and apt-installing everything. Keys are tool ids.
DOCKER_IMAGE_OVERRIDES: dict[str, str] = {
    "information_gathering.NMAP":           "instrumentisto/nmap",
    "information_gathering.Masscan":        "ilyaglow/masscan",
    "information_gathering.RustScan":       "rustscan/rustscan",
    "information_gathering.Subfinder":      "projectdiscovery/subfinder",
    "information_gathering.Httpx":          "projectdiscovery/httpx",
    "information_gathering.Amass":          "caffix/amass",
    "information_gathering.TheHarvester":   "secsi/theharvester",
    "information_gathering.Holehe":         "megadose/holehe",
    "information_gathering.Maigret":        "soxoj/maigret",
    "information_gathering.SpiderFoot":     "spiderfoot/spiderfoot",
    "information_gathering.TruffleHog":     "trufflesecurity/trufflehog",
    "information_gathering.Gitleaks":       "zricethezav/gitleaks",
    "web_attack.Nuclei":                    "projectdiscovery/nuclei",
    "web_attack.Katana":                    "projectdiscovery/katana",
    "web_attack.Ffuf":                      "secsi/ffuf",
    "web_attack.Gobuster":                  "devopsworks/gobuster",
    "web_attack.Dirsearch":                 "loqutus/dirsearch",
    "web_attack.TestSSL":                   "drwetter/testssl.sh",
    "web_attack.Wafw00f":                   "0xsauby/wafw00f",
    "web_attack.Nikto":                     "frapsoft/nikto",
    "sql_injection.Sqlmap":                 "paoloo/sqlmap",
    "phishing_attack.Dnstwist":             "elceef/dnstwist",
    "active_directory.Impacket":            "rflathers/impacket",
    "active_directory.NetExec":             "byt3bl33d3r/netexec",
    "forensics.Binwalk":                    "cincan/binwalk",
}

# Default Docker image when no override exists
DEFAULT_DOCKER_IMAGE = "kalilinux/kali-rolling"


# ── Index loading ─────────────────────────────────────────────────────────────

def load_tools() -> dict:
    if not DATA_PATH.exists():
        sys.exit(json.dumps({
            "status": "error",
            "message": f"tools.json not found at {DATA_PATH}. Run ht_index.py first.",
        }))
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def find_tool(doc: dict, tool_id: str) -> dict | None:
    for t in doc["tools"]:
        if t["id"] == tool_id:
            return t
    return None


# ── Handoff formatting ────────────────────────────────────────────────────────

def handoff(tool: dict, reason: str, command: str, hint: str = "", diagnostic: dict | None = None) -> dict:
    msg = (
        f"Couldn't run from here ({reason}). Run it yourself, paste the output back:\n\n"
        f"  {command}\n"
    )
    if hint:
        msg += f"\n{hint}\n"
    result = {
        "status": "handoff",
        "reason": reason,
        "tool": tool["id"],
        "title": tool["title"],
        "command": command,
        "message": msg,
    }
    if diagnostic:
        result["diagnostic"] = diagnostic
    return result


# ── Error classification ──────────────────────────────────────────────────────

# Patterns that indicate "try again with sudo" would help
PERMISSION_PATTERNS = [
    re.compile(r"permission denied", re.I),
    re.compile(r"operation not permitted", re.I),
    re.compile(r"you need to be root", re.I),
    re.compile(r"requires root", re.I),
    re.compile(r"must be run as root", re.I),
    re.compile(r"EPERM"),
    re.compile(r"you do not have enough privileges", re.I),
]

# Patterns that indicate the binary isn't installed
NOT_FOUND_PATTERNS = [
    re.compile(r"command not found", re.I),
    re.compile(r"not found.*PATH", re.I),
    re.compile(r"No such file or directory.*bin", re.I),
    re.compile(r": not found$", re.I | re.M),
    re.compile(r"is not recognized as an internal or external command", re.I),
]

# Patterns that indicate hardware the host doesn't have (or can't reach)
NO_DEVICE_PATTERNS = [
    re.compile(r"no such device", re.I),
    re.compile(r"no wireless (interface|extensions)", re.I),
    re.compile(r"no interfaces.*monitor mode", re.I),
    re.compile(r"SIOCGIFFLAGS.*No such device", re.I),
    re.compile(r"cannot find (any )?interface", re.I),
    re.compile(r"device .* does not exist", re.I),
]

# Patterns that indicate the tool blocked waiting for input
STDIN_NEEDED_PATTERNS = [
    re.compile(r"input.*required", re.I),
    re.compile(r"EOFError"),
    re.compile(r"cannot read from stdin", re.I),
]


def classify_error(stdout: str, stderr: str, returncode: int) -> str | None:
    """Return a category string for the error, or None if not classifiable."""
    blob = f"{stdout}\n{stderr}"
    if any(p.search(blob) for p in NOT_FOUND_PATTERNS):
        return "not_installed"
    if any(p.search(blob) for p in NO_DEVICE_PATTERNS):
        return "no_device"
    if any(p.search(blob) for p in PERMISSION_PATTERNS):
        return "permission_denied"
    if any(p.search(blob) for p in STDIN_NEEDED_PATTERNS):
        return "stdin_needed"
    return None


# ── Backends ──────────────────────────────────────────────────────────────────

def _decode(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("utf-8", errors="replace")


def _run(argv: list[str], timeout: int, label: str, extra: dict | None = None,
         stdin: str | None = None) -> dict:
    try:
        r = subprocess.run(
            argv,
            capture_output=True, timeout=timeout,
            input=stdin.encode("utf-8") if stdin else None,
        )
    except subprocess.TimeoutExpired as e:
        # Partial output may still be useful
        stdout = _decode(e.stdout or b"")
        stderr = _decode(e.stderr or b"")
        return {"status": "timeout", "backend": label, "argv": argv,
                "stdout": stdout, "stderr": stderr,
                "message": f"Timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"status": "error", "backend": label, "argv": argv,
                "message": f"Backend executable not found: {e}"}

    result = {
        "status": "ok" if r.returncode == 0 else "error",
        "backend": label,
        "returncode": r.returncode,
        "stdout": _decode(r.stdout),
        "stderr": _decode(r.stderr),
    }
    if extra:
        result.update(extra)
    return result


def run_native(command: str, timeout: int, use_sudo: bool = False) -> dict:
    prefix = "sudo -n " if use_sudo else ""
    full = f"{prefix}{command}" if use_sudo else command
    return _run(["bash", "-lc", full], timeout, "native",
                {"command": full, "sudo": use_sudo})


def run_wsl(command: str, timeout: int, distro: str | None, use_sudo: bool = False) -> dict:
    prefix = "sudo -n " if use_sudo else ""
    full = f"{prefix}{command}" if use_sudo else command
    argv = ["wsl"]
    if distro:
        argv += ["-d", distro]
    argv += ["--", "bash", "-lc", full]
    return _run(argv, timeout, "wsl",
                {"command": full, "distro": distro, "sudo": use_sudo})


def run_docker(command: str, timeout: int, image: str,
               network_host: bool = False, privileged: bool = False,
               use_entrypoint: bool = True) -> dict:
    """Run inside a docker container.

    If use_entrypoint is True (default for override images), we append the
    command as args to the image's ENTRYPOINT. Otherwise we run via bash -lc
    (required for the generic kali-rolling image).
    """
    cwd = os.getcwd().replace("\\", "/")
    if len(cwd) > 1 and cwd[1] == ":":
        cwd = "/" + cwd[0].lower() + cwd[2:]

    argv = ["docker", "run", "--rm"]
    if network_host:
        argv += ["--network", "host"]
    if privileged:
        argv += ["--privileged"]
    argv += ["-v", f"{cwd}:/work", "-w", "/work"]

    if use_entrypoint:
        # Image has a proper ENTRYPOINT (e.g. instrumentisto/nmap → nmap).
        # Strip the binary name if it's the first token — entrypoint adds it.
        tokens = command.split()
        image_binary = image.split("/")[-1].split(":")[0]
        if tokens and tokens[0] == image_binary:
            tokens = tokens[1:]
        argv += [image] + tokens
    else:
        argv += [image, "bash", "-lc", command]

    return _run(argv, timeout, "docker",
                {"command": command, "image": image,
                 "network_host": network_host, "privileged": privileged})


# ── Dispatcher ────────────────────────────────────────────────────────────────

def pick_docker_image(tool_id: str) -> tuple[str, bool]:
    """Return (image, use_entrypoint) for a tool id."""
    if tool_id in DOCKER_IMAGE_OVERRIDES:
        return DOCKER_IMAGE_OVERRIDES[tool_id], True
    return DEFAULT_DOCKER_IMAGE, False


def execute(tool: dict, command: str, backend: str, timeout: int,
            distro: str | None, docker_network_host: bool,
            docker_privileged: bool) -> dict:
    """Run once on the given backend. No retry logic — caller handles that."""
    if backend == "native":
        return run_native(command, timeout)
    if backend == "wsl":
        return run_wsl(command, timeout, distro)
    if backend == "docker":
        image, use_ep = pick_docker_image(tool["id"])
        return run_docker(command, timeout, image,
                          network_host=docker_network_host,
                          privileged=docker_privileged,
                          use_entrypoint=use_ep)
    if backend == "handoff":
        return {"status": "no_backend"}
    return {"status": "error", "message": f"unknown backend: {backend}"}


def retry_with_sudo(tool: dict, command: str, backend: str, timeout: int,
                    distro: str | None) -> dict:
    """Only applicable to native/wsl backends. Docker already runs as root."""
    if backend == "native":
        return run_native(command, timeout, use_sudo=True)
    if backend == "wsl":
        return run_wsl(command, timeout, distro, use_sudo=True)
    return {"status": "error", "message": "cannot retry with sudo on this backend"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Try-first runner for hackingtool tools.")
    ap.add_argument("tool_id", help="Tool id, e.g. information_gathering.Amass")
    ap.add_argument("--args", default="", help="Args appended to the tool's run command")
    ap.add_argument("--command", default=None,
                    help="Full command override. Use when run_commands is empty (e.g. nmap) "
                         "or you need a completely different invocation.")
    ap.add_argument("--install", action="store_true",
                    help="Run INSTALL_COMMANDS (native/wsl only; docker images include the tool)")
    ap.add_argument("--force", action="store_true",
                    help="Bypass the interactive pre-block and still attempt the run.")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--backend",
                    choices=["auto", "native", "wsl", "docker"], default="auto")
    ap.add_argument("--distro", default=None, help="WSL distro name")
    ap.add_argument("--docker-image", default=None,
                    help="Override docker image for this run")
    ap.add_argument("--network-host", action="store_true",
                    help="Docker: use --network host (useful for LAN scans)")
    ap.add_argument("--privileged", action="store_true",
                    help="Docker: run with --privileged (for raw sockets, hardware access)")
    ap.add_argument("--no-retry-sudo", action="store_true",
                    help="Don't retry with sudo on permission_denied")
    args = ap.parse_args()

    doc = load_tools()
    tool = find_tool(doc, args.tool_id)
    if not tool:
        print(json.dumps({
            "status": "error",
            "message": f"tool not found: {args.tool_id}. Use ht_search.py to discover ids.",
        }, indent=2))
        sys.exit(2)

    # Resolve command: --command override > tool.run_commands[0] + --args
    if args.command is not None:
        command = args.command
    else:
        cmds = tool["install_commands"] if args.install else tool["run_commands"]
        if not cmds:
            print(json.dumps(handoff(
                tool, "no_command", "",
                hint=(
                    f"The index has no {'install' if args.install else 'run'}_commands. "
                    f"Pass --command \"...\" to invoke directly. "
                    f"Project: {tool.get('project_url') or '(none)'}"
                ),
            ), indent=2))
            return
        command = cmds[0]
        if not args.install and args.args:
            command = f"{command} {args.args}"

    caps = tool["capabilities"]

    # The ONLY pre-block: interactive tools that read stdin mid-run.
    # --force bypasses this.
    if caps.get("interactive") and not args.force and args.command is None:
        print(json.dumps(handoff(
            tool, "interactive",
            command,
            hint="Tool reads stdin mid-run; pipe can't answer prompts. Run it yourself, "
                 "or use --command to supply a non-interactive invocation, or --force.",
        ), indent=2))
        return

    env = describe()
    backend = args.backend if args.backend != "auto" else env["preferred_backend"]
    distro = args.distro or (env["wsl_distros"][0] if env["wsl_distros"] else None)

    if backend == "handoff":
        print(json.dumps(handoff(
            tool, "no_backend", command,
            hint=(
                "No Linux runtime available. Options: (a) `wsl --install -d Ubuntu`, "
                "(b) start Docker Desktop, (c) run this command on another machine."
            ),
        ), indent=2))
        return

    # Apply user's docker image override
    if args.docker_image and backend == "docker":
        DOCKER_IMAGE_OVERRIDES[tool["id"]] = args.docker_image

    # First attempt
    result = execute(tool, command, backend, args.timeout, distro,
                     args.network_host, args.privileged)

    # Try sudo retry on permission errors (native/wsl only — docker is already root)
    if (result.get("status") == "error"
            and backend in ("native", "wsl")
            and not args.no_retry_sudo):
        err_class = classify_error(result.get("stdout", ""), result.get("stderr", ""),
                                   result.get("returncode", 1))
        if err_class == "permission_denied":
            retry = retry_with_sudo(tool, command, backend, args.timeout, distro)
            if retry.get("status") == "ok":
                retry["retried_with_sudo"] = True
                retry["tool"] = tool["id"]
                retry["title"] = tool["title"]
                print(json.dumps(retry, indent=2, ensure_ascii=False))
                return
            # Sudo also failed — likely needs interactive password
            if retry.get("returncode") == 1 and "password" in (retry.get("stderr", "").lower()):
                print(json.dumps(handoff(
                    tool, "sudo_password_needed", f"sudo {command}",
                    hint="`sudo -n` failed (needs password). Run manually or configure passwordless sudo.",
                    diagnostic={"first_try": result, "sudo_try": retry},
                ), indent=2))
                return
            result = retry  # fall through with sudo'd result

    # On failure, classify and maybe handoff with context
    if result.get("status") != "ok":
        err_class = classify_error(result.get("stdout", ""), result.get("stderr", ""),
                                   result.get("returncode", 1))
        if err_class == "no_device":
            # True hardware limitation — handoff with hint about what's needed
            print(json.dumps(handoff(
                tool, "no_device",
                command,
                hint="Tool needs hardware (wifi adapter in monitor mode, SDR, etc.) that isn't visible to the backend.",
                diagnostic=result,
            ), indent=2))
            return
        if err_class == "not_installed":
            print(json.dumps(handoff(
                tool, "not_installed",
                command,
                hint=(
                    f"Tool binary not found. Try: `python ht_run.py {tool['id']} --install`. "
                    f"On docker backend, consider --docker-image <image> with the tool pre-installed."
                ),
                diagnostic=result,
            ), indent=2))
            return
        if err_class == "stdin_needed":
            print(json.dumps(handoff(
                tool, "interactive_detected",
                command,
                hint="Tool blocked on stdin during the run. Index didn't flag it interactive — update the capability.",
                diagnostic=result,
            ), indent=2))
            return
        # Unclassified error — surface it but don't handoff; let caller decide
        result["tool"] = tool["id"]
        result["title"] = tool["title"]
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    # Success
    result["tool"] = tool["id"]
    result["title"] = tool["title"]
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
