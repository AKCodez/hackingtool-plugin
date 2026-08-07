# HackingTool Plugin Integration Guide for Claude Code

**Plugin:** `hackingtool` (marketplace: `hackingtool-marketplace`, repo `AKCODEZ/hackingtool-plugin`)
**Wraps:** [Z4nzu/hackingtool](https://github.com/Z4nzu/hackingtool) — 183 pentesting/OSINT tools (MIT)
**Plugin version:** 0.2.0
**This guide replaces an earlier draft that described a CLI surface (`claude code --task`, `--workflow`, `--plugin install`) that does not exist. Everything below was verified against the actual scripts and a live run.**

## Table of Contents

1. Quick Start
2. Prerequisites
3. Installation
4. How It Actually Works
5. Basic Usage
6. Common Workflows
7. Best Practices
8. Security Considerations
9. Troubleshooting
10. Examples (real, validated runs)

---

## 1. Quick Start

There is no special `claude code --task "..."` command. You install the plugin once, then just talk to Claude normally.

```
# 1. Install Claude Code, if you haven't already
npm install -g @anthropic-ai/claude-code

# 2. Inside a Claude Code session, add the marketplace and install the plugin
/plugin marketplace add AKCODEZ/hackingtool-plugin
/plugin install hackingtool@hackingtool-marketplace

# 3. Just ask, in plain language
"recon example.com"
"hunt the username johndoe"
"scan my repo for leaked secrets"
```

The first pentest-shaped ask in a session triggers a preflight check automatically — Claude will tell you which backend it picked (native / WSL / Docker) before running anything.

---

## 2. Prerequisites

### System Requirements

- **OS:** Linux, macOS, or Windows.
- **Python 3.10+** on the machine running Claude Code — the plugin's scripts (`ht_preflight.py`, `ht_search.py`, `ht_run.py`) are plain Python, executed via Claude Code's Bash tool. (Verified working on Python 3.14.)
- **Claude Code** with plugin support.
- **Disk space:** 5GB+ free recommended. `ht_preflight.py` checks free space and warns below that threshold, since pentest Docker images add up.

### Windows specifically

You need **one** of:

- a real WSL distro (Ubuntu, Kali, etc.), or
- Docker Desktop running.

The detector (`ht_env.py`) explicitly filters out Docker Desktop's internal housekeeping distros (`docker-desktop`, `docker-desktop-data`, etc.) — those don't count as a usable WSL backend. If neither a real distro nor Docker is present, the environment reports `preferred_backend: fallback` and the skill says so rather than pretending it can run tools.

### Network

Outbound internet is required for Docker Hub image pulls and some tools' own lookups (e.g. `nuclei` templates, `subfinder` sources). Preflight actively checks connectivity (`1.1.1.1:443`) and flags it if unreachable.

### Authorization

Unchanged from good general practice: never point this at a system you don't own or don't have explicit written permission to test. See [Security Considerations](#8-security-considerations).

### No built-in credential vault

There is no `~/.hackingtool/credentials.env` mechanism. If a tool needs an API key (e.g. a Shodan-backed lookup), export it as a normal environment variable in the shell Claude Code is running in, or pass it inline when the tool is invoked via `--command`.

---

## 3. Installation

**Step 1 — Install Claude Code.** Standard install, nothing hackingtool-specific.

**Step 2 — Add the marketplace and install the plugin**, from inside a Claude Code chat (slash commands, not shell flags):

```
/plugin marketplace add AKCODEZ/hackingtool-plugin
/plugin install hackingtool@hackingtool-marketplace
```

**Step 3 — Confirm it's active.** Ask something pentest-shaped, e.g. `"recon example.com"`. If the `pentest` skill's description matches your ask, Claude invokes it and runs preflight automatically. There's no shell-level `claude code --plugin list` to check from outside a session — installed plugins are managed from inside Claude Code.

**Step 4 (Windows, one-time, if needed)** — set up a backend before your first real task:

```
wsl --install -d Ubuntu
```

or install Docker Desktop and leave it running.

There is **no `HACKINGTOOL_BACKEND` environment variable**. Backend selection is automatic (`ht_env.py`), and can be overridden per-invocation with `--backend native|wsl|docker` when a tool actually runs.

---

## 4. How It Actually Works

```
Claude Code chat (natural language)
        │
        ▼
`pentest` skill (SKILL.md) — auto-triggered when the ask is pentest/OSINT-shaped
        │
        ├─ Step 0: ht_preflight.py  → verdict: ready | partial | blocked
        ├─ ht_search.py             → look up a tool id in data/tools.json (183 tools)
        └─ ht_run.py <tool_id>      → picks a backend and runs it
                │
                ├─ native (Linux/macOS): bash -lc "<command>"
                ├─ wsl (Windows + a real distro): wsl -d <distro> -- bash -lc "<command>"
                └─ docker (anywhere Docker runs): docker run --rm <image> <args>
                       │
                       └─ ~25 tools map to a purpose-built image
                          (instrumentisto/nmap, projectdiscovery/nuclei,
                          caffix/amass, paoloo/sqlmap, ...); everything
                          else falls back to kalilinux/kali-rolling
        │
        ▼
structured JSON: {status, backend, returncode, stdout, stderr, command, tool, title, ...}
        │
        ▼
Claude reads the JSON and summarizes it in chat
```

What's different from the fictional version of this doc:

- There's no separate "Claude Code API" layer sitting behind the chat — the skill runs as part of the same session, executing the bundled Python scripts through the ordinary Bash tool. You can read and run every one of those scripts yourself.
- Tool invocation isn't hidden behind an opaque marshaling layer — it's three scripts: `ht_preflight.py` (capability check), `ht_search.py` (query the 183-tool index), `ht_run.py` (execute with backend/retry logic).
- Backend selection on Windows specifically distinguishes a *real* WSL distro from Docker Desktop's internal pseudo-distros, and prefers WSL over Docker when both are available (falls back to Docker only if no real distro exists).
- Only one thing is ever pre-blocked: tools flagged `interactive` (they read from stdin mid-run, which a captured pipe can't answer). Everything else is tried first, and only falls back to a "do this yourself" message if the real attempt actually fails.

---

## 5. Basic Usage

No CLI syntax like `claude code --task "..."` exists — you talk to Claude directly. Two runs from this session, verified end-to-end:

**"scan scanme.nmap.org for open ports"** *(scanme.nmap.org is the Nmap project's own public host, explicitly offered for testing — see nmap.org/legal — so it's a genuinely safe target to demo against)*

1. Skill runs `ht_preflight.py` → `verdict: ready`, backend `wsl` (Docker also available).
2. `ht_search.py --q nmap` → resolves to `information_gathering.NMAP`.
3. NMAP has no default `run_commands` in the index (`runnable: false` upstream), so the skill supplies `--command` directly: `ht_run.py information_gathering.NMAP --command "nmap -F scanme.nmap.org"`.
4. First attempt on WSL fails (`nmap` not installed in that distro) → automatically retried on the Docker backend with the `instrumentisto/nmap` override image.
5. Real result: ports 22 (ssh) and 80 (http) open, others closed/filtered — returned as JSON and summarized in chat.

**"run httpx -h"**

Resolves to `information_gathering.Httpx`. WSL attempt fails (`command not found`) → falls back to Docker with `projectdiscovery/httpx`, image is pulled on first use, full `--help` output returned with `status: ok`.

---

## 6. Common Workflows

These are the real named playbooks (`skills/pentest/reference/workflows.md`) — you ask for the outcome in one sentence and Claude walks the chain, tool by tool, narrating results as it goes. There is no single flag that packages a multi-step workflow into one shell invocation like the old `--workflow pentest --output report.html` — that doesn't exist.

| # | Workflow | Input | Tool chain (ids) |
|---|---|---|---|
| 1 | Domain recon | root domain | `Subfinder`/`Amass` → `Httpx` → `Nuclei` → `Ffuf`/`Gobuster` |
| 2 | Username investigation | username | `Sherlock` → `Maigret` → manual pivot |
| 3 | Email investigation | email address | `Holehe` → `Infoga` → pivot to #2 if a name surfaces |
| 4 | Leaked-secrets scan | git repo (URL or local) | `TruffleHog` → `Gitleaks` (cross-reference both) |
| 5 | Web app recon | target URL | `Wafw00f` → `Katana` → `Arjun` → `Ffuf` → `Nuclei` → `TestSSL` → `Sqlmap --batch` |
| 6 | Active Directory enumeration | DC + credentials | `NetExec` → `Impacket` → `Kerbrute` → `Certipy` → `BloodHound` |
| 7 | Cloud misconfig recon | cloud creds/asset | `Prowler` → `ScoutSuite` → `Pacu` |
| 8 | Mobile app static analysis | APK/IPA | `MobSF` → `Frida` → `Objection` |
| 9 | Wifi recon | monitor-mode adapter required | `Airgeddon` / `Wifite` / `Fluxion` / `pixiewps` |
| 10 | Reverse-engineer a binary | binary path | `Radare2` → `Ghidra` → `Binwalk` |
| 11 | Forensic image triage | disk image / memory dump | `Autopsy` → `BulkExtractor` → `Pspy` |

For chaining, intermediate output is conventionally written to `./ht-<date>/<workflow>-<step>.txt` so a multi-tool session stays reproducible.

---

## 7. Best Practices

**Authorization first.** Same rule as always — get written permission, define scope, stay inside it. This has nothing to do with the CLI and doesn't change.

**Incremental scanning.** Ask for the narrow version first (`nmap -F` — top 100 ports) before the wide one. There's no separate "pass 1 / pass 2" flag; you just phrase the ask that way.

**Output handling.** `ht_run.py` always prints JSON to stdout — there's no `--output` or `--preserve-raw` flag. Redirect it yourself, or ask Claude to write/summarize results to a file. The workflow convention above (`./ht-<date>/...`) is the closest thing to a built-in output scheme.

**Tool selection** — driven by the real capability flags in `data/tools.json`, not an invented table:

| Capability flag | Meaning |
|---|---|
| `requires_sudo` | needs elevated privileges (native/WSL auto-retries once with `sudo -n`) |
| `interactive` | reads stdin mid-run — pre-blocked unless you pass `--force` + `--command` |
| `requires_hardware` | needs physical hardware (wifi adapter in monitor mode, etc.) |
| `long_running` | expect to raise `--timeout` |
| `runnable_by_claude` | whether the index ships a ready-to-run command (56 of 183 do) |

**Resource management.** The real lever is `--timeout <seconds>` on `ht_run.py` (default 180). There's no thread-count flag on some outer CLI — pass tool-native flags (e.g. `nuclei -c 50`) as part of the command itself.

**Error handling.** Read `skills/pentest/reference/runtime-fallbacks.md` — every failure mode `ht_run.py` can hit is documented there with the exact JSON shape to expect. There's no `--dry-run` flag; `ht_search.py` (which shows the command without executing it) is the closest equivalent.

---

## 8. Security Considerations

The substance of the original guidance was sound and isn't tied to any fictional CLI — authorization docs, legal review, scope definition, and restricting sensitive tools all still apply as written. What changes is the *mechanics*:

**Secrets management.** There's no `~/.hackingtool/credentials.env` support. Export API keys as environment variables in the shell Claude Code runs in, or reference them explicitly when a tool is invoked via `ht_run.py ... --command`.

**Audit logging.** Not built in. There's no `~/.hackingtool/audit.log` today. If your org needs an audit trail of every tool invocation, that has to be layered on yourself — e.g. by reviewing Claude Code's own session transcripts, or wrapping `ht_run.py` with your own logging before deploying it to a team.

**Sensitive tool restrictions.** Build any allow/deny policy on the real capability flags (`requires_sudo`, `interactive`, `requires_hardware`, `long_running`) and real tool ids — e.g. `sql_injection.Sqlmap`, `active_directory.Impacket`, `wordlist_generator.Hashcat`, `wordlist_generator.JohnTheRipper` — rather than a generic "some tools need more approval" list.

**Docker runs as root inside the container.** Unlike a native/WSL `sudo` retry (which needs a real password unless passwordless sudo is configured), the Docker backend always executes as the container's default user — usually root. Treat Docker-backed invocations of any exploitation-class tool with the same scrutiny you'd give root shell access.

---

## 9. Troubleshooting

Real diagnostics, all plain Python — run from `plugins/hackingtool/`:

```bash
python scripts/ht_preflight.py
python scripts/ht_search.py --q "<keyword>"
python scripts/ht_run.py <tool_id> --backend docker --command "..." --timeout 300
python scripts/ht_index.py --hackingtool-path <path>   # regenerate tools.json from upstream
python scripts/build_readme_table.py                   # regenerate the README tool table
```

There is no `claude code --diagnostic`, `--show-backends`, `--test-tool`, or `--plugin verify` — those don't exist.

### Preflight verdicts

- **`ready`** — proceed; the summary states which backend was picked.
- **`partial`** — some core tools missing and no Docker fallback; recommendations list what to install.
- **`blocked`** — `preferred_backend: fallback` (no WSL, no Docker, on Windows) or critical recommendation unmet. Fix that first.

### `ht_run.py` fallback reasons (`status: "fallback"`, `reason: ...`)

| Reason | Means | Fix |
|---|---|---|
| `no_backend` | No usable Linux runtime | `wsl --install -d Ubuntu`, or start Docker Desktop |
| `not_installed` | Binary missing on the chosen backend | `ht_run.py <id> --install`, or `--docker-image <img>` |
| `no_device` | Tool needs hardware not visible to the backend (e.g. wifi monitor mode) | Passthrough hardware via `usbipd-win`, or run on a machine that has it |
| `sudo_password_needed` | `sudo -n` retry failed — needs an interactive password | Run manually, or configure passwordless sudo for that command |
| `interactive` / `interactive_detected` | Tool reads stdin mid-run | Supply a non-interactive form via `--command` (e.g. `sqlmap --batch`), or run it yourself |
| `no_command` | Index has no `run_commands` for this tool (e.g. NMAP, Masscan) | Supply `--command "<full invocation>"` yourself |
| `timeout` | Ran past `--timeout` (default 180s) | Raise `--timeout`, or narrow the scan |

---

## 10. Examples (real, validated runs)

**Port scan (Docker backend, real target — authorized public test host):**

```
$ python scripts/ht_run.py information_gathering.NMAP --backend docker \
    --command "nmap -F scanme.nmap.org" --timeout 90
```
```json
{
  "status": "ok",
  "backend": "docker",
  "returncode": 0,
  "stdout": "Nmap scan report for scanme.nmap.org (45.33.32.156)\nHost is up (0.055s latency).\n...\n22/tcp open ssh\n80/tcp open http\n...",
  "command": "nmap -F scanme.nmap.org",
  "image": "instrumentisto/nmap",
  "tool": "information_gathering.NMAP",
  "title": "Network Map (nmap)"
}
```

**HTTP probing tool, help output (Docker backend):**

```
$ python scripts/ht_run.py information_gathering.Httpx --backend docker --timeout 60
```
Result: `status: "ok"`, image `projectdiscovery/httpx`, full `httpx -h` usage text returned.

**Same tool, WSL backend, binary missing:**

```
$ python scripts/ht_run.py information_gathering.Httpx --timeout 30
```
```json
{
  "status": "fallback",
  "reason": "not_installed",
  "command": "httpx -h",
  "message": "Runtime fell back (not_installed). Manual run needed:\n\n  httpx -h\n\nTool binary not found. Try: `python ht_run.py information_gathering.Httpx --install`...",
  "diagnostic": {"backend": "wsl", "returncode": 127, "stderr": "bash: line 1: httpx: command not found\n"}
}
```

Note the difference from a hypothetical `claude code --task` command: these are plain scripts you (or Claude, via Bash) invoke directly. Nothing about them requires Claude in the loop — you can script `ht_run.py` yourself outside of Claude Code if you want a repeatable, non-interactive pipeline.

---

## Summary Checklist

Before conducting security tests with this plugin:

- [ ] Written authorization from the system owner
- [ ] Defined scope (targets, timing, intensity)
- [ ] Legal review completed
- [ ] Secure handling worked out for anything the tools output
- [ ] Preflight run and verdict is `ready` (or `partial` with accepted limitations)
- [ ] Team knows there's no built-in audit log or credential vault — plan for those separately if needed

---

**Sources:** `README.md`, `plugins/hackingtool/.claude-plugin/plugin.json`, `plugins/hackingtool/skills/pentest/SKILL.md`, `plugins/hackingtool/skills/pentest/reference/workflows.md`, `plugins/hackingtool/skills/pentest/reference/runtime-fallbacks.md`, and live script runs (`ht_preflight.py`, `ht_search.py`, `ht_run.py`) in this session.
