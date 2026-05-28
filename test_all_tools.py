#!/usr/bin/env python3
"""Mass-test every tool in the index using hackingtool_run.

This script loads tools.json and attempts to invoke every tool via the
plugin's internal executor (not through MCP), printing results to stdout.
"""

import json
import subprocess
import sys
import os
from datetime import datetime

# Paths
SCRIPT_DIR = "/run/media/dan/EXTRA/hackingtool-plugin/plugins/hackingtool/scripts"
DATA_DIR = "/run/media/dan/EXTRA/hackingtool-plugin/plugins/hackingtool/data"
INDEX_FILE = os.path.join(DATA_DIR, "tools.json")
EXECUTOR_SCRIPT = os.path.join(SCRIPT_DIR, "ht_executor.py")

# Load index
with open(INDEX_FILE) as f:
    data = json.load(f)

all_tools = data.get("tools", [])
total = len(all_tools)

print(f"{'='*70}")
print(f"MASS TOOL TEST — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
print(f"Testing {total} tools from index...")
print(f"{'='*70}\n")

results = []

for i, tool in enumerate(all_tools, 1):
    tool_id = tool["id"]
    title = tool.get("title", "?")
    runnable = tool.get("capabilities", {}).get("runnable", False)

    print(f"[{i}/{total}] Testing {tool_id} ({title})...", end=" ")

    # Skip tools that are explicitly not runnable — record as N/A
    if not runnable:
        print("⏭️  SKIPPED (not marked runnable)")
        results.append({"id": tool_id, "status": "skipped", "reason": "not runnable"})
        continue

    # Attempt to run the tool via ht_executor.py --dry-run
    try:
        result = subprocess.run(
            [
                "python3", EXECUTOR_SCRIPT,
                "--tool-id", tool_id,
                "--dry-run"   # simulate only — no actual execution
            ],
            capture_output=True, text=True, timeout=10, cwd=DATA_DIR
        )

        if result.returncode == 0:
            print("✅ PASS")
            results.append({"id": tool_id, "status": "pass"})
        else:
            error = (result.stderr or result.stdout).strip()[:200]
            print(f"❌ FAIL — {error}")
            results.append({"id": tool_id, "status": "fail", "error": error})

    except subprocess.TimeoutExpired:
        print("⏱️  TIMEOUT")
        results.append({"id": tool_id, "status": "timeout"})
    except Exception as e:
        print(f"💥 ERROR — {e}")
        results.append({"id": tool_id, "status": "error", "message": str(e)})

# Summary
print(f"\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")

passes = [r for r in results if r["status"] == "pass"]
fails = [r for r in results if r["status"] in ("fail", "error")]
skipped = [r for r in results if r["status"] == "skipped"]
timeouts = [r for r in results if r["status"] == "timeout"]

print(f"Total tools:     {total}")
print(f"Runnable tested: {len(passes) + len(fails) + len(timeouts)}")
print(f"  ✅ Passed:     {len(passes)}")
print(f"  ❌ Failed:     {len(fails)}")
print(f"  ⏱️  Timeout:   {len(timeouts)}")
print(f"  ⏭️  Skipped:   {len(skipped)}  (not marked runnable)")

if fails or timeouts:
    print(f"\n{'─'*70}")
    print("FAILED / TIMEOUT TOOLS:")
    print(f"{'─'*70}")
    for r in fails + timeouts:
        reason = r.get("error") or r.get("message", "")
        print(f"  • {r['id']}: {reason[:100]}")

# Write JSON report
report_path = os.path.join(DATA_DIR, "test_report.json")
with open(report_path, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n📋 Full report saved to: {report_path}")

sys.exit(1 if fails else 0)