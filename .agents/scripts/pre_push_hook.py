#!/usr/bin/env python3
"""Pre-push / verification lifecycle hook for CapLLM.

Supports both:
1. Antigravity PreToolUse hook protocol (receives JSON on stdin, outputs decision JSON on stdout).
2. Standalone CLI execution (runs checks directly and exits with 0 or 1).
"""

import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_verification() -> tuple[bool, str]:
    """Runs git diff --check and python -m unittest discover tests -v.

    Returns (success, message).
    """
    # 1. Check git formatting
    try:
        diff_proc = subprocess.run(
            ["git", "diff", "--check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if diff_proc.returncode != 0:
            err_msg = diff_proc.stdout or diff_proc.stderr or "git diff --check failed"
            return False, f"Git formatting issues detected:\n{err_msg}"
    except Exception as exc:
        return False, f"Failed to execute git diff --check: {exc}"

    # 2. Run unit tests
    try:
        test_proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "tests", "-v"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if test_proc.returncode != 0:
            err_msg = test_proc.stderr or test_proc.stdout or "Unit tests failed"
            return False, f"Unit tests failed (exit code {test_proc.returncode}):\n{err_msg}"
    except Exception as exc:
        return False, f"Failed to run unit tests: {exc}"

    return True, "All pre-push verification checks passed cleanly."


def main() -> None:
    # Check if called via Antigravity PreToolUse hook (JSON on stdin)
    is_hook_input = False
    payload = {}

    if not sys.stdin.isatty():
        try:
            stdin_content = sys.stdin.read().strip()
            if stdin_content:
                payload = json.loads(stdin_content)
                is_hook_input = "toolCall" in payload
        except Exception:
            is_hook_input = False

    if is_hook_input:
        tool_call = payload.get("toolCall", {})
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("args", {})
        command_line = tool_args.get("CommandLine", "").strip().lower()

        # Only intercept push or commit actions
        needs_check = (
            "git push" in command_line
            or "git commit" in command_line
        )

        if not needs_check:
            print(json.dumps({"decision": "allow"}))
            sys.exit(0)

        # Run verification checks
        success, msg = run_verification()
        if success:
            print(json.dumps({"decision": "allow"}))
            sys.exit(0)
        else:
            print(json.dumps({
                "decision": "deny",
                "reason": msg,
            }))
            sys.exit(0)
    else:
        # Standalone execution
        print(f"Running pre-push verification checks in {REPO_ROOT}...")
        success, msg = run_verification()
        print(msg)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
