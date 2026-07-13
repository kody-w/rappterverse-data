#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Command-line entry point for trusted public-data governance checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

try:
    from .policy import PolicyConfigurationError, PolicySet
    from .validator import (
        Change,
        GovernanceValidator,
        collect_git_changes,
        resolve_git_revision,
    )
except ImportError:
    from policy import PolicyConfigurationError, PolicySet
    from validator import (
        Change,
        GovernanceValidator,
        collect_git_changes,
        resolve_git_revision,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a public-data pull request with trusted base policy."
    )
    parser.add_argument("--root", default=".", help="candidate repository checkout")
    parser.add_argument(
        "--policy-root",
        help="trusted policy directory (defaults to <root>/policies)",
    )
    parser.add_argument(
        "--base",
        help="base commit or ref (defaults to GITHUB_BASE_SHA, then HEAD^)",
    )
    parser.add_argument("--head", default="HEAD", help="candidate commit or ref")
    parser.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="validate an added file without calculating a Git diff",
    )
    parser.add_argument(
        "--diff-bytes",
        type=int,
        default=0,
        help="raw diff bytes when --changed-file is used",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="redacted result format",
    )
    return parser


def _default_base(root: Path) -> str:
    environment_base = os.environ.get("GITHUB_BASE_SHA")
    if environment_base:
        return environment_base
    process = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^"],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if process.returncode != 0:
        raise ValueError("a base revision is required")
    return "HEAD^"


def _emit_fatal(output_format: str, code: str, message: str) -> None:
    if output_format == "json":
        print(
            json.dumps(
                {
                    "ok": False,
                    "findingCount": 1,
                    "findings": [
                        {
                            "severity": "error",
                            "code": code,
                            "path": ".",
                            "line": 0,
                            "column": 0,
                            "message": message,
                        }
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    else:
        print(f"ERROR {code} .: {message}")


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.root).resolve()
    policy_root = Path(args.policy_root).resolve() if args.policy_root else root / "policies"
    try:
        policies = PolicySet.load(policy_root)
        if args.changed_file:
            changes = [Change("A", path) for path in args.changed_file]
            diff_bytes = args.diff_bytes
            base = args.base
        else:
            base = args.base or _default_base(root)
            expected_head = resolve_git_revision(root, args.head)
            checked_out_head = resolve_git_revision(root, "HEAD")
            if expected_head != checked_out_head:
                raise ValueError("candidate checkout does not match the requested head")
            changes, diff_bytes = collect_git_changes(root, base, args.head)
        validator = GovernanceValidator(root, policies, base_revision=base)
        report = validator.validate(changes, diff_bytes=diff_bytes)
    except PolicyConfigurationError:
        _emit_fatal(
            args.format,
            "POLICY_CONFIGURATION",
            "trusted governance policy is unavailable or unsafe",
        )
        return 2
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        _emit_fatal(
            args.format,
            "VALIDATION_PRECONDITION",
            "governance validation could not establish trusted inputs",
        )
        return 2
    except RecursionError:
        _emit_fatal(
            args.format,
            "JSON_DEPTH",
            "JSON nesting exceeds the deterministic maximum depth",
        )
        return 2
    except Exception:
        _emit_fatal(
            args.format,
            "VALIDATION_INTERNAL",
            "governance validation stopped safely",
        )
        return 2

    if args.format == "json":
        print(json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":")))
    elif report.ok:
        print(f"governance: PASS ({len(changes)} changed files)")
    else:
        for finding in report.findings:
            location = finding.path
            if finding.line:
                location += f":{finding.line}"
                if finding.column:
                    location += f":{finding.column}"
            print(f"{finding.severity.upper()} {finding.code} {location}: {finding.message}")
        print(f"governance: FAIL ({len(report.findings)} redacted findings)")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
