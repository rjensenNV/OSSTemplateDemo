"""Bounded real-repository smoke scan that never writes data/."""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collector.config import LIBRARIES
from collector.scanner_v2 import ScanTask, scan_many

DEFAULT_REPOS = [
    "Fsoft-AIC/Mamba-token-dynamic",
    "EXPmaster/nqs",
    "2410030364-vineeth/Intelligent-doubt-clustering-for-online-class",
]


def _public_head(full_name, timeout):
    result = subprocess.run(
        [
            "git",
            "ls-remote",
            "https://github.com/%s.git" % full_name,
            "HEAD",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=min(float(timeout), 60.0),
        check=False,
    )
    fields = result.stdout.split()
    if result.returncode != 0 or not fields or not re.fullmatch(
        r"[0-9a-fA-F]{40}", fields[0]
    ):
        raise RuntimeError("public Git HEAD could not be resolved")
    return fields[0].lower()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", default=",".join(DEFAULT_REPOS))
    parser.add_argument("--out", default="smoke-output.json")
    parser.add_argument("--repo-timeout", type=float, default=180)
    args = parser.parse_args(argv)

    repos = [item.strip() for item in args.repos.split(",") if item.strip()]
    output = {
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repos": [],
    }
    failures = 0
    with tempfile.TemporaryDirectory(prefix="cudax-v2-smoke-") as temporary:
        cache = Path(temporary) / "git-cache"
        for index, full_name in enumerate(repos, 1):
            print(
                "== smoke %d/%d: %s =="
                % (index, len(repos), full_name),
                flush=True,
            )
            try:
                head = _public_head(full_name, args.repo_timeout)
                outcomes = scan_many(
                    [
                        ScanTask(
                            full_name,
                            head,
                            tuple(lib["id"] for lib in LIBRARIES),
                        )
                    ],
                    LIBRARIES,
                    cache,
                    workers=1,
                    repo_timeout=args.repo_timeout,
                    cache_target_bytes=8 * 1024**3,
                    cache_hard_bytes=12 * 1024**3,
                )
                outcome = outcomes[0]
                result = outcome.result
                if outcome.status == "error" or result is None:
                    status, failures = "error", failures + 1
                    libraries = {}
                elif not result or not result.get("libraries"):
                    status, libraries = "clean-reject", {}
                else:
                    status = "detected"
                    libraries = result.get("libraries", {})
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                status, failures = "error", failures + 1
                libraries = {}
                print("  bounded V2 scanner error: %s" % exc, flush=True)
            print(
                "  result: %s (%s)"
                % (
                    status,
                    ", ".join(sorted(libraries)) or "no libraries",
                )
            )
            output["repos"].append({
                "full_name": full_name,
                "status": status,
                "libraries": {
                    key: {
                        "classification": value.get("classification"),
                        "first_integration": value.get(
                            "first_integration"
                        ),
                    }
                    for key, value in libraries.items()
                },
            })

    with open(args.out, "w") as fh:
        json.dump(output, fh, indent=2)
    print("wrote %s" % args.out)
    if failures:
        print("ERROR: %d smoke repo(s) failed" % failures)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
