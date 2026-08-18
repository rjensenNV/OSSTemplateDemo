"""Compatibility tombstone for the retired V1 partial-snapshot merger.

REQ-14 onboarding is stateful and publication-safe.  Keeping the former
merge-not-wipe implementation below an early return made dead collection code
look callable and allowed it to rot.  The pre-REQ-14 tag preserves that
implementation for forensic rollback; this module now does only one thing:
fail with the supported replacement command.
"""

from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Retired V1 CUDA-X onboarding command"
    )
    parser.add_argument("--libraries")
    parser.add_argument("--out")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--from-cache", action="store_true")
    parser.add_argument("--max-per-lib")
    parser.parse_known_args(argv)
    print(
        "ERROR: collector.onboard_merge is retired by REQ-14; use "
        "`python3.12 -m collector.cli onboard --libraries ID ...`",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
