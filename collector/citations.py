"""Retired V1 citation writer compatibility tombstone.

REQ-14 citation collection lives in :mod:`collector.citation_pipeline`; its
bounded public-source parser lives in :mod:`collector.citation_extract`.
Keeping this module executable only as an explicit refusal prevents old
automation from writing V1 artifacts outside the task journal and atomic V2
publication transaction.
"""

from __future__ import annotations

import sys


def run(*_args, **_kwargs):
    raise RuntimeError(
        "collector.citations.run is retired; use "
        "`python3.12 -m collector.cli refresh`"
    )


def main(argv):
    del argv
    print(
        "ERROR: collector.citations is retired; use "
        "`python3.12 -m collector.cli refresh` "
        "(or `onboard`/`reconcile`)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
