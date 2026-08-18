#!/bin/bash
# Maintainer-operated local data refresh — the supported weekly collection driver.
# This script fast-forwards main, runs the stateful collector (including
# citations), and validates the generated local artifacts. Generated data is
# ignored by this source repository and is never committed or pushed here.
# Repository CI tests source only and never collects.
export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
REPO="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$REPO" || exit 1
MODE="${1:-}"
case "$MODE" in
  "") exec >>"$REPO/refresh.log" 2>&1 ;;
  "--check") ;;
  *)
    echo "ERROR: unknown argument: $MODE (supported: --check)" >&2
    exit 2
    ;;
esac
echo "===================== refresh start $(date) ====================="

TOK="$(gh auth token 2>/dev/null)"
if [ -z "$TOK" ]; then
  echo "ERROR: could not get GitHub token from gh (login/keychain unavailable?)"
  exit 1
fi
export GITHUB_TOKEN="$TOK"

if [ "$(git branch --show-current)" != "main" ]; then
  echo "ERROR: refresh checkout must be on main"
  exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  echo "ERROR: worktree must be completely clean before refresh (including untracked files)"
  exit 1
fi
if ! git pull --ff-only --quiet origin main; then
  echo "ERROR: could not fast-forward main before refresh"
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))'; then
  echo "ERROR: refresh requires Homebrew Python 3.12"
  exit 1
fi
if [ -s "$HOME/.config/openalex-api-key" ] &&
   [ "$(stat -f '%Lp' "$HOME/.config/openalex-api-key")" != "600" ]; then
  echo "ERROR: ~/.config/openalex-api-key must have mode 600"
  exit 1
fi

if [ "$MODE" = "--check" ]; then
  if ! python3 -m collector.cli --help >/dev/null; then
    echo "ERROR: collector entry point is not runnable with python3"
    exit 1
  fi
  if ! python3 -m collector.cli plan --json >/dev/null; then
    echo "ERROR: REQ-14 read-only planner is not runnable"
    exit 1
  fi
  if ! python3 -m collector.cli validate --help >/dev/null; then
    echo "ERROR: V2 validator entry point is not runnable"
    exit 1
  fi
  if ! python3 -m collector.validate_refresh --help >/dev/null; then
    echo "ERROR: retained refresh anomaly gate is not runnable"
    exit 1
  fi
  if [ ! -s "$HOME/.config/openalex-api-key" ] && [ -z "${OPENALEX_API_KEY:-}" ]; then
    echo "ERROR: OpenAlex API key is unavailable"
    exit 1
  fi
  echo "refresh readiness check passed (no collection performed)"
  exit 0
fi

# Bounded stateful weekly refresh. It never silently becomes a full scan: when
# fingerprints or missing state imply unbounded work it exits with the explicit
# attended reconcile command. The first REQ-14 reconcile is owner-triggered:
#   python3 -m collector.cli plan --mode reconcile
#   python3 -m collector.cli reconcile --confirm-full
if ! python3 -m collector.cli refresh; then
  echo "ERROR: collector run failed"; exit 1
fi

if ! python3 -m collector.cli validate; then
  echo "ERROR: generated local data failed validation"
  exit 1
fi

echo "refresh done $(date)"
echo "generated artifacts remain local under data/ and are ignored by Git"
