#!/usr/bin/env bash
# Run the complete local/CI suite without importing script-style legacy tests.
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3.12}"
NODE_BIN="${NODE_BIN:-node}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"

python_tests=(
  tests/test_config_invariants.py
  tests/test_scanned_ledger.py
  tests/test_public_only.py
  tests/test_onboard_safety.py
  tests/test_scan_resilience.py
  tests/test_validate_refresh.py
  tests/test_req14_state.py
  tests/test_req14_discovery.py
  tests/test_req14_transports.py
  tests/test_req14_scanner.py
  tests/test_req14_evidence_content.py
  tests/test_req14_content_materialization.py
  tests/test_req14_scan_attempts.py
  tests/test_req14_resume_control.py
  tests/test_req14_phase8_tail_control.py
  tests/test_req14_historical_scan_usage.py
  tests/test_req14_content_successor.py
  tests/test_req14_citations.py
  tests/test_req14_publication.py
  tests/test_req14_portfolio.py
  tests/test_req14_pipeline.py
  tests/test_req14_successor.py
  tests/test_req14_safety.py
  tests/test_req14_acceptance.py
  tests/test_req14_evidence_contract.py
)

for test_file in "${python_tests[@]}"; do
  "$PYTHON_BIN" "$test_file"
done

"$NODE_BIN" tests/test_req14_frontend.js
"$NODE_BIN" --check web/js/data-v2.js
"$NODE_BIN" --check web/js/library.js
"$NODE_BIN" --check web/js/home.js
