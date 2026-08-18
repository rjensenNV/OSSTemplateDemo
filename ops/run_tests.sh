#!/usr/bin/env bash
# Run the complete local/CI suite without importing script-style legacy tests.
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3.12}"
NODE_BIN="${NODE_BIN:-node}"

python_tests=(
  test_config_invariants.py
  test_scanned_ledger.py
  test_public_only.py
  test_onboard_safety.py
  test_scan_resilience.py
  test_validate_refresh.py
  test_req14_state.py
  test_req14_discovery.py
  test_req14_transports.py
  test_req14_scanner.py
  test_req14_evidence_content.py
  test_req14_content_materialization.py
  test_req14_scan_attempts.py
  test_req14_resume_control.py
  test_req14_phase8_tail_control.py
  test_req14_historical_scan_usage.py
  test_req14_content_successor.py
  test_req14_citations.py
  test_req14_publication.py
  test_req14_portfolio.py
  test_req14_pipeline.py
  test_req14_successor.py
  test_req14_safety.py
  test_req14_acceptance.py
  test_req14_evidence_contract.py
)

for test_file in "${python_tests[@]}"; do
  "$PYTHON_BIN" "$test_file"
done

"$NODE_BIN" test_req14_frontend.js
"$NODE_BIN" --check web/js/data-v2.js
"$NODE_BIN" --check web/js/library.js
"$NODE_BIN" --check web/js/home.js
