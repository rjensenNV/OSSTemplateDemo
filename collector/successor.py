"""Audited discovery-task carry-forward for reviewed incident remediation.

This module never executes discovery. A scope-reduction successor requires an
unchanged network executable and a strict task subset. A transport-policy
successor requires the exact task universe, payloads, evidence fingerprints,
budgets, and base release while recording both old and new executable/source
hashes. The Phase 8 cohort path derives a strict certified product subset,
proves per-task network semantics stayed exact across downstream partial-release
changes, and preflights every hard budget. Every path revalidates inherited
documents and records durable task-level lineage before the coordinator resumes.
"""

from __future__ import annotations

import ast
import copy
import datetime
import hashlib
import json
import math
import shutil
import subprocess
import uuid
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import config
from .discovery import (
    github_query_fingerprint,
    query_packs,
    signal_specs,
    sourcegraph_query_fingerprint,
)
from .fingerprints import FingerprintManifest, fingerprint
from .pipeline import (
    METADATA_BATCH_SIZE,
    NO_LIVE_V2_RELEASE,
    PipelineError,
    RunBudgets,
    _assert_discovery_task_result,
    _canonical_metadata_identity_indexes,
    _canonical_repository_identity,
    _durable_discovery_request_usage,
    _discovery_observation_excluded,
    _discovery_result_from_task_result,
    _graphql_journal_budget,
    _legacy_candidates,
    _library_fp_values,
    _metadata_input_context_sha256,
    _metadata_lookup_universe_sha256,
    _metadata_result_from_task_result,
    _metadata_result_to_task_result,
    _network_task_source_sha256,
    _record_coverage,
    _repository_excluded,
    _resolve_canonical_observation_identity,
    _library_repository_excluded,
    _state_candidates,
)
from .github_client import RepositoryLookup
from .planner import build_plan
from .state import (
    StateDB,
    _scan_attempt_usage_values,
    canonical_json,
)


SUCCESSOR_CONTRACT_VERSION = 1
TRANSPORT_SUCCESSOR_CONTRACT_VERSION = 3
COHORT_SUCCESSOR_CONTRACT_VERSION = 2
COHORT_RECOVERY_CONTRACT_VERSION = 1
HISTORICAL_SCAN_USAGE_CONTRACT_VERSION = 2
_SCAN_USAGE_FLOAT_FIELDS = (
    "seconds",
    "current_tree_triage_seconds",
    "history_dating_seconds",
    "analysis_seconds",
)
_SCAN_USAGE_COUNT_FIELDS = (
    "git_subprocess_count",
    "network_clone_count",
    "network_fetch_count",
    "network_materialized_bytes",
)
_HISTORICAL_SCAN_EXACT_METHODS = frozenset({
    "scan-attempt-ledger-v1",
    "pre-v5-task-result-v1",
})
_HISTORICAL_SCAN_CONSERVATIVE_METHOD = (
    "pre-v5-public-cache-disk-upper-v1"
)
_HISTORICAL_SCAN_UNKNOWN_METHOD = (
    "owner-authorized-irreconstructible-v1"
)
_CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY = {
    "version": 1,
    "policy_id": "phase8-owner-checkpoint-continuation-2026-07-31",
    "predecessor_run_id": "20260731T052650Z-cd66b01e",
    "expected_attempt_count": 14,
    "required_status": "interrupted",
    "required_error_code": (
        "run_abandoned:strict_notebook_metadata_and_deadline_"
        "classification_remediation"
    ),
    "accounting": "usage_unknown_never_zero",
}
_LEGACY_NETWORK_TASK_PATHS = (
    "collector/pipeline.py",
    "collector/github_client.py",
    "collector/discovery/base.py",
    "collector/discovery/github_search.py",
    "collector/discovery/query_plan.py",
    "collector/discovery/sourcegraph.py",
)
_CURRENT_NETWORK_TASK_PATHS = (
    "collector/pipeline.py",
    "collector/http_transport.py",
    "collector/github_client.py",
    "collector/discovery/base.py",
    "collector/discovery/github_search.py",
    "collector/discovery/query_plan.py",
    "collector/discovery/sourcegraph.py",
)
_TRANSPORT_POLICY_ALLOWED_PATHS = frozenset(
    {
        ".gitlab-ci.yml",
        "AGENTS.md",
        "collector/cli.py",
        "collector/discovery/github_search.py",
        "collector/http_transport.py",
        "collector/pipeline.py",
        "collector/state.py",
        "collector/state_migrations.py",
        "collector/successor.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_discovery.py",
        "test_req14_state.py",
        "test_req14_successor.py",
        "test_req14_transports.py",
    }
)
_COHORT_SUCCESSOR_ALLOWED_PATHS = frozenset(
    {
        ".gitlab-ci.yml",
        "AGENTS.md",
        "collector/catalog.py",
        "collector/cli.py",
        "collector/evidence_content.py",
        "collector/github_client.py",
        "collector/pipeline.py",
        "collector/planner.py",
        "collector/portfolio.py",
        "collector/publish_v2.py",
        "collector/repo_cache.py",
        "collector/req14_evidence_contract.json",
        "collector/scan.py",
        "collector/scanner_v2.py",
        "collector/state.py",
        "collector/state_migrations.py",
        "collector/successor.py",
        "collector/triage.py",
        "collector/validate_v2.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "docs/REQ14-PHASE8-READINESS.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_portfolio.py",
        "test_req14_publication.py",
        "test_req14_scanner.py",
        "test_req14_safety.py",
        "test_req14_state.py",
        "test_req14_successor.py",
        "test_req14_acceptance.py",
        "test_req14_frontend.js",
        "test_req14_discovery.py",
        "test_req14_content_materialization.py",
        "test_req14_content_successor.py",
        "test_req14_evidence_content.py",
        "test_req14_evidence_contract.py",
        "test_req14_historical_scan_usage.py",
        "test_req14_scan_attempts.py",
        "web/js/data-v2.js",
        "web/js/home.js",
    }
)
_SCAN_RUNTIME_REMEDIATION_PROFILES = {
    "checkpoint-continuation-and-certified-reuse": {
        "collector/cli.py": (
            "_prepare_phase8_cohort_recovery_successor",
            "build_parser",
        ),
        "collector/evidence_content.py": (
            "_bounded_json_recovery",
            "_surface_document",
            "parse_notebook_surfaces",
        ),
        "collector/pipeline.py": (
            "<module>.Assign:9",
            "CollectorPipeline._runtime_report",
            "CollectorPipeline._scan",
            "CollectorPipeline.run",
            "_combine_scan_attempt_usage",
            "_validate_reviewed_execution_contract",
        ),
        "collector/repo_cache.py": (
            "RepoCache._materialize_relevant_lfs",
        ),
        "collector/successor.py": (
            "<module>.Assign:10",
            "<module>.Assign:11",
            "<module>.Assign:12",
            "<module>.Assign:13",
            "<module>.Assign:14",
            "<module>.Assign:15",
            "<module>.Assign:16",
            "<module>.Assign:17",
            "<module>.Assign:18",
            "<module>.Assign:19",
            "<module>.Assign:20",
            "<module>.Assign:21",
            "<module>.Assign:22",
            "<module>.Assign:23",
            "<module>.Assign:24",
            "<module>.Assign:25",
            "<module>.Assign:26",
            "<module>.Assign:27",
            "<module>.Assign:28",
            "<module>.Assign:5",
            "<module>.ImportFrom:8",
            "_certify_completed_scan_checkpoint",
            "_cohort_recovery_preflight",
            "_cohort_successor_source_audit",
            "_derive_historical_scan_usage",
            "_is_content_diagnostic_candidate",
            "_materialize_certified_scan_rows",
            "_validate_certified_scan_checkpoint_contract",
            "_validate_historical_scan_proof_row",
            "_validate_historical_scan_usage_contract",
            "prepare_phase8_cohort_successor",
        ),
    },
    "git-lfs-checkout-and-content-availability": {
        "collector/scan.py": ("_git_auth_env",),
        "collector/scanner_v2.py": ("_scan_error_contract",),
        "collector/triage.py": (
            "_TextInventory.__init__",
            "_is_git_lfs_pointer",
            "_tracked_text_inventory",
            "triage_tree",
        ),
    },
    "git-root-rename-boundary-and-timeout-classification": {
        "collector/scan.py": ("_rename_predecessors",),
        "collector/scanner_v2.py": ("_scan_error_contract",),
    },
    "generated-evidence-band-exclusion": {
        "collector/scan.py": (
            "_has_token_reference",
            "_scan_repo_once",
        ),
    },
    "generated-lfs-evidence-relevance": {
        "collector/scan.py": (
            "_has_token_reference",
            "_is_generated_evidence_path",
            "_scan_repo_once",
        ),
        "collector/triage.py": (
            "_eligible",
            "_is_binary_media_path",
            "_is_generated_evidence_path",
            "_own_source",
            "_tracked_text_inventory",
        ),
    },
    "copied-orbslam-workspace-provenance": {
        "collector/triage.py": (
            "_embedded_project_roots",
            "_inside_embedded_project",
        ),
    },
    "worker-deadline-and-notebook-bom": {
        "collector/scan.py": (
            "_notebook_source_surfaces",
        ),
        "collector/scanner_v2.py": (
            "scan_many",
        ),
        "collector/triage.py": (
            "_notebook_surfaces",
        ),
    },
    "clone-integrity-timeout-policy": {
        "collector/scan.py": (
            "_verify_clone",
        ),
    },
    "strict-notebook-recovery-and-deadline-propagation": {
        "collector/evidence_content.py": (
            "_bounded_json_recovery",
            "_surface_document",
            "parse_notebook_surfaces",
        ),
        "collector/repo_cache.py": (
            "RepoCache._materialize_relevant_lfs",
        ),
        "collector/successor.py": (
            "<module>.Assign:14",
            "<module>.Assign:15",
            "_cohort_successor_source_audit",
            "_is_content_diagnostic_candidate",
        ),
    },
}
_SCAN_RUNTIME_REMEDIATION_REQUIRED_PATHS = {
    "checkpoint-continuation-and-certified-reuse": frozenset({
        "collector/cli.py",
        "collector/evidence_content.py",
        "collector/pipeline.py",
        "collector/repo_cache.py",
        "collector/successor.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "docs/REQ14-V2-REVISION.md",
        "test_req14_content_successor.py",
        "test_req14_evidence_content.py",
        "test_req14_historical_scan_usage.py",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "git-lfs-checkout-and-content-availability": frozenset({
        "collector/scan.py",
        "collector/scanner_v2.py",
        "collector/successor.py",
        "collector/triage.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "git-root-rename-boundary-and-timeout-classification": frozenset({
        "collector/scan.py",
        "collector/scanner_v2.py",
        "collector/successor.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "generated-evidence-band-exclusion": frozenset({
        "collector/scan.py",
        "collector/successor.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "generated-lfs-evidence-relevance": frozenset({
        "collector/scan.py",
        "collector/successor.py",
        "collector/triage.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "copied-orbslam-workspace-provenance": frozenset({
        "collector/successor.py",
        "collector/triage.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "worker-deadline-and-notebook-bom": frozenset({
        "collector/scan.py",
        "collector/scanner_v2.py",
        "collector/successor.py",
        "collector/triage.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "clone-integrity-timeout-policy": frozenset({
        "collector/scan.py",
        "collector/successor.py",
        "docs/Documentation.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
    "strict-notebook-recovery-and-deadline-propagation": frozenset({
        "collector/evidence_content.py",
        "collector/repo_cache.py",
        "collector/successor.py",
        "docs/Documentation.md",
        "docs/PROJECT-CONTEXT.md",
        "docs/REQ14-V2-REVISION.md",
        "ops/req14_detector_fingerprints.json",
        "test_req14_evidence_content.py",
        "test_req14_pipeline.py",
        "test_req14_scanner.py",
        "test_req14_successor.py",
    }),
}
_PREFLIGHT_REUSE_REMEDIATION_PROFILE = {
    "collector/cli.py": (
        "_prepare_phase8_cohort_recovery_successor",
        "build_parser",
    ),
    "collector/successor.py": (
        "<module>.Assign:11",
        "<module>.Assign:12",
        "<module>.Assign:13",
        "<module>.ImportFrom:9",
        "_cohort_candidate_preflight",
        "_cohort_recovery_preflight",
        "_cohort_successor_source_audit",
        "prepare_phase8_cohort_successor",
    ),
}
_CONTENT_DIAGNOSTIC_REMEDIATION_KIND = (
    "evidence-content-and-attempt-diagnostics"
)
_CONTENT_DIAGNOSTIC_ADDED_PATHS = frozenset({
    "collector/evidence_content.py",
})
_CONTENT_DIAGNOSTIC_PRODUCTION_PATHS = frozenset({
    "collector/evidence_content.py",
    "collector/pipeline.py",
    "collector/planner.py",
    "collector/repo_cache.py",
    "collector/scan.py",
    "collector/scanner_v2.py",
    "collector/state.py",
    "collector/state_migrations.py",
    "collector/successor.py",
    "collector/triage.py",
})
_CONTENT_DIAGNOSTIC_SUPPORT_PATHS = frozenset({
    ".gitlab-ci.yml",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "docs/REQ14-V2-REVISION.md",
    "ops/req14_detector_fingerprints.json",
    "test_req14_content_materialization.py",
    "test_req14_content_successor.py",
    "test_req14_evidence_content.py",
    "test_req14_evidence_contract.py",
    "test_req14_historical_scan_usage.py",
    "test_req14_acceptance.py",
    "test_req14_pipeline.py",
    "test_req14_scan_attempts.py",
    "test_req14_scanner.py",
    "test_req14_state.py",
    "test_req14_successor.py",
})
_CONTENT_DIAGNOSTIC_REQUIRED_SUPPORT_PATHS = frozenset({
    ".gitlab-ci.yml",
    "docs/Documentation.md",
    "docs/PROJECT-CONTEXT.md",
    "docs/REQ14-V2-REVISION.md",
    "ops/req14_detector_fingerprints.json",
    "test_req14_content_materialization.py",
    "test_req14_content_successor.py",
    "test_req14_evidence_content.py",
    "test_req14_historical_scan_usage.py",
    "test_req14_acceptance.py",
    "test_req14_pipeline.py",
    "test_req14_scan_attempts.py",
    "test_req14_scanner.py",
    "test_req14_state.py",
    "test_req14_successor.py",
})
# This exact AST-node delta is separate from the older, incident-specific
# scanner profiles so those contracts cannot be broadened retroactively.
_CONTENT_DIAGNOSTIC_REMEDIATION_PROFILE = {
    "collector/evidence_content.py": (
        "<module>.Assign:1",
        "<module>.Assign:2",
        "<module>.Assign:3",
        "<module>.Assign:4",
        "<module>.Assign:5",
        "<module>.Assign:6",
        "<module>.Expr:1",
        "<module>.Import:1",
        "<module>.Import:2",
        "<module>.Import:3",
        "<module>.Import:4",
        "<module>.ImportFrom:1",
        "<module>.ImportFrom:2",
        "LFSPointer.<class>",
        "NotebookEvidenceError.<class>",
        "NotebookSurfaces.<class>",
        "_cells",
        "_contains_authored_damage",
        "_surface_document",
        "_validate_damage_location",
        "parse_lfs_pointer",
        "parse_notebook_surfaces",
    ),
    "collector/pipeline.py": (
        "<module>.Assign:10",
        "<module>.Assign:8",
        "<module>.Assign:9",
        "<module>.Import:10",
        "<module>.Import:11",
        "<module>.Import:12",
        "<module>.Import:13",
        "<module>.Import:14",
        "<module>.Import:15",
        "<module>.Import:16",
        "<module>.Import:6",
        "<module>.Import:7",
        "<module>.Import:8",
        "<module>.Import:9",
        "CollectorPipeline.__init__",
        "CollectorPipeline._runtime_report",
        "CollectorPipeline._scan",
        "CollectorPipeline.run",
        "_canonical_sha256",
        "_combine_scan_attempt_usage",
        "_enforce_scan_attempt_budgets",
        "_historical_scan_usage_for_run",
        "_scan_attempt_usage_for_run",
        "_validate_historical_scan_usage",
        "_validate_reviewed_execution_contract",
    ),
    "collector/planner.py": (
        "<module>.Assign:2",
        "_scanner_semantic_source_sha256",
    ),
    "collector/repo_cache.py": (
        "<module>.Assign:10",
        "<module>.Assign:11",
        "<module>.Assign:12",
        "<module>.Assign:13",
        "<module>.Assign:8",
        "<module>.Assign:9",
        "<module>.Import:10",
        "<module>.Import:6",
        "<module>.Import:7",
        "<module>.Import:8",
        "<module>.Import:9",
        "<module>.ImportFrom:5",
        "<module>.ImportFrom:6",
        "<module>.ImportFrom:7",
        "RepoCache.__init__",
        "RepoCache._assert_public_lfs_policy",
        "RepoCache._git_dir",
        "RepoCache._git_dir_bytes",
        "RepoCache._hash_file",
        "RepoCache._materialize_relevant_lfs",
        "RepoCache._public_lfs_env",
        "RepoCache._record_metadata",
        "RepoCache._run_public_lfs",
        "RepoCache.checkout",
        "RepoCache.ensure",
    ),
    "collector/scan.py": (
        "<module>.ImportFrom:3",
        "_dependency_names_for_file",
        "_notebook_code_text",
        "_notebook_source_surfaces",
    ),
    "collector/scanner_v2.py": (
        "_assert_lfs_history_compatible",
        "_worker",
    ),
    "collector/state.py": (
        "<module>.Assign:6",
        "<module>.Assign:7",
        "<module>.Import:4",
        "<module>.Import:5",
        "<module>.Import:6",
        "<module>.Import:7",
        "<module>.Import:8",
        "StateDB.<class>",
        "StateDB._finish_scan_attempt",
        "StateDB._scan_attempt_identity",
        "StateDB._scan_task_recovery_disposition",
        "StateDB._start_scan_attempt",
        "StateDB._validate_checkpoint",
        "StateDB.abandon_run",
        "StateDB.checkpoint_document",
        "StateDB.complete_task",
        "StateDB.export_checkpoint_shards",
        "StateDB.fail_task",
        "StateDB.lease_task",
        "StateDB.lease_task_by_id",
        "StateDB.record_scan_attempt_result",
        "StateDB.recover_stale_tasks",
        "StateDB.reset_failed_tasks",
        "StateDB.resume_compatible_run",
        "StateDB.scan_attempt_usage",
        "_sanitize_checkpoint_operational_row",
        "_scan_attempt_usage_values",
    ),
    "collector/state_migrations.py": (
        "<module>.AnnAssign:1",
        "<module>.Assign:1",
    ),
    "collector/successor.py": (
        "<module>.Assign:10",
        "<module>.Assign:11",
        "<module>.Assign:12",
        "<module>.Assign:13",
        "<module>.Assign:14",
        "<module>.Assign:15",
        "<module>.Assign:16",
        "<module>.Assign:17",
        "<module>.Assign:18",
        "<module>.Assign:19",
        "<module>.Assign:20",
        "<module>.Assign:21",
        "<module>.Assign:22",
        "<module>.Assign:23",
        "<module>.Assign:24",
        "<module>.Assign:25",
        "<module>.Assign:26",
        "<module>.Assign:5",
        "<module>.Assign:6",
        "<module>.Assign:7",
        "<module>.Assign:8",
        "<module>.Assign:9",
        "<module>.ImportFrom:12",
        "_assert_content_diagnostic_fingerprint_contract",
        "_assert_content_diagnostic_paths",
        "_assert_content_diagnostic_source_bytes",
        "_assert_exact_network_task_semantics",
        "_assert_predecessor_lfs_transfer_bound",
        "_assert_reviewed_source_sha256",
        "_cohort_successor_source_audit",
        "_derive_historical_scan_usage",
        "_historical_scan_hex_sha256",
        "_historical_scan_nonnegative_float",
        "_historical_scan_nonnegative_int",
        "_historical_scan_task_identity",
        "_pre_v5_conservative_scan_usage_row",
        "_reviewed_semantic_changes",
        "_validate_historical_scan_proof_row",
        "_validate_historical_scan_usage_contract",
        "_validate_predecessor_lfs_transfer_bound",
        "prepare_phase8_cohort_successor",
    ),
    "collector/triage.py": (
        "<module>.Assign:10",
        "<module>.Assign:11",
        "<module>.Assign:12",
        "<module>.Assign:13",
        "<module>.Assign:14",
        "<module>.Assign:15",
        "<module>.Assign:16",
        "<module>.Assign:17",
        "<module>.Assign:18",
        "<module>.Assign:19",
        "<module>.Assign:8",
        "<module>.Assign:9",
        "<module>.Import:10",
        "<module>.Import:11",
        "<module>.Import:12",
        "<module>.Import:5",
        "<module>.Import:6",
        "<module>.Import:7",
        "<module>.Import:8",
        "<module>.Import:9",
        "<module>.ImportFrom:4",
        "<module>.ImportFrom:5",
        "<module>.ImportFrom:6",
        "TriageResult.<class>",
        "_TextInventory.__init__",
        "_bare_tracked_text_inventory",
        "_eligible",
        "_embedded_project_roots",
        "_is_git_lfs_pointer",
        "_notebook_might_affect_verdict",
        "_notebook_surfaces",
        "_tracked_text_inventory",
        "lfs_evidence_path_relevant",
        "triage_tree",
    ),
}
# Frozen after the complete reviewed remediation passed its full suite.
# The successor module uses the normalized digest below so its own audit
# implementation is covered without a self-referential byte hash.
_CONTENT_DIAGNOSTIC_SUCCESSOR_SOURCE_SHA256 = {
    "collector/evidence_content.py": (
        "90d66fcdc8be256fc45d978795e28edf5"
        "5e0c1f4d80370a3102e892ed7e88c54"
    ),
    "collector/pipeline.py": (
        "e2afd0256ac239653431f370846af9045"
        "d11b10f85eb92001cfb75c5a91e2920"
    ),
    "collector/planner.py": (
        "474567056f9ffd8d30f49296c4a044ff"
        "d24806819132283ffe5eb348e1a447ab"
    ),
    "collector/repo_cache.py": (
        "e5934bf2a964a73ecf27c1a366fb6f5e"
        "c961295e282b08cb824a1919d0496128"
    ),
    "collector/scan.py": (
        "65ac4d0c76e0e61f2c827ebb8b341af0"
        "f37de2f58050e20f34b01231da57422c"
    ),
    "collector/scanner_v2.py": (
        "12b1d56d3032e0f45bacc6520aea1898"
        "bdbc2a679fffa3afb1dcfeadf0fa1718"
    ),
    "collector/state.py": (
        "8e30bd4aa7c715262197a4c3f3beb01a0"
        "c943c14585ed4bbae2990fe39021bb9"
    ),
    "collector/state_migrations.py": (
        "a7b1ac656449eab587d9602128a3fa0a"
        "11646feffe581b3899d621ae77e56459"
    ),
    "collector/triage.py": (
        "1acb612c2f31c86ffdcd721c010b56f7"
        "db4746514ab1eb90044cbfe80e420a02"
    ),
}
_CONTENT_DIAGNOSTIC_SUCCESSOR_NORMALIZED_SHA256 = (
    "223a9be6d3c20f3883b4c3a7232856734256ac6aa5ec85db09757960186d67a0"
)
_COHORT_DISCOVERY_PIPELINE_NODES = (
    "_completed_discovery_request_count",
    "_durable_discovery_request_usage",
    "_complete_journaled_network_task",
    "_discovery_result_to_task_result",
    "_assert_discovery_task_result",
    "_discovery_observation_from_dict",
    "_discovery_result_from_task_result",
    "_record_coverage",
    "CollectorPipeline._transport_usage_snapshot",
    "CollectorPipeline._record_transport_task_usage",
    "CollectorPipeline._discover",
)
_COHORT_METADATA_PIPELINE_NODES = (
    "_complete_journaled_network_task",
    "_metadata_result_to_task_result",
    "_metadata_result_from_task_result",
    "CollectorPipeline._metadata_batch_size",
)


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def _historical_scan_hex_sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PipelineError(
            "historical scan usage has invalid " + label
        )
    return value


def _historical_scan_nonnegative_int(
    value: Any, *, label: str
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PipelineError(
            "historical scan usage has invalid " + label
        )
    return int(value)


def _historical_scan_nonnegative_float(
    value: Any, *, label: str
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise PipelineError(
            "historical scan usage has invalid " + label
        )
    return float(value)


def _validate_historical_scan_proof_row(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PipelineError(
            "historical scan usage proof row is not an object"
        )
    row = dict(value)
    expected = {
        "run_id",
        "task_id",
        "task_key",
        "attempt",
        "repository_id",
        "full_name",
        "head_sha",
        "task_payload_sha256",
        "method",
        "usage",
        "evidence",
    }
    if set(row) != expected:
        raise PipelineError(
            "historical scan usage proof row has an invalid schema"
        )
    for field in (
        "run_id",
        "task_id",
        "task_key",
        "repository_id",
        "full_name",
        "head_sha",
    ):
        if not isinstance(row[field], str) or not row[field]:
            raise PipelineError(
                "historical scan usage proof row has invalid " + field
            )
    _historical_scan_hex_sha256(
        row["task_payload_sha256"],
        label="proof task payload digest",
    )
    _historical_scan_nonnegative_int(
        row["attempt"], label="proof attempt"
    )
    if row["attempt"] < 1:
        raise PipelineError(
            "historical scan usage proof attempt must be positive"
        )
    method = row["method"]
    if method not in (
        *_HISTORICAL_SCAN_EXACT_METHODS,
        _HISTORICAL_SCAN_CONSERVATIVE_METHOD,
        _HISTORICAL_SCAN_UNKNOWN_METHOD,
    ):
        raise PipelineError(
            "historical scan usage proof method is invalid"
        )
    usage = row["usage"]
    if not isinstance(usage, Mapping) or set(usage) != {
        *_SCAN_USAGE_FLOAT_FIELDS,
        *_SCAN_USAGE_COUNT_FIELDS,
    }:
        raise PipelineError(
            "historical scan usage proof metrics have an invalid schema"
        )
    usage = dict(usage)
    if method in _HISTORICAL_SCAN_EXACT_METHODS:
        for field in _SCAN_USAGE_FLOAT_FIELDS:
            usage[field] = _historical_scan_nonnegative_float(
                usage[field], label="proof " + field
            )
        for field in _SCAN_USAGE_COUNT_FIELDS:
            usage[field] = _historical_scan_nonnegative_int(
                usage[field], label="proof " + field
            )
    elif method == _HISTORICAL_SCAN_CONSERVATIVE_METHOD:
        if any(usage[field] is not None for field in _SCAN_USAGE_FLOAT_FIELDS):
            raise PipelineError(
                "conservative historical scan proof invented timing"
            )
        if usage["git_subprocess_count"] is not None:
            raise PipelineError(
                "conservative historical scan proof invented git usage"
            )
        if usage["network_clone_count"] is not None:
            raise PipelineError(
                "conservative historical scan proof invented clone usage"
            )
        if usage["network_fetch_count"] is not None:
            raise PipelineError(
                "conservative historical scan proof invented fetch usage"
            )
        usage["network_materialized_bytes"] = (
            _historical_scan_nonnegative_int(
                usage["network_materialized_bytes"],
                label="proof network_materialized_bytes",
            )
        )
        if usage["network_materialized_bytes"] < 1:
            raise PipelineError(
                "conservative historical scan byte charge is not positive"
            )
    else:
        if any(usage[field] is not None for field in usage):
            raise PipelineError(
                "irreconstructible historical scan proof invented usage"
            )
    evidence = row["evidence"]
    if not isinstance(evidence, Mapping):
        raise PipelineError(
            "historical scan proof evidence is not an object"
        )
    evidence = dict(evidence)
    if method == "scan-attempt-ledger-v1":
        if set(evidence) != {
            "attempt_status",
            "retryable",
            "error_code",
            "started_at",
            "finished_at",
        }:
            raise PipelineError(
                "scan-attempt ledger proof has an invalid schema"
            )
        if evidence["attempt_status"] not in {
            "complete",
            "failed",
            "interrupted",
        }:
            raise PipelineError(
                "scan-attempt ledger proof status is invalid"
            )
        if evidence["retryable"] not in {True, False, None}:
            raise PipelineError(
                "scan-attempt ledger retryable value is invalid"
            )
        for field in ("error_code", "finished_at"):
            if (
                evidence[field] is not None
                and not isinstance(evidence[field], str)
            ):
                raise PipelineError(
                    "scan-attempt ledger " + field + " is invalid"
                )
        if (
            not isinstance(evidence["started_at"], str)
            or not evidence["started_at"]
        ):
            raise PipelineError(
                "scan-attempt ledger started_at is invalid"
            )
    elif method == "pre-v5-task-result-v1":
        if set(evidence) != {
            "task_status",
            "error_code",
            "result_sha256",
        }:
            raise PipelineError(
                "pre-v5 result proof has an invalid schema"
            )
        if not isinstance(evidence["task_status"], str):
            raise PipelineError(
                "pre-v5 result proof status is invalid"
            )
        if (
            evidence["error_code"] is not None
            and not isinstance(evidence["error_code"], str)
        ):
            raise PipelineError(
                "pre-v5 result proof error code is invalid"
            )
        _historical_scan_hex_sha256(
            evidence["result_sha256"],
            label="pre-v5 result digest",
        )
    elif method == _HISTORICAL_SCAN_CONSERVATIVE_METHOD:
        if set(evidence) != {
            "bound_method",
            "public_repository_metadata_sha256",
            "cache_metadata_sha256",
            "cache_key",
            "disk_usage_kb",
            "public_disk_usage_bytes",
            "cache_accounted_bytes",
            "network_materialized_bytes_upper_bound",
            "predecessor_lfs_transfer_bound_sha256",
        }:
            raise PipelineError(
                "pre-v5 conservative proof has an invalid schema"
            )
        if (
            evidence["bound_method"]
            != "max-public-disk-usage-and-exact-head-cache-v1"
        ):
            raise PipelineError(
                "pre-v5 conservative bound method is invalid"
            )
        for field in (
            "public_repository_metadata_sha256",
            "cache_metadata_sha256",
            "cache_key",
            "predecessor_lfs_transfer_bound_sha256",
        ):
            _historical_scan_hex_sha256(
                evidence[field], label="conservative " + field
            )
        for field in (
            "disk_usage_kb",
            "public_disk_usage_bytes",
            "cache_accounted_bytes",
            "network_materialized_bytes_upper_bound",
        ):
            evidence[field] = _historical_scan_nonnegative_int(
                evidence[field], label="conservative " + field
            )
        if (
            evidence["public_disk_usage_bytes"]
            != evidence["disk_usage_kb"] * 1024
            or evidence["network_materialized_bytes_upper_bound"]
            != max(
                evidence["public_disk_usage_bytes"],
                evidence["cache_accounted_bytes"],
            )
            or evidence["network_materialized_bytes_upper_bound"]
            != usage["network_materialized_bytes"]
        ):
            raise PipelineError(
                "pre-v5 conservative byte proof is inconsistent"
            )
    else:
        if set(evidence) != {
            "policy_id",
            "attempt_status",
            "error_code",
            "usage_complete",
            "started_at",
            "finished_at",
        }:
            raise PipelineError(
                "irreconstructible attempt proof has an invalid schema"
            )
        if (
            evidence["policy_id"]
            != _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY["policy_id"]
            or evidence["attempt_status"]
            != _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY[
                "required_status"
            ]
            or evidence["error_code"]
            != _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY[
                "required_error_code"
            ]
            or evidence["usage_complete"] is not False
            or not isinstance(evidence["started_at"], str)
            or not evidence["started_at"]
            or not isinstance(evidence["finished_at"], str)
            or not evidence["finished_at"]
        ):
            raise PipelineError(
                "irreconstructible attempt proof is outside owner policy"
            )
    row["usage"] = usage
    row["evidence"] = evidence
    return row


def _validate_historical_scan_usage_contract(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PipelineError(
            "historical scan usage contract is not an object"
        )
    contract = dict(value)
    version = contract.get("version")
    if (
        isinstance(version, bool)
        or version not in {1, HISTORICAL_SCAN_USAGE_CONTRACT_VERSION}
    ):
        raise PipelineError(
            "historical scan usage contract version is invalid"
        )
    expected = {
        "version",
        "predecessor_run_id",
        "predecessor_plan_sha256",
        "predecessor_lineage_sha256",
        "attempt_count",
        "exact_attempt_count",
        "conservative_attempt_count",
        "timing_known_attempt_count",
        "timing_unknown_attempt_count",
        "usage",
        "proof_rows",
        "proof_rows_sha256",
        "contract_sha256",
    }
    if version >= 2:
        expected.update({
            "irreconstructible_attempt_count",
            "unknown_usage_policy",
        })
    if set(contract) != expected:
        raise PipelineError(
            "historical scan usage contract has an invalid schema"
        )
    if (
        not isinstance(contract["predecessor_run_id"], str)
        or not contract["predecessor_run_id"]
    ):
        raise PipelineError(
            "historical scan usage predecessor is invalid"
        )
    for field in (
        "predecessor_plan_sha256",
        "predecessor_lineage_sha256",
        "proof_rows_sha256",
        "contract_sha256",
    ):
        _historical_scan_hex_sha256(
            contract[field], label=field
        )
    count_fields = (
        "attempt_count",
        "exact_attempt_count",
        "conservative_attempt_count",
        "timing_known_attempt_count",
        "timing_unknown_attempt_count",
    )
    if version >= 2:
        count_fields += ("irreconstructible_attempt_count",)
    for field in count_fields:
        contract[field] = _historical_scan_nonnegative_int(
            contract[field], label=field
        )
    rows_value = contract["proof_rows"]
    if not isinstance(rows_value, list):
        raise PipelineError(
            "historical scan usage proof rows are not a list"
        )
    rows = [
        _validate_historical_scan_proof_row(row)
        for row in rows_value
    ]
    if rows != sorted(
        rows,
        key=lambda row: (
            row["run_id"],
            row["task_id"],
            row["attempt"],
        ),
    ):
        raise PipelineError(
            "historical scan usage proof rows are not canonical"
        )
    identities = {
        (row["run_id"], row["task_id"], row["attempt"])
        for row in rows
    }
    if len(identities) != len(rows):
        raise PipelineError(
            "historical scan usage proof rows contain duplicates"
        )
    exact_count = sum(
        row["method"] in _HISTORICAL_SCAN_EXACT_METHODS
        for row in rows
    )
    conservative_count = sum(
        row["method"] == _HISTORICAL_SCAN_CONSERVATIVE_METHOD
        for row in rows
    )
    irreconstructible_count = sum(
        row["method"] == _HISTORICAL_SCAN_UNKNOWN_METHOD
        for row in rows
    )
    if (
        contract["attempt_count"] != len(rows)
        or contract["exact_attempt_count"] != exact_count
        or contract["conservative_attempt_count"] != conservative_count
        or contract["timing_known_attempt_count"] != exact_count
        or contract["timing_unknown_attempt_count"]
        != conservative_count + irreconstructible_count
        or (
            version >= 2
            and contract["irreconstructible_attempt_count"]
            != irreconstructible_count
        )
        or (version == 1 and irreconstructible_count)
    ):
        raise PipelineError(
            "historical scan usage attempt counts are inconsistent"
        )
    usage_value = contract["usage"]
    expected_usage_fields = {
        *_SCAN_USAGE_FLOAT_FIELDS,
        *_SCAN_USAGE_COUNT_FIELDS,
        "git_subprocess_unknown_attempt_count",
        "network_clone_unknown_attempt_count",
        "network_fetch_unknown_attempt_count",
    }
    if version >= 2:
        expected_usage_fields.add(
            "network_materialized_bytes_unknown_attempt_count"
        )
    if (
        not isinstance(usage_value, Mapping)
        or set(usage_value) != expected_usage_fields
    ):
        raise PipelineError(
            "historical scan usage totals have an invalid schema"
        )
    expected_usage: dict[str, int | float] = {
        field: math.fsum(
            float(row["usage"][field])
            for row in rows
            if row["usage"][field] is not None
        )
        for field in _SCAN_USAGE_FLOAT_FIELDS
    }
    expected_usage.update({
        "git_subprocess_count": sum(
            int(row["usage"]["git_subprocess_count"])
            for row in rows
            if row["usage"]["git_subprocess_count"] is not None
        ),
        "git_subprocess_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "network_clone_count": sum(
            int(row["usage"]["network_clone_count"])
            for row in rows
            if row["usage"]["network_clone_count"] is not None
        ),
        "network_clone_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "network_fetch_count": sum(
            int(row["usage"]["network_fetch_count"])
            for row in rows
            if row["usage"]["network_fetch_count"] is not None
        ),
        "network_fetch_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "network_materialized_bytes": sum(
            int(row["usage"]["network_materialized_bytes"])
            for row in rows
            if row["usage"]["network_materialized_bytes"] is not None
        ),
    })
    if version >= 2:
        expected_usage[
            "network_materialized_bytes_unknown_attempt_count"
        ] = irreconstructible_count
    normalized_usage = {
        field: _historical_scan_nonnegative_float(
            usage_value[field], label=field
        )
        for field in _SCAN_USAGE_FLOAT_FIELDS
    }
    normalized_usage.update({
        field: _historical_scan_nonnegative_int(
            usage_value[field], label=field
        )
        for field in (
            *_SCAN_USAGE_COUNT_FIELDS,
            "git_subprocess_unknown_attempt_count",
            "network_clone_unknown_attempt_count",
            "network_fetch_unknown_attempt_count",
            *(
                ("network_materialized_bytes_unknown_attempt_count",)
                if version >= 2
                else ()
            ),
        )
    })
    if normalized_usage != expected_usage:
        raise PipelineError(
            "historical scan usage totals do not match proof rows"
        )
    if contract["proof_rows_sha256"] != _sha256(rows):
        raise PipelineError(
            "historical scan usage proof-row digest changed"
        )
    unsigned = dict(contract)
    unsigned.pop("contract_sha256")
    unsigned["proof_rows"] = rows
    unsigned["usage"] = normalized_usage
    if contract["contract_sha256"] != _sha256(unsigned):
        raise PipelineError(
            "historical scan usage contract digest changed"
        )
    contract["proof_rows"] = rows
    contract["usage"] = normalized_usage
    if version >= 2:
        policy = contract["unknown_usage_policy"]
        if irreconstructible_count:
            expected_policy = {
                **_CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY,
                "policy_sha256": _sha256(
                    _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY
                ),
            }
            if policy != expected_policy:
                raise PipelineError(
                    "historical unknown-usage policy changed"
                )
            if (
                contract["predecessor_run_id"]
                != expected_policy["predecessor_run_id"]
                or irreconstructible_count
                != expected_policy["expected_attempt_count"]
            ):
                raise PipelineError(
                    "historical unknown-usage scope changed"
                )
        elif policy is not None:
            raise PipelineError(
                "historical usage has an unnecessary unknown policy"
            )
    return contract


def _historical_scan_task_identity(
    state: StateDB,
    task: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        payload = json.loads(str(task["payload_json"]))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "predecessor scan task payload is invalid"
        ) from exc
    if not isinstance(payload, Mapping):
        raise PipelineError(
            "predecessor scan task payload is not an object"
        )
    repository_values = {
        str(value)
        for value in (
            task["repository_id"],
            payload.get("repository_id"),
            payload.get("repo_node_id"),
            payload.get("node_id"),
        )
        if isinstance(value, str) and value
    }
    if len(repository_values) != 1:
        raise PipelineError(
            "predecessor scan repository identity is missing or conflicting"
        )
    repository_id = next(iter(repository_values))
    repository = state.connection.execute(
        """
        SELECT node_id, full_name, visibility, head_sha, metadata_json
        FROM repositories WHERE node_id=?
        """,
        (repository_id,),
    ).fetchone()
    if repository is None or repository["visibility"] != "public":
        raise PipelineError(
            "predecessor scan repository is not explicitly public"
        )
    full_names = {
        str(value)
        for value in (
            repository["full_name"],
            payload.get("full_name"),
            payload.get("repo"),
        )
        if isinstance(value, str) and value
    }
    if len(full_names) != 1:
        raise PipelineError(
            "predecessor scan repository name is missing or conflicting"
        )
    head_values = {
        str(value)
        for value in (
            repository["head_sha"],
            payload.get("head_sha"),
        )
        if isinstance(value, str) and value
    }
    if len(head_values) != 1:
        raise PipelineError(
            "predecessor scan head is missing or conflicting"
        )
    return {
        "payload": dict(payload),
        "payload_sha256": hashlib.sha256(
            str(task["payload_json"]).encode("utf-8")
        ).hexdigest(),
        "repository_id": repository_id,
        "full_name": next(iter(full_names)),
        "head_sha": next(iter(head_values)),
        "repository_metadata_json": str(
            repository["metadata_json"] or "{}"
        ),
    }


def _pre_v5_conservative_scan_usage_row(
    *,
    state: StateDB,
    task: Mapping[str, Any],
    identity: Mapping[str, Any],
    attempt: int,
    cache_root: Path,
    predecessor_lfs_transfer_bound: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        public_metadata = json.loads(
            identity["repository_metadata_json"]
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "pre-v5 unknown scan has invalid public metadata"
        ) from exc
    if not isinstance(public_metadata, Mapping):
        raise PipelineError(
            "pre-v5 unknown scan public metadata is not an object"
        )
    full_name = identity["full_name"]
    repository_id = identity["repository_id"]
    head_sha = identity["head_sha"]
    if (
        public_metadata.get("explicitly_public") is not True
        or public_metadata.get("is_private") is not False
        or str(public_metadata.get("visibility") or "").upper()
        != "PUBLIC"
        or public_metadata.get("node_id") != repository_id
        or public_metadata.get("full_name") != full_name
        or public_metadata.get("head_oid") != head_sha
    ):
        raise PipelineError(
            "pre-v5 unknown scan lacks exact public repository metadata"
        )
    disk_usage_kb = public_metadata.get("disk_usage_kb")
    if (
        isinstance(disk_usage_kb, bool)
        or not isinstance(disk_usage_kb, int)
        or disk_usage_kb < 0
    ):
        raise PipelineError(
            "pre-v5 unknown scan lacks safe public disk usage"
        )
    cache_key = hashlib.sha256(
        str(full_name).lower().encode("utf-8")
    ).hexdigest()
    cache_path = cache_root / "repos" / (cache_key + ".json")
    try:
        cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (
        FileNotFoundError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise PipelineError(
            "pre-v5 unknown scan lacks safe exact-head cache metadata"
        ) from exc
    if (
        not isinstance(cache_payload, Mapping)
        or cache_payload.get("full_name") != full_name
        or cache_payload.get("head_sha") != head_sha
    ):
        raise PipelineError(
            "pre-v5 unknown scan cache metadata is not exact"
        )
    cache_bytes = cache_payload.get("bytes")
    reserved_bytes = cache_payload.get("reserved_growth_bytes", 0)
    for label, value in (
        ("cache bytes", cache_bytes),
        ("cache reserved bytes", reserved_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PipelineError(
                "pre-v5 unknown scan has invalid " + label
            )
    public_disk_bytes = int(disk_usage_kb) * 1024
    cache_accounted_bytes = int(cache_bytes) + int(reserved_bytes)
    upper_bound = max(public_disk_bytes, cache_accounted_bytes)
    if upper_bound < 1:
        raise PipelineError(
            "pre-v5 unknown scan has no positive safe byte bound"
        )
    evidence = {
        "bound_method": (
            "max-public-disk-usage-and-exact-head-cache-v1"
        ),
        "public_repository_metadata_sha256": _sha256(public_metadata),
        "cache_metadata_sha256": _sha256(cache_payload),
        "cache_key": cache_key,
        "disk_usage_kb": int(disk_usage_kb),
        "public_disk_usage_bytes": public_disk_bytes,
        "cache_accounted_bytes": cache_accounted_bytes,
        "network_materialized_bytes_upper_bound": upper_bound,
        "predecessor_lfs_transfer_bound_sha256": (
            predecessor_lfs_transfer_bound["contract_sha256"]
        ),
    }
    return {
        "run_id": str(task["run_id"]),
        "task_id": str(task["task_id"]),
        "task_key": str(task["task_key"]),
        "attempt": int(attempt),
        "repository_id": str(repository_id),
        "full_name": str(full_name),
        "head_sha": str(head_sha),
        "task_payload_sha256": str(identity["payload_sha256"]),
        "method": _HISTORICAL_SCAN_CONSERVATIVE_METHOD,
        "usage": {
            **{field: None for field in _SCAN_USAGE_FLOAT_FIELDS},
            "git_subprocess_count": None,
            "network_clone_count": None,
            "network_fetch_count": None,
            "network_materialized_bytes": upper_bound,
        },
        "evidence": evidence,
    }


def _derive_historical_scan_usage(
    *,
    state: StateDB,
    predecessor_run_id: str,
    predecessor_plan: Mapping[str, Any],
    cache_root: str | Path,
    predecessor_lfs_transfer_bound: Mapping[str, Any] | None = None,
    unknown_usage_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Charge every predecessor scan dispatch without inheriting verdicts."""
    predecessor_execution = predecessor_plan.get("execution_contract") or {}
    if not isinstance(predecessor_execution, Mapping):
        raise PipelineError(
            "predecessor execution contract is invalid"
        )
    prior_value = predecessor_execution.get("historical_scan_usage")
    prior_rows: list[dict[str, Any]] = []
    if prior_value is not None:
        prior_contract = _validate_historical_scan_usage_contract(
            prior_value
        )
        prior_rows = list(prior_contract["proof_rows"])
    task_rows = list(state.connection.execute(
        """
        SELECT task_id, run_id, task_key, repository_id, payload_json,
               result_json, status, attempts, error_code
        FROM tasks
        WHERE run_id=? AND stage='scan'
        ORDER BY task_id
        """,
        (predecessor_run_id,),
    ))
    expected_attempts = sum(
        _historical_scan_nonnegative_int(
            row["attempts"], label="predecessor task attempts"
        )
        for row in task_rows
    )
    has_attempt_ledger = state.connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='scan_attempts'
        """
    ).fetchone()
    ledger_rows = (
        list(state.connection.execute(
            """
            SELECT task_id, attempt, run_id, repository_id, task_key,
                   payload_sha256, head_sha, status, retryable, error_code,
                   seconds, current_tree_triage_seconds,
                   history_dating_seconds, analysis_seconds,
                   git_subprocess_count, network_clone_count,
                   network_fetch_count, network_materialized_bytes,
                   usage_complete, started_at, finished_at
            FROM scan_attempts
            WHERE run_id=?
            ORDER BY task_id, attempt
            """,
            (predecessor_run_id,),
        ))
        if has_attempt_ledger is not None
        else []
    )
    task_by_id = {
        str(row["task_id"]): row for row in task_rows
    }
    direct_rows: list[dict[str, Any]] = []
    if ledger_rows:
        if len(ledger_rows) != expected_attempts:
            raise PipelineError(
                "predecessor scan-attempt ledger is incomplete"
            )
        observed_ordinals: dict[str, list[int]] = {}
        for ledger in ledger_rows:
            task_id = str(ledger["task_id"])
            task = task_by_id.get(task_id)
            if task is None:
                raise PipelineError(
                    "predecessor scan-attempt ledger has an unknown task"
                )
            identity = _historical_scan_task_identity(state, task)
            if (
                str(ledger["run_id"]) != predecessor_run_id
                or str(ledger["repository_id"])
                != identity["repository_id"]
                or str(ledger["task_key"]) != str(task["task_key"])
                or str(ledger["payload_sha256"])
                != identity["payload_sha256"]
                or str(ledger["head_sha"]) != identity["head_sha"]
            ):
                raise PipelineError(
                    "predecessor scan-attempt ledger proof is incomplete"
                )
            attempt = _historical_scan_nonnegative_int(
                ledger["attempt"], label="ledger attempt"
            )
            observed_ordinals.setdefault(task_id, []).append(attempt)
            if ledger["usage_complete"] != 1:
                expected_policy = {
                    **_CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY,
                    "policy_sha256": _sha256(
                        _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY
                    ),
                }
                if unknown_usage_policy != expected_policy:
                    raise PipelineError(
                        "predecessor scan-attempt ledger proof is incomplete"
                    )
                direct_rows.append({
                    "run_id": predecessor_run_id,
                    "task_id": task_id,
                    "task_key": str(task["task_key"]),
                    "attempt": attempt,
                    "repository_id": identity["repository_id"],
                    "full_name": identity["full_name"],
                    "head_sha": identity["head_sha"],
                    "task_payload_sha256": identity["payload_sha256"],
                    "method": _HISTORICAL_SCAN_UNKNOWN_METHOD,
                    "usage": {
                        **{
                            field: None
                            for field in _SCAN_USAGE_FLOAT_FIELDS
                        },
                        **{
                            field: None
                            for field in _SCAN_USAGE_COUNT_FIELDS
                        },
                    },
                    "evidence": {
                        "policy_id": expected_policy["policy_id"],
                        "attempt_status": str(ledger["status"]),
                        "error_code": ledger["error_code"],
                        "usage_complete": False,
                        "started_at": str(ledger["started_at"]),
                        "finished_at": str(ledger["finished_at"]),
                    },
                })
                continue
            usage, complete = _scan_attempt_usage_values(dict(ledger))
            if not complete:
                raise PipelineError(
                    "predecessor scan-attempt ledger has invalid usage"
                )
            direct_rows.append({
                "run_id": predecessor_run_id,
                "task_id": task_id,
                "task_key": str(task["task_key"]),
                "attempt": attempt,
                "repository_id": identity["repository_id"],
                "full_name": identity["full_name"],
                "head_sha": identity["head_sha"],
                "task_payload_sha256": identity["payload_sha256"],
                "method": "scan-attempt-ledger-v1",
                "usage": usage,
                "evidence": {
                    "attempt_status": str(ledger["status"]),
                    "retryable": (
                        None
                        if ledger["retryable"] is None
                        else bool(ledger["retryable"])
                    ),
                    "error_code": ledger["error_code"],
                    "started_at": str(ledger["started_at"]),
                    "finished_at": ledger["finished_at"],
                },
            })
        for task in task_rows:
            task_id = str(task["task_id"])
            expected = list(range(1, int(task["attempts"]) + 1))
            if observed_ordinals.get(task_id, []) != expected:
                raise PipelineError(
                    "predecessor scan-attempt ordinals are incomplete"
                )
    else:
        cache_path = Path(cache_root).resolve()
        lfs_transfer_bound = None
        for task in task_rows:
            attempts = int(task["attempts"])
            if attempts == 0:
                if task["result_json"] is not None:
                    raise PipelineError(
                        "pre-v5 scan result has no recorded dispatch"
                    )
                continue
            identity = _historical_scan_task_identity(state, task)
            exact_attempt = attempts if task["result_json"] is not None else None
            for attempt in range(1, attempts + 1):
                if attempt != exact_attempt:
                    if lfs_transfer_bound is None:
                        lfs_transfer_bound = (
                            _validate_predecessor_lfs_transfer_bound(
                                predecessor_lfs_transfer_bound
                            )
                        )
                    direct_rows.append(
                        _pre_v5_conservative_scan_usage_row(
                            state=state,
                            task=task,
                            identity=identity,
                            attempt=attempt,
                            cache_root=cache_path,
                            predecessor_lfs_transfer_bound=(
                                lfs_transfer_bound
                            ),
                        )
                    )
                    continue
                result_json = str(task["result_json"])
                try:
                    result = json.loads(result_json)
                except (
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                ) as exc:
                    raise PipelineError(
                        "pre-v5 scan result is malformed"
                    ) from exc
                usage, complete = _scan_attempt_usage_values(result)
                if not complete:
                    raise PipelineError(
                        "pre-v5 scan result usage is incomplete or invalid"
                    )
                direct_rows.append({
                    "run_id": predecessor_run_id,
                    "task_id": str(task["task_id"]),
                    "task_key": str(task["task_key"]),
                    "attempt": attempt,
                    "repository_id": identity["repository_id"],
                    "full_name": identity["full_name"],
                    "head_sha": identity["head_sha"],
                    "task_payload_sha256": identity["payload_sha256"],
                    "method": "pre-v5-task-result-v1",
                    "usage": usage,
                    "evidence": {
                        "task_status": str(task["status"]),
                        "error_code": task["error_code"],
                        "result_sha256": hashlib.sha256(
                            result_json.encode("utf-8")
                        ).hexdigest(),
                    },
                })
    if len(direct_rows) != expected_attempts:
        raise PipelineError(
            "predecessor scan dispatch accounting is incomplete"
        )
    proof_rows = sorted(
        [*prior_rows, *direct_rows],
        key=lambda row: (
            row["run_id"],
            row["task_id"],
            row["attempt"],
        ),
    )
    exact_count = sum(
        row["method"] in _HISTORICAL_SCAN_EXACT_METHODS
        for row in proof_rows
    )
    conservative_count = sum(
        row["method"] == _HISTORICAL_SCAN_CONSERVATIVE_METHOD
        for row in proof_rows
    )
    irreconstructible_count = sum(
        row["method"] == _HISTORICAL_SCAN_UNKNOWN_METHOD
        for row in proof_rows
    )
    usage: dict[str, int | float] = {
        field: math.fsum(
            float(row["usage"][field])
            for row in proof_rows
            if row["usage"][field] is not None
        )
        for field in _SCAN_USAGE_FLOAT_FIELDS
    }
    usage.update({
        "git_subprocess_count": sum(
            int(row["usage"]["git_subprocess_count"])
            for row in proof_rows
            if row["usage"]["git_subprocess_count"] is not None
        ),
        "git_subprocess_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "network_clone_count": sum(
            int(row["usage"]["network_clone_count"])
            for row in proof_rows
            if row["usage"]["network_clone_count"] is not None
        ),
        "network_clone_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "network_fetch_count": sum(
            int(row["usage"]["network_fetch_count"])
            for row in proof_rows
            if row["usage"]["network_fetch_count"] is not None
        ),
        "network_fetch_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "network_materialized_bytes": sum(
            int(row["usage"]["network_materialized_bytes"])
            for row in proof_rows
            if row["usage"]["network_materialized_bytes"] is not None
        ),
        "network_materialized_bytes_unknown_attempt_count": (
            irreconstructible_count
        ),
    })
    contract = {
        "version": HISTORICAL_SCAN_USAGE_CONTRACT_VERSION,
        "predecessor_run_id": predecessor_run_id,
        "predecessor_plan_sha256": _sha256(predecessor_plan),
        "predecessor_lineage_sha256": _sha256(
            predecessor_plan.get("successor_lineage") or {}
        ),
        "attempt_count": len(proof_rows),
        "exact_attempt_count": exact_count,
        "conservative_attempt_count": conservative_count,
        "irreconstructible_attempt_count": irreconstructible_count,
        "timing_known_attempt_count": exact_count,
        "timing_unknown_attempt_count": (
            conservative_count + irreconstructible_count
        ),
        "usage": usage,
        "proof_rows": proof_rows,
        "proof_rows_sha256": _sha256(proof_rows),
        "unknown_usage_policy": (
            dict(unknown_usage_policy)
            if irreconstructible_count
            else None
        ),
    }
    contract["contract_sha256"] = _sha256(contract)
    return _validate_historical_scan_usage_contract(contract)


def _source_payload_sha256(
    payloads: Mapping[str, bytes],
    paths: tuple[str, ...] = _LEGACY_NETWORK_TASK_PATHS,
) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        payload = payloads[relative]
        encoded = relative.removeprefix("collector/").encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _git(
    root: Path,
    *args: str,
    text: bool = True,
) -> str | bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=text,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise PipelineError("transport successor source audit failed")
    return result.stdout


def _transport_policy_source_audit(
    root: Path,
    predecessor_source_ref: str,
    expected_predecessor_network_sha256: str | None = None,
) -> dict[str, Any]:
    if not predecessor_source_ref or predecessor_source_ref.startswith("-"):
        raise PipelineError("predecessor source ref is invalid")
    dirty = str(
        _git(root, "status", "--porcelain", "--untracked-files=no")
    ).strip()
    if dirty:
        raise PipelineError(
            "transport successor requires a clean tracked worktree"
        )
    predecessor_commit = str(
        _git(root, "rev-parse", "--verify", predecessor_source_ref + "^{commit}")
    ).strip()
    current_commit = str(_git(root, "rev-parse", "--verify", "HEAD^{commit}")).strip()
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", predecessor_commit, current_commit],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if ancestor.returncode != 0:
        raise PipelineError(
            "predecessor source ref is not an ancestor of current HEAD"
        )
    changed_paths = tuple(
        sorted(
            line
            for line in str(
                _git(
                    root,
                    "diff",
                    "--name-only",
                    predecessor_commit + ".." + current_commit,
                )
            ).splitlines()
            if line
        )
    )
    unexpected = sorted(
        set(changed_paths) - _TRANSPORT_POLICY_ALLOWED_PATHS
    )
    if unexpected:
        raise PipelineError(
            "transport successor changed unapproved source paths: "
            + ",".join(unexpected)
        )
    changed_set = set(changed_paths)
    if "collector/discovery/github_search.py" in changed_set:
        required_changes = {
            "collector/discovery/github_search.py",
            "collector/pipeline.py",
        }
        remediation_kind = "query-decomposition-remediation"
    else:
        required_changes = {"collector/http_transport.py"}
        remediation_kind = "transport-policy-remediation"
    if not required_changes <= changed_set:
        raise PipelineError(
            "transport successor does not contain the reviewed runtime change"
        )
    predecessor_paths = tuple(
        dict.fromkeys(
            _LEGACY_NETWORK_TASK_PATHS + _CURRENT_NETWORK_TASK_PATHS
        )
    )
    predecessor_payloads = {
        path: bytes(
            _git(
                root,
                "show",
                predecessor_commit + ":" + path,
                text=False,
            )
        )
        for path in predecessor_paths
    }
    predecessor_network_candidates = {
        "legacy_without_transport": _source_payload_sha256(
            predecessor_payloads,
            _LEGACY_NETWORK_TASK_PATHS,
        ),
        "current_with_transport": _source_payload_sha256(
            predecessor_payloads,
            _CURRENT_NETWORK_TASK_PATHS,
        ),
    }
    if expected_predecessor_network_sha256 is None:
        predecessor_network_sha256 = predecessor_network_candidates[
            "legacy_without_transport"
        ]
    else:
        matches = [
            value
            for value in predecessor_network_candidates.values()
            if value == expected_predecessor_network_sha256
        ]
        if len(matches) != 1:
            raise PipelineError(
                "predecessor source ref does not reproduce its recorded "
                "network executable"
            )
        predecessor_network_sha256 = matches[0]
    predecessor_transport = bytes(
        _git(
            root,
            "show",
            predecessor_commit + ":collector/http_transport.py",
            text=False,
        )
    )
    current_transport = (root / "collector/http_transport.py").read_bytes()
    predecessor_transport_sha256 = hashlib.sha256(
        predecessor_transport
    ).hexdigest()
    current_transport_sha256 = hashlib.sha256(
        current_transport
    ).hexdigest()
    if (
        remediation_kind == "transport-policy-remediation"
        and predecessor_transport_sha256 == current_transport_sha256
    ):
        raise PipelineError("transport policy source did not change")
    return {
        "predecessor_source_ref": predecessor_source_ref,
        "predecessor_source_commit": predecessor_commit,
        "successor_source_commit": current_commit,
        "changed_paths": list(changed_paths),
        "remediation_kind": remediation_kind,
        "predecessor_network_task_source_sha256": (
            predecessor_network_sha256
        ),
        "predecessor_network_task_source_candidates": (
            predecessor_network_candidates
        ),
        "successor_network_task_source_sha256": (
            _network_task_source_sha256()
        ),
        "predecessor_transport_source_sha256": (
            predecessor_transport_sha256
        ),
        "successor_transport_source_sha256": current_transport_sha256,
    }


def _pipeline_node_digests(source: bytes) -> dict[str, str]:
    """Hash the exact ASTs that define one discovery task's semantics."""
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PipelineError(
            "cohort successor could not parse the pipeline source"
        ) from exc
    found: dict[str, ast.AST] = {}
    wanted = set(_COHORT_DISCOVERY_PIPELINE_NODES)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in wanted:
                found[node.name] = node
        elif isinstance(node, ast.ClassDef) and node.name == "CollectorPipeline":
            for child in node.body:
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    qualified = "CollectorPipeline." + child.name
                    if qualified in wanted:
                        found[qualified] = child
    missing = sorted(wanted - set(found))
    if missing:
        raise PipelineError(
            "cohort successor source audit is missing discovery nodes: "
            + ",".join(missing)
        )
    return {
        name: hashlib.sha256(
            ast.dump(
                found[name],
                annotate_fields=True,
                include_attributes=False,
            ).encode("utf-8")
        ).hexdigest()
        for name in sorted(found)
    }


def _normalized_discovery_usage_digest(source: bytes) -> str:
    """Ignore only the reviewed inheritance-stage restriction.

    Metadata tasks now use the generic task-lineage table too.  Discovery
    request accounting must therefore read only inherited discovery tasks.
    Removing that exact SQL predicate must reproduce the predecessor AST.
    """
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PipelineError(
            "cohort recovery could not parse discovery accounting source"
        ) from exc
    node = next(
        (
            item
            for item in tree.body
            if isinstance(item, ast.FunctionDef)
            and item.name == "_durable_discovery_request_usage"
        ),
        None,
    )
    if node is None:
        raise PipelineError(
            "cohort recovery is missing discovery request accounting"
        )
    normalized = copy.deepcopy(node)
    marker = "\n          AND t.stage='discovery-query'"
    seen = 0
    for item in ast.walk(normalized):
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            if marker in item.value:
                item.value = item.value.replace(marker, "")
                seen += 1
    if seen > 1:
        raise PipelineError(
            "cohort recovery found ambiguous discovery stage predicates"
        )
    return hashlib.sha256(
        ast.dump(
            normalized,
            annotate_fields=True,
            include_attributes=False,
        ).encode("utf-8")
    ).hexdigest()


def _semantic_node_digests(source: bytes) -> dict[str, str]:
    """Hash every executable module node, with class methods separated."""
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PipelineError(
            "cohort successor could not parse audited source"
        ) from exc

    nodes: dict[str, ast.AST] = {}
    ordinal = Counter()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = node.name
            nodes[key] = node
            continue
        if isinstance(node, ast.ClassDef):
            shell = ast.ClassDef(
                name=node.name,
                bases=node.bases,
                keywords=node.keywords,
                body=[
                    child
                    for child in node.body
                    if not isinstance(
                        child, (ast.FunctionDef, ast.AsyncFunctionDef)
                    )
                ],
                decorator_list=node.decorator_list,
                type_params=getattr(node, "type_params", []),
            )
            nodes[node.name + ".<class>"] = shell
            for child in node.body:
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    nodes[node.name + "." + child.name] = child
            continue
        label = type(node).__name__
        ordinal[label] += 1
        nodes["<module>.%s:%d" % (label, ordinal[label])] = node
    return {
        name: hashlib.sha256(
            ast.dump(
                node,
                annotate_fields=True,
                include_attributes=False,
            ).encode("utf-8")
        ).hexdigest()
        for name, node in sorted(nodes.items())
    }


def _metadata_task_execution_digests(source: bytes) -> dict[str, str]:
    """Hash metadata serialization plus the exact nested network operation."""
    semantic = _semantic_node_digests(source)
    missing = sorted(
        set(_COHORT_METADATA_PIPELINE_NODES) - set(semantic)
    )
    if missing:
        raise PipelineError(
            "cohort recovery is missing metadata execution nodes: "
            + ",".join(missing)
        )
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PipelineError(
            "cohort recovery could not parse metadata execution source"
        ) from exc
    nested = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "run_metadata_task"
    ]
    if len(nested) != 1:
        raise PipelineError(
            "cohort recovery found an ambiguous metadata network operation"
        )
    result = {
        name: semantic[name]
        for name in _COHORT_METADATA_PIPELINE_NODES
    }
    result["CollectorPipeline._resolve_metadata.run_metadata_task"] = (
        hashlib.sha256(
            ast.dump(
                nested[0],
                annotate_fields=True,
                include_attributes=False,
            ).encode("utf-8")
        ).hexdigest()
    )
    return dict(sorted(result.items()))


def _assert_exact_network_task_semantics(
    predecessor_pipeline: bytes,
    successor_pipeline: bytes,
) -> dict[str, Any]:
    """Prove discovery and metadata task execution stayed byte-independent."""
    predecessor_discovery = _pipeline_node_digests(
        predecessor_pipeline
    )
    successor_discovery = _pipeline_node_digests(successor_pipeline)
    if predecessor_discovery != successor_discovery:
        changed = sorted(
            name
            for name in set(predecessor_discovery) | set(successor_discovery)
            if predecessor_discovery.get(name)
            != successor_discovery.get(name)
        )
        raise PipelineError(
            "cohort content/diagnostic recovery changed discovery task "
            "semantics: " + ",".join(changed)
        )
    predecessor_metadata = _metadata_task_execution_digests(
        predecessor_pipeline
    )
    successor_metadata = _metadata_task_execution_digests(
        successor_pipeline
    )
    if predecessor_metadata != successor_metadata:
        changed = sorted(
            name
            for name in set(predecessor_metadata) | set(successor_metadata)
            if predecessor_metadata.get(name)
            != successor_metadata.get(name)
        )
        raise PipelineError(
            "cohort content/diagnostic recovery changed metadata task "
            "semantics: " + ",".join(changed)
        )
    return {
        "discovery_task_nodes_sha256": _sha256(
            predecessor_discovery
        ),
        "metadata_task_nodes_sha256": _sha256(predecessor_metadata),
        "exact_discovery_task_execution": True,
        "exact_metadata_task_execution": True,
    }


def _module_import_names(source: bytes) -> set[str]:
    try:
        tree = ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PipelineError(
            "cohort recovery could not parse control-plane imports"
        ) from exc
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
    return names


def _validate_predecessor_lfs_transfer_bound(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PipelineError(
            "pre-v5 byte bound lacks predecessor LFS transfer proof"
        )
    proof = dict(value)
    if set(proof) != {
        "version",
        "predecessor_source_commit",
        "scan_source_sha256",
        "repo_cache_source_sha256",
        "git_auth_env_semantic_sha256",
        "repo_cache_run_semantic_sha256",
        "repo_cache_checkout_semantic_sha256",
        "git_lfs_skip_smudge",
        "public_lfs_hydration",
        "contract_sha256",
    }:
        raise PipelineError(
            "predecessor LFS transfer proof has an invalid schema"
        )
    if proof["version"] != 1:
        raise PipelineError(
            "predecessor LFS transfer proof version is invalid"
        )
    if (
        not isinstance(proof["predecessor_source_commit"], str)
        or not proof["predecessor_source_commit"]
    ):
        raise PipelineError(
            "predecessor LFS transfer source is invalid"
        )
    for field in (
        "scan_source_sha256",
        "repo_cache_source_sha256",
        "git_auth_env_semantic_sha256",
        "repo_cache_run_semantic_sha256",
        "repo_cache_checkout_semantic_sha256",
        "contract_sha256",
    ):
        _historical_scan_hex_sha256(proof[field], label=field)
    if (
        proof["git_lfs_skip_smudge"] != "1"
        or proof["public_lfs_hydration"] != "absent"
    ):
        raise PipelineError(
            "predecessor LFS transfer behavior is not safely bounded"
        )
    unsigned = dict(proof)
    unsigned.pop("contract_sha256")
    if proof["contract_sha256"] != _sha256(unsigned):
        raise PipelineError(
            "predecessor LFS transfer proof digest changed"
        )
    return proof


def _assert_predecessor_lfs_transfer_bound(
    root: Path,
    predecessor_commit: str,
) -> dict[str, Any]:
    """Prove the predecessor could not hydrate public Git LFS objects."""
    scan_source = bytes(
        _git(
            root,
            "show",
            predecessor_commit + ":collector/scan.py",
            text=False,
        )
    )
    cache_source = bytes(
        _git(
            root,
            "show",
            predecessor_commit + ":collector/repo_cache.py",
            text=False,
        )
    )
    try:
        scan_tree = ast.parse(scan_source)
        cache_tree = ast.parse(cache_source)
    except (SyntaxError, ValueError) as exc:
        raise PipelineError(
            "predecessor LFS transfer source is not valid Python"
        ) from exc
    git_auth_functions = [
        node
        for node in scan_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_git_auth_env"
    ]
    if len(git_auth_functions) != 1:
        raise PipelineError(
            "predecessor lacks one audited Git environment function"
        )
    skip_assignments = []
    for node in ast.walk(git_auth_functions[0]):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "env"
                and isinstance(target.slice, ast.Constant)
                and target.slice.value == "GIT_LFS_SKIP_SMUDGE"
            ):
                skip_assignments.append(node.value)
    if (
        len(skip_assignments) != 1
        or not isinstance(skip_assignments[0], ast.Constant)
        or skip_assignments[0].value != "1"
    ):
        raise PipelineError(
            "predecessor did not force Git LFS smudge off"
        )
    imported_git_env = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "scan"
        and any(alias.name == "_git_auth_env" for alias in node.names)
        for node in cache_tree.body
    )
    cache_functions = {
        node.name: node
        for node in ast.walk(cache_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"_run", "checkout"}
    }
    if not imported_git_env or set(cache_functions) != {"_run", "checkout"}:
        raise PipelineError(
            "predecessor checkout LFS control flow is incomplete"
        )
    if not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_git_auth_env"
        for node in ast.walk(cache_functions["_run"])
    ):
        raise PipelineError(
            "predecessor checkout did not use the audited Git environment"
        )
    lfs_tokens = []
    for node in ast.walk(cache_tree):
        values = []
        if isinstance(node, ast.Name):
            values.append(node.id)
        elif isinstance(node, ast.Attribute):
            values.append(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.append(node.value)
        lfs_tokens.extend(
            value for value in values if "lfs" in value.casefold()
        )
    if lfs_tokens:
        raise PipelineError(
            "predecessor checkout contains an unaudited LFS hydration path"
        )
    semantic = _semantic_node_digests(scan_source)
    cache_semantic = _semantic_node_digests(cache_source)
    for label, nodes, name in (
        ("git auth", semantic, "_git_auth_env"),
        ("cache run", cache_semantic, "_run"),
        ("cache checkout", cache_semantic, "RepoCache.checkout"),
    ):
        if name not in nodes:
            raise PipelineError(
                "predecessor lacks audited " + label + " semantics"
            )
    proof = {
        "version": 1,
        "predecessor_source_commit": predecessor_commit,
        "scan_source_sha256": hashlib.sha256(scan_source).hexdigest(),
        "repo_cache_source_sha256": hashlib.sha256(
            cache_source
        ).hexdigest(),
        "git_auth_env_semantic_sha256": semantic["_git_auth_env"],
        "repo_cache_run_semantic_sha256": cache_semantic["_run"],
        "repo_cache_checkout_semantic_sha256": (
            cache_semantic["RepoCache.checkout"]
        ),
        "git_lfs_skip_smudge": "1",
        "public_lfs_hydration": "absent",
    }
    proof["contract_sha256"] = _sha256(proof)
    return _validate_predecessor_lfs_transfer_bound(proof)


def _reviewed_semantic_changes(
    root: Path,
    predecessor_commit: str,
    profile: Mapping[str, tuple[str, ...]],
    *,
    added_paths: frozenset[str] = frozenset(),
) -> dict[str, list[str]]:
    """Return exact AST-node changes, proving reviewed additions are new."""
    changes: dict[str, list[str]] = {}
    for path in sorted(profile):
        predecessor_tree = bytes(
            _git(
                root,
                "ls-tree",
                "-z",
                "--full-tree",
                predecessor_commit,
                "--",
                path,
                text=False,
            )
        )
        predecessor_exists = bool(predecessor_tree)
        if path in added_paths:
            if predecessor_exists:
                raise PipelineError(
                    "cohort remediation expected an added source path: "
                    + path
                )
            predecessor_semantic: dict[str, str] = {}
        else:
            if not predecessor_exists:
                raise PipelineError(
                    "cohort remediation predecessor lacks audited source: "
                    + path
                )
            predecessor_semantic = _semantic_node_digests(
                bytes(
                    _git(
                        root,
                        "show",
                        predecessor_commit + ":" + path,
                        text=False,
                    )
                )
            )
        current_path = root / path
        if not current_path.is_file():
            raise PipelineError(
                "cohort remediation successor lacks audited source: "
                + path
            )
        successor_semantic = _semantic_node_digests(
            current_path.read_bytes()
        )
        changed = sorted(
            name
            for name in set(predecessor_semantic) | set(successor_semantic)
            if predecessor_semantic.get(name)
            != successor_semantic.get(name)
        )
        if changed:
            changes[path] = changed
    return changes


def _assert_content_diagnostic_paths(
    changed_paths: tuple[str, ...],
) -> None:
    """Refuse any unreviewed production or support path for this profile."""
    changed = set(changed_paths)
    production = {
        path for path in changed
        if path.startswith("collector/")
    }
    if production != _CONTENT_DIAGNOSTIC_PRODUCTION_PATHS:
        missing = sorted(
            _CONTENT_DIAGNOSTIC_PRODUCTION_PATHS - production
        )
        unexpected = sorted(
            production - _CONTENT_DIAGNOSTIC_PRODUCTION_PATHS
        )
        raise PipelineError(
            "cohort content/diagnostic recovery changed an inexact "
            "production source set"
            + ("; missing=" + ",".join(missing) if missing else "")
            + (
                "; unexpected=" + ",".join(unexpected)
                if unexpected else ""
            )
        )
    unexpected_support = sorted(
        changed
        - _CONTENT_DIAGNOSTIC_PRODUCTION_PATHS
        - _CONTENT_DIAGNOSTIC_SUPPORT_PATHS
    )
    if unexpected_support:
        raise PipelineError(
            "cohort content/diagnostic recovery changed unreviewed "
            "support paths: " + ",".join(unexpected_support)
        )
    missing_support = sorted(
        _CONTENT_DIAGNOSTIC_REQUIRED_SUPPORT_PATHS - changed
    )
    if missing_support:
        raise PipelineError(
            "cohort content/diagnostic recovery lacks reviewed support "
            "paths: " + ",".join(missing_support)
        )


def _assert_reviewed_source_sha256(
    root: Path,
    expected: Mapping[str, str],
) -> dict[str, str]:
    """Fail closed unless every reviewed successor source byte is exact."""
    actual: dict[str, str] = {}
    for path, expected_sha256 in sorted(expected.items()):
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_sha256
            )
        ):
            raise PipelineError(
                "cohort remediation has an invalid reviewed source hash: "
                + path
            )
        source = root / path
        if not source.is_file():
            raise PipelineError(
                "cohort remediation successor lacks reviewed source: "
                + path
            )
        actual_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise PipelineError(
                "cohort remediation changed reviewed source bytes: "
                + path
            )
        actual[path] = actual_sha256
    return actual


def _is_content_diagnostic_candidate(
    root: Path,
    predecessor_commit: str,
    changed_paths: tuple[str, ...],
    *,
    scan_runtime_remediation: bool,
) -> bool:
    """Identify only the original profile that added the shared parser."""
    if (
        not scan_runtime_remediation
        or "collector/evidence_content.py" not in changed_paths
    ):
        return False
    predecessor_tree = bytes(
        _git(
            root,
            "ls-tree",
            "-z",
            "--full-tree",
            predecessor_commit,
            "--",
            "collector/evidence_content.py",
            text=False,
        )
    )
    return not bool(predecessor_tree)


def _assert_content_diagnostic_source_bytes(
    root: Path,
) -> dict[str, str]:
    expected_paths = (
        _CONTENT_DIAGNOSTIC_PRODUCTION_PATHS
        - {"collector/successor.py"}
    )
    if (
        set(_CONTENT_DIAGNOSTIC_SUCCESSOR_SOURCE_SHA256)
        != expected_paths
    ):
        raise PipelineError(
            "cohort content/diagnostic reviewed source hash set is "
            "incomplete"
        )
    actual = _assert_reviewed_source_sha256(
        root,
        _CONTENT_DIAGNOSTIC_SUCCESSOR_SOURCE_SHA256,
    )
    successor_path = root / "collector" / "successor.py"
    if not successor_path.is_file():
        raise PipelineError(
            "cohort remediation successor lacks audited source: "
            "collector/successor.py"
        )
    source = successor_path.read_bytes()
    reviewed = (
        _CONTENT_DIAGNOSTIC_SUCCESSOR_NORMALIZED_SHA256.encode("ascii")
    )
    if source.count(reviewed) != 1:
        raise PipelineError(
            "cohort remediation successor digest marker is ambiguous"
        )
    normalized = source.replace(reviewed, b"0" * 64)
    normalized_sha256 = hashlib.sha256(normalized).hexdigest()
    if (
        normalized_sha256
        != _CONTENT_DIAGNOSTIC_SUCCESSOR_NORMALIZED_SHA256
    ):
        raise PipelineError(
            "cohort remediation changed reviewed source bytes: "
            "collector/successor.py"
        )
    actual["collector/successor.py"] = normalized_sha256
    return actual


def _cohort_successor_source_audit(
    root: Path,
    predecessor_source_ref: str,
    expected_predecessor_network_sha256: str,
    *,
    metadata_remediation: bool = False,
    identity_scan_remediation: bool = False,
    control_plane_remediation: bool = False,
    scan_runtime_remediation: bool = False,
    candidate_policy_remediation: bool = False,
    preflight_reuse_remediation: bool = False,
    preflight_budget_remediation: bool = False,
    checkpoint_continuation_remediation: bool = False,
) -> dict[str, Any]:
    """Prove task execution stayed exact despite downstream cohort changes."""
    if not predecessor_source_ref or predecessor_source_ref.startswith("-"):
        raise PipelineError("predecessor source ref is invalid")
    dirty = str(
        _git(root, "status", "--porcelain", "--untracked-files=no")
    ).strip()
    if dirty:
        raise PipelineError(
            "cohort successor requires a clean tracked worktree"
        )
    predecessor_commit = str(
        _git(
            root,
            "rev-parse",
            "--verify",
            predecessor_source_ref + "^{commit}",
        )
    ).strip()
    current_commit = str(
        _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    ).strip()
    ancestor = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            predecessor_commit,
            current_commit,
        ],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if ancestor.returncode != 0:
        raise PipelineError(
            "predecessor source ref is not an ancestor of current HEAD"
        )
    changed_paths = tuple(
        sorted(
            line
            for line in str(
                _git(
                    root,
                    "diff",
                    "--name-only",
                    predecessor_commit + ".." + current_commit,
                )
            ).splitlines()
            if line
        )
    )
    content_diagnostic_candidate = _is_content_diagnostic_candidate(
        root,
        predecessor_commit,
        changed_paths,
        scan_runtime_remediation=scan_runtime_remediation,
    )
    unexpected = sorted(
        set(changed_paths) - _COHORT_SUCCESSOR_ALLOWED_PATHS
    )
    if unexpected:
        raise PipelineError(
            "cohort successor changed unapproved source paths: "
            + ",".join(unexpected)
        )
    if identity_scan_remediation and not metadata_remediation:
        raise PipelineError(
            "identity/scan recovery requires a cohort predecessor"
        )
    if control_plane_remediation and not identity_scan_remediation:
        raise PipelineError(
            "control-plane recovery requires the identity/scan path"
        )
    if scan_runtime_remediation and not identity_scan_remediation:
        raise PipelineError(
            "scan-runtime recovery requires the identity/scan path"
        )
    if candidate_policy_remediation and not identity_scan_remediation:
        raise PipelineError(
            "candidate-policy recovery requires the identity/scan path"
        )
    if preflight_reuse_remediation and not identity_scan_remediation:
        raise PipelineError(
            "preflight-reuse recovery requires the identity/scan path"
        )
    if preflight_budget_remediation and not identity_scan_remediation:
        raise PipelineError(
            "preflight-budget recovery requires the identity/scan path"
        )
    if sum(bool(value) for value in (
        control_plane_remediation,
        scan_runtime_remediation,
        candidate_policy_remediation,
        preflight_reuse_remediation,
        preflight_budget_remediation,
    )) > 1:
        raise PipelineError(
            "control-plane, scan-runtime, candidate-policy, preflight-reuse, "
            "and preflight-budget recovery are mutually exclusive"
        )
    if preflight_budget_remediation:
        required_changes = {
            "collector/cli.py",
            "collector/successor.py",
            "docs/Documentation.md",
            "docs/PROJECT-CONTEXT.md",
            "docs/REQ14-V2-REVISION.md",
            "test_req14_content_successor.py",
            "test_req14_successor.py",
        }
        if set(changed_paths) != required_changes:
            raise PipelineError(
                "cohort preflight-budget recovery changed unreviewed paths: "
                + ",".join(changed_paths)
            )
    elif preflight_reuse_remediation:
        required_changes = {
            "collector/cli.py",
            "collector/successor.py",
            "test_req14_successor.py",
        }
        if set(changed_paths) != required_changes:
            raise PipelineError(
                "cohort preflight-reuse recovery changed unreviewed paths: "
                + ",".join(changed_paths)
            )
    elif candidate_policy_remediation:
        required_changes = {
            "collector/catalog.py",
            "collector/cli.py",
            "collector/pipeline.py",
            "collector/req14_evidence_contract.json",
            "collector/successor.py",
            "docs/Documentation.md",
            "docs/REQ14-PHASE8-READINESS.md",
            "docs/REQ14-V2-REVISION.md",
            "ops/req14_detector_fingerprints.json",
            "test_req14_evidence_contract.py",
            "test_req14_pipeline.py",
            "test_req14_successor.py",
        }
    elif scan_runtime_remediation:
        # The exact profile is derived from semantic-node deltas below; its
        # profile-specific source/test/doc set is enforced after that match.
        required_changes = set()
    elif control_plane_remediation:
        required_changes = {
            "collector/cli.py",
            "collector/pipeline.py",
            "collector/successor.py",
            "test_req14_pipeline.py",
            "test_req14_successor.py",
        }
    elif identity_scan_remediation:
        required_changes = {
            "collector/cli.py",
            "collector/pipeline.py",
            "collector/scan.py",
            "collector/scanner_v2.py",
            "collector/state.py",
            "collector/successor.py",
            "collector/triage.py",
            "test_req14_pipeline.py",
            "test_req14_scanner.py",
            "test_req14_successor.py",
        }
    elif metadata_remediation:
        required_changes = {
            "collector/github_client.py",
            "collector/pipeline.py",
            "collector/successor.py",
            "test_req14_discovery.py",
            "test_req14_pipeline.py",
        }
    else:
        required_changes = {
            "collector/cli.py",
            "collector/pipeline.py",
            "collector/successor.py",
            "collector/validate_v2.py",
        }
    if not required_changes <= set(changed_paths):
        raise PipelineError(
            "cohort successor lacks the reviewed execution/publication changes"
        )

    predecessor_payloads = {
        path: bytes(
            _git(
                root,
                "show",
                predecessor_commit + ":" + path,
                text=False,
            )
        )
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    predecessor_network_sha256 = _source_payload_sha256(
        predecessor_payloads,
        _CURRENT_NETWORK_TASK_PATHS,
    )
    if predecessor_network_sha256 != expected_predecessor_network_sha256:
        raise PipelineError(
            "predecessor source ref does not reproduce its recorded "
            "network executable"
        )
    current_payloads = {
        path: (root / path).read_bytes()
        for path in _CURRENT_NETWORK_TASK_PATHS
    }
    changed_network_paths = sorted(
        path
        for path in _CURRENT_NETWORK_TASK_PATHS
        if predecessor_payloads[path] != current_payloads[path]
    )
    if content_diagnostic_candidate:
        expected_network_paths = ["collector/pipeline.py"]
    elif checkpoint_continuation_remediation:
        expected_network_paths = ["collector/pipeline.py"]
    elif (
        scan_runtime_remediation
        or preflight_reuse_remediation
        or preflight_budget_remediation
    ):
        expected_network_paths = []
    else:
        expected_network_paths = (
            ["collector/pipeline.py"]
            if (
                identity_scan_remediation
                or candidate_policy_remediation
            )
            else (
                ["collector/github_client.py", "collector/pipeline.py"]
                if metadata_remediation
                else ["collector/pipeline.py"]
            )
        )
    if changed_network_paths != expected_network_paths:
        raise PipelineError(
            "cohort successor changed discovery transport/query sources: "
            + ",".join(changed_network_paths)
        )
    predecessor_nodes = _pipeline_node_digests(
        predecessor_payloads["collector/pipeline.py"]
    )
    successor_nodes = _pipeline_node_digests(
        current_payloads["collector/pipeline.py"]
    )
    changed_discovery_nodes = sorted(
        name
        for name in set(predecessor_nodes) | set(successor_nodes)
        if predecessor_nodes.get(name) != successor_nodes.get(name)
    )
    expected_discovery_changes = (
        []
        if (
            control_plane_remediation
            or scan_runtime_remediation
            or candidate_policy_remediation
            or preflight_reuse_remediation
            or preflight_budget_remediation
        )
        else (
            ["_durable_discovery_request_usage"]
            if identity_scan_remediation
            else []
        )
    )
    if changed_discovery_nodes != expected_discovery_changes:
        raise PipelineError(
            "cohort successor changed discovery task semantics: "
            + ",".join(changed_discovery_nodes)
        )
    if (
        identity_scan_remediation
        and not control_plane_remediation
        and not scan_runtime_remediation
        and not candidate_policy_remediation
        and (
            _normalized_discovery_usage_digest(
                predecessor_payloads["collector/pipeline.py"]
            )
            != _normalized_discovery_usage_digest(
                current_payloads["collector/pipeline.py"]
            )
        )
    ):
        raise PipelineError(
            "cohort recovery changed discovery accounting beyond its "
            "task-stage restriction"
        )
    if control_plane_remediation:
        predecessor_semantic = _semantic_node_digests(
            predecessor_payloads["collector/pipeline.py"]
        )
        successor_semantic = _semantic_node_digests(
            current_payloads["collector/pipeline.py"]
        )
        changed_non_import_nodes = sorted(
            name
            for name in set(predecessor_semantic) | set(successor_semantic)
            if (
                not name.startswith("<module>.Import:")
                and predecessor_semantic.get(name)
                != successor_semantic.get(name)
            )
        )
        added_imports = (
            _module_import_names(
                current_payloads["collector/pipeline.py"]
            )
            - _module_import_names(
                predecessor_payloads["collector/pipeline.py"]
            )
        )
        removed_imports = (
            _module_import_names(
                predecessor_payloads["collector/pipeline.py"]
            )
            - _module_import_names(
                current_payloads["collector/pipeline.py"]
            )
        )
        if (
            changed_non_import_nodes
            or added_imports != {"re"}
            or removed_imports
        ):
            raise PipelineError(
                "cohort control-plane recovery changed executable "
                "semantics beyond the missing re import"
            )
    scan_runtime_changes = {}
    scan_runtime_kind = None
    content_task_semantics = {}
    content_source_sha256 = {}
    predecessor_lfs_transfer_bound = None
    if scan_runtime_remediation:
        scan_runtime_profiles = {
            **_SCAN_RUNTIME_REMEDIATION_PROFILES,
            _CONTENT_DIAGNOSTIC_REMEDIATION_KIND: (
                _CONTENT_DIAGNOSTIC_REMEDIATION_PROFILE
            ),
        }
        audited_paths = sorted({
            path
            for profile in scan_runtime_profiles.values()
            for path in profile
        })
        scan_runtime_changes = _reviewed_semantic_changes(
            root,
            predecessor_commit,
            {path: () for path in audited_paths},
            added_paths=(
                _CONTENT_DIAGNOSTIC_ADDED_PATHS
                if content_diagnostic_candidate
                else frozenset()
            ),
        )
        matching_profiles = [
            kind
            for kind, profile in scan_runtime_profiles.items()
            if scan_runtime_changes == {
                path: list(nodes)
                for path, nodes in profile.items()
            }
        ]
        if len(matching_profiles) != 1:
            rendered = ",".join(
                "%s=[%s]" % (path, ",".join(nodes))
                for path, nodes in sorted(scan_runtime_changes.items())
            )
            raise PipelineError(
                "cohort scan-runtime recovery changed unreviewed "
                "semantics: " + (rendered or "none")
            )
        scan_runtime_kind = matching_profiles[0]
        if scan_runtime_kind == _CONTENT_DIAGNOSTIC_REMEDIATION_KIND:
            _assert_content_diagnostic_paths(changed_paths)
            content_source_sha256 = (
                _assert_content_diagnostic_source_bytes(root)
            )
            content_task_semantics = (
                _assert_exact_network_task_semantics(
                    predecessor_payloads["collector/pipeline.py"],
                    current_payloads["collector/pipeline.py"],
                )
            )
            predecessor_lfs_transfer_bound = (
                _assert_predecessor_lfs_transfer_bound(
                    root,
                    predecessor_commit,
                )
            )
        else:
            required_scan_runtime_paths = (
                _SCAN_RUNTIME_REMEDIATION_REQUIRED_PATHS[
                    scan_runtime_kind
                ]
            )
            if not required_scan_runtime_paths <= set(changed_paths):
                raise PipelineError(
                    "cohort scan-runtime recovery lacks reviewed profile "
                    "paths: "
                    + ",".join(
                        sorted(
                            required_scan_runtime_paths - set(changed_paths)
                        )
                    )
                )
    candidate_policy_changes = {}
    if candidate_policy_remediation:
        expected_candidate_policy_changes = {
            "collector/catalog.py": [
                "<module>.For:4",
                "<module>.Import:3",
            ],
            "collector/pipeline.py": [
                "CollectorPipeline._persist_candidates",
                "_discovery_observation_excluded",
            ],
        }
        for path in sorted(expected_candidate_policy_changes):
            predecessor_semantic = _semantic_node_digests(
                bytes(
                    _git(
                        root,
                        "show",
                        predecessor_commit + ":" + path,
                        text=False,
                    )
                )
            )
            successor_semantic = _semantic_node_digests(
                (root / path).read_bytes()
            )
            changed = sorted(
                name
                for name in (
                    set(predecessor_semantic)
                    | set(successor_semantic)
                )
                if predecessor_semantic.get(name)
                != successor_semantic.get(name)
            )
            if changed:
                candidate_policy_changes[path] = changed
        if candidate_policy_changes != expected_candidate_policy_changes:
            rendered = ",".join(
                "%s=[%s]" % (path, ",".join(nodes))
                for path, nodes in sorted(
                    candidate_policy_changes.items()
                )
            )
            raise PipelineError(
                "cohort candidate-policy recovery changed unreviewed "
                "semantics: " + (rendered or "none")
            )
    preflight_reuse_changes = {}
    if preflight_reuse_remediation:
        for path in sorted(_PREFLIGHT_REUSE_REMEDIATION_PROFILE):
            predecessor_semantic = _semantic_node_digests(
                bytes(
                    _git(
                        root,
                        "show",
                        predecessor_commit + ":" + path,
                        text=False,
                    )
                )
            )
            successor_semantic = _semantic_node_digests(
                (root / path).read_bytes()
            )
            changed = sorted(
                name
                for name in (
                    set(predecessor_semantic)
                    | set(successor_semantic)
                )
                if predecessor_semantic.get(name)
                != successor_semantic.get(name)
            )
            if changed:
                preflight_reuse_changes[path] = changed
        expected = {
            path: list(nodes)
            for path, nodes in _PREFLIGHT_REUSE_REMEDIATION_PROFILE.items()
        }
        if preflight_reuse_changes != expected:
            rendered = ",".join(
                "%s=[%s]" % (path, ",".join(nodes))
                for path, nodes in sorted(
                    preflight_reuse_changes.items()
                )
            )
            raise PipelineError(
                "cohort preflight-reuse recovery changed unreviewed "
                "semantics: " + (rendered or "none")
            )
    preflight_budget_changes = {}
    if preflight_budget_remediation:
        expected_preflight_budget_changes = {
            "collector/cli.py": [
                "_prepare_phase8_cohort_recovery_successor",
                "build_parser",
            ],
            "collector/successor.py": [
                "<module>.Assign:24",
                "_cohort_successor_source_audit",
                "prepare_phase8_cohort_successor",
            ],
        }
        for path in sorted(expected_preflight_budget_changes):
            predecessor_semantic = _semantic_node_digests(
                bytes(
                    _git(
                        root,
                        "show",
                        predecessor_commit + ":" + path,
                        text=False,
                    )
                )
            )
            successor_semantic = _semantic_node_digests(
                (root / path).read_bytes()
            )
            changed = sorted(
                name
                for name in (
                    set(predecessor_semantic)
                    | set(successor_semantic)
                )
                if predecessor_semantic.get(name)
                != successor_semantic.get(name)
            )
            if changed:
                preflight_budget_changes[path] = changed
        if preflight_budget_changes != expected_preflight_budget_changes:
            rendered = ",".join(
                "%s=[%s]" % (path, ",".join(nodes))
                for path, nodes in sorted(
                    preflight_budget_changes.items()
                )
            )
            raise PipelineError(
                "cohort preflight-budget recovery changed unreviewed "
                "semantics: " + (rendered or "none")
            )
    metadata_execution_nodes = {}
    if identity_scan_remediation:
        predecessor_metadata_nodes = _metadata_task_execution_digests(
            predecessor_payloads["collector/pipeline.py"]
        )
        successor_metadata_nodes = _metadata_task_execution_digests(
            current_payloads["collector/pipeline.py"]
        )
        if predecessor_metadata_nodes != successor_metadata_nodes:
            changed = sorted(
                name
                for name in (
                    set(predecessor_metadata_nodes)
                    | set(successor_metadata_nodes)
                )
                if predecessor_metadata_nodes.get(name)
                != successor_metadata_nodes.get(name)
            )
            raise PipelineError(
                "cohort recovery changed metadata task execution: "
                + ",".join(changed)
            )
        metadata_execution_nodes = predecessor_metadata_nodes
    if predecessor_nodes != successor_nodes and not identity_scan_remediation:
        changed = sorted(
            name
            for name in set(predecessor_nodes) | set(successor_nodes)
            if predecessor_nodes.get(name) != successor_nodes.get(name)
        )
        raise PipelineError(
            "cohort successor changed discovery task semantics: "
            + ",".join(changed)
        )
    github_node_changes: list[str] = []
    if metadata_remediation and not identity_scan_remediation:
        predecessor_github_nodes = _semantic_node_digests(
            predecessor_payloads["collector/github_client.py"]
        )
        successor_github_nodes = _semantic_node_digests(
            current_payloads["collector/github_client.py"]
        )
        github_node_changes = sorted(
            name
            for name in (
                set(predecessor_github_nodes)
                | set(successor_github_nodes)
            )
            if predecessor_github_nodes.get(name)
            != successor_github_nodes.get(name)
        )
        if github_node_changes != [
            "GitHubGraphQLClient._partial_errors"
        ]:
            raise PipelineError(
                "metadata remediation changed unreviewed GitHub client "
                "semantics: " + ",".join(github_node_changes)
            )
    current_network_sha256 = _network_task_source_sha256()
    content_diagnostic_remediation = (
        scan_runtime_kind == _CONTENT_DIAGNOSTIC_REMEDIATION_KIND
    )
    if (
        (
            scan_runtime_remediation
            or preflight_reuse_remediation
            or preflight_budget_remediation
        )
        and current_network_sha256 != predecessor_network_sha256
        and not content_diagnostic_remediation
        and not checkpoint_continuation_remediation
    ):
        raise PipelineError(
            "cohort non-network recovery changed the network executable"
        )
    if (
        content_diagnostic_remediation
        and current_network_sha256 == predecessor_network_sha256
    ):
        raise PipelineError(
            "cohort content/diagnostic recovery did not record its "
            "audited pipeline diagnostics"
        )
    if (
        not scan_runtime_remediation
        and not preflight_reuse_remediation
        and not preflight_budget_remediation
        and current_network_sha256 == predecessor_network_sha256
    ):
        raise PipelineError(
            "cohort successor executable did not record its downstream change"
        )
    if control_plane_remediation:
        remediation_kind = "preseed-contract-validator-import"
    elif preflight_budget_remediation:
        remediation_kind = "lineage-scan-budget-preflight"
    elif preflight_reuse_remediation:
        remediation_kind = "effective-detector-preflight-reuse"
    elif candidate_policy_remediation:
        remediation_kind = "library-scoped-discovery-provenance"
    elif scan_runtime_remediation:
        remediation_kind = scan_runtime_kind
    elif identity_scan_remediation:
        remediation_kind = "candidate-identity-and-scan-reliability"
    elif metadata_remediation:
        remediation_kind = "github-alias-not-found"
    else:
        remediation_kind = "partial-cohort"
    return {
        "predecessor_source_ref": predecessor_source_ref,
        "predecessor_source_commit": predecessor_commit,
        "successor_source_commit": current_commit,
        "changed_paths": list(changed_paths),
        "changed_network_paths": changed_network_paths,
        "raw_network_source_changed": (
            current_network_sha256 != predecessor_network_sha256
        ),
        "predecessor_network_task_source_sha256": (
            predecessor_network_sha256
        ),
        "successor_network_task_source_sha256": current_network_sha256,
        "discovery_pipeline_node_sha256": predecessor_nodes,
        "discovery_pipeline_nodes_sha256": _sha256(predecessor_nodes),
        "changed_discovery_pipeline_nodes": changed_discovery_nodes,
        "discovery_accounting_stage_filter_only": (
            identity_scan_remediation
            and not control_plane_remediation
            and not scan_runtime_remediation
            and not candidate_policy_remediation
            and not preflight_reuse_remediation
            and not preflight_budget_remediation
        ),
        "control_plane_import_only": control_plane_remediation,
        "scan_runtime_only": scan_runtime_remediation,
        "checkpoint_continuation_only": (
            checkpoint_continuation_remediation
        ),
        "content_diagnostic_semantics_only": (
            content_diagnostic_remediation
        ),
        "content_diagnostic_task_semantics": content_task_semantics,
        "content_diagnostic_source_sha256": content_source_sha256,
        "predecessor_lfs_transfer_bound": (
            predecessor_lfs_transfer_bound
        ),
        "candidate_policy_only": candidate_policy_remediation,
        "preflight_reuse_only": preflight_reuse_remediation,
        "preflight_budget_only": preflight_budget_remediation,
        "scan_runtime_changed_semantic_nodes": scan_runtime_changes,
        "candidate_policy_changed_semantic_nodes": (
            candidate_policy_changes
        ),
        "preflight_reuse_changed_semantic_nodes": (
            preflight_reuse_changes
        ),
        "preflight_budget_changed_semantic_nodes": (
            preflight_budget_changes
        ),
        "metadata_task_execution_node_sha256": (
            metadata_execution_nodes
        ),
        "metadata_task_execution_nodes_sha256": (
            _sha256(metadata_execution_nodes)
            if metadata_execution_nodes
            else None
        ),
        "github_client_changed_semantic_nodes": github_node_changes,
        "remediation_kind": remediation_kind,
        "per_task_execution_equivalent": True,
    }


def _live_release_id(data_dir: Path) -> str:
    manifest_path = data_dir / "v2" / "manifest.json"
    if not manifest_path.exists():
        return NO_LIVE_V2_RELEASE
    try:
        release_id = json.loads(manifest_path.read_text())["release"]["id"]
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise PipelineError(
            "live V2 manifest has no valid base release"
        ) from exc
    if (
        not isinstance(release_id, str)
        or not release_id
        or release_id != release_id.strip()
    ):
        raise PipelineError("live V2 manifest has no valid base release")
    return release_id


def _discovery_specs(libraries) -> list[dict[str, Any]]:
    specs = []
    for library in libraries:
        for pack in query_packs(library):
            sourcegraph_fp = sourcegraph_query_fingerprint(pack)
            specs.append(
                {
                    "source": "sourcegraph",
                    "library_id": library["id"],
                    "signal_id": pack.signal_id,
                    "query": pack.sourcegraph_query,
                    "query_fingerprint": sourcegraph_fp,
                    "extensions": [],
                    "pack_kind": pack.kind,
                    "member_signal_ids": list(pack.member_signal_ids),
                }
            )
            github_fp = github_query_fingerprint(pack)
            specs.append(
                {
                    "source": "github-code-search",
                    "library_id": library["id"],
                    "signal_id": pack.signal_id,
                    "query": pack.github_query,
                    "query_fingerprint": github_fp,
                    "extensions": list(pack.extensions),
                    "pack_kind": pack.kind,
                    "member_signal_ids": list(pack.member_signal_ids),
                }
            )
    return specs


def _query_execution_equivalence(libraries) -> dict[str, Any]:
    """Prove each packed GitHub query is the OR of its exact member lanes."""
    records = []
    for library in libraries:
        members = {
            member.signal_id: member.github_query
            for member in signal_specs(library)
        }
        for pack in query_packs(library):
            member_queries = tuple(
                members[member_id]
                for member_id in pack.member_signal_ids
            )
            if " OR ".join(member_queries) != pack.github_query:
                raise PipelineError(
                    "GitHub member queries do not reproduce a logical pack"
                )
            records.append(
                {
                    "library_id": library["id"],
                    "query_fingerprint": github_query_fingerprint(pack),
                    "member_signal_ids": list(pack.member_signal_ids),
                    "member_queries_sha256": _sha256(member_queries),
                    "logical_query_sha256": hashlib.sha256(
                        pack.github_query.encode("utf-8")
                    ).hexdigest(),
                }
            )
    return {
        "version": 1,
        "logical_operator": "OR",
        "pack_count": len(records),
        "multi_member_pack_count": sum(
            len(record["member_signal_ids"]) > 1
            for record in records
        ),
        "records_sha256": _sha256(records),
    }


def _task_key(spec: Mapping[str, Any]) -> str:
    prefix = "sg" if spec["source"] == "sourcegraph" else "github"
    return "%s:%s:%s" % (
        prefix,
        spec["library_id"],
        spec["query_fingerprint"],
    )


def _public_only_result(
    document: Mapping[str, Any],
    spec: Mapping[str, Any],
    *,
    source_policy: str,
) -> tuple[Any, int]:
    result = _discovery_result_from_task_result(document)
    _assert_discovery_task_result(result, spec)
    certificate = result.certificate
    observations = (
        tuple(result.observations)
        + tuple(result.quarantined_observations)
    )
    if any(
        observation.visibility.lower() != "public"
        for observation in observations
    ):
        raise PipelineError("inherited discovery evidence is not public-only")
    if not certificate.terminal or certificate.epoch_completed_at is None:
        raise PipelineError("inherited discovery result is not terminal")
    if source_policy == "required":
        uncapped = all(
            partition.complete
            and not (partition.capped and not partition.subdivided)
            for partition in certificate.partitions
        )
        if (
            not certificate.complete
            or certificate.gaps
            or not uncapped
            or result.quarantined_observations
        ):
            raise PipelineError(
                "required inherited discovery result is partial, capped, "
                "gapped, or quarantined"
            )
    request_count = max(
        1,
        int(certificate.metrics.get("request_count", 0) or 0),
    )
    return result, request_count


def _validated_metadata_task(
    row: Mapping[str, Any],
    *,
    ordinal: int,
) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """Revalidate one exact, complete, public-safe metadata document."""
    if row["status"] != "complete" or row["result_json"] is None:
        raise PipelineError(
            "metadata predecessor task is not a completed result"
        )
    try:
        payload = json.loads(row["payload_json"])
        document = json.loads(row["result_json"])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "inherited metadata task is not valid JSON"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "lookups"}
        or payload.get("version") != 1
        or not isinstance(payload.get("lookups"), list)
        or not 1 <= len(payload["lookups"]) <= METADATA_BATCH_SIZE
    ):
        raise PipelineError(
            "inherited metadata task payload is malformed"
        )
    lookups = []
    for raw in payload["lookups"]:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"node_id", "full_name"}
            or (
                raw["node_id"] is not None
                and (
                    not isinstance(raw["node_id"], str)
                    or not raw["node_id"]
                )
            )
            or (
                raw["full_name"] is not None
                and (
                    not isinstance(raw["full_name"], str)
                    or not raw["full_name"]
                )
            )
            or (
                raw["node_id"] is None
                and raw["full_name"] is None
            )
        ):
            raise PipelineError(
                "inherited metadata lookup is malformed"
            )
        lookups.append(
            RepositoryLookup(
                node_id=raw["node_id"],
                full_name=raw["full_name"],
            )
        )
    lookup_keys = [lookup.key for lookup in lookups]
    if len(lookup_keys) != len(set(lookup_keys)):
        raise PipelineError(
            "inherited metadata task has duplicate lookups"
        )
    payload_fp = fingerprint("github-metadata-task", payload)
    expected_task_key = "batch:%06d:%s" % (
        ordinal,
        payload_fp[:32],
    )
    if row["task_key"] != expected_task_key:
        raise PipelineError(
            "inherited metadata task key does not match its payload"
        )
    if not isinstance(document, dict):
        raise PipelineError(
            "inherited metadata result is malformed"
        )
    resolution = _metadata_result_from_task_result(document)
    if canonical_json(
        _metadata_result_to_task_result(resolution)
    ) != canonical_json(document):
        raise PipelineError(
            "inherited metadata result is not canonical or public-safe"
        )
    result_keys = [
        repository.request_key
        for repository in resolution.repositories
    ]
    if (
        len(result_keys) != len(set(result_keys))
        or set(result_keys) != set(lookup_keys)
        or not resolution.complete
        or resolution.request_count <= 0
        or resolution.points_used < 0
        or resolution.remaining < 0
    ):
        raise PipelineError(
            "inherited metadata result is incomplete or mismatched"
        )
    for repository in resolution.repositories:
        if repository.explicitly_public and (
            not repository.node_id
            or not repository.full_name
            or repository.visibility != "PUBLIC"
            or repository.is_private is not False
        ):
            raise PipelineError(
                "inherited public metadata identity is incomplete"
            )
    return payload, document, resolution


def _certify_completed_scan_checkpoint(
    *,
    state: StateDB,
    predecessor_run_id: str,
    predecessor_fingerprints: Mapping[str, Any],
    successor_plan,
    selected_library_ids: set[str],
    cache_root: Path,
    predecessor_source_ref: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], set[tuple[str, str, str]]]:
    """Prove and map the exact completed scan transactions at one checkpoint.

    This incident-specific path does not reinterpret a fingerprint as equal.
    It verifies the source task, exact attempt, atomic result/candidate/analysis
    postimages, and the only changed content surface before producing explicit
    target rows.  No attempt is synthesized and no network operation is
    permitted; promised objects are read with lazy fetching disabled.
    """
    if predecessor_run_id != _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY[
        "predecessor_run_id"
    ]:
        raise PipelineError(
            "scan checkpoint certificate is outside the reviewed incident"
        )
    import os
    import sys
    import types

    from . import evidence_content as current_content
    from .triage import (
        _bare_attribute_rows,
        _bare_config_value,
        _eligible,
    )

    predecessor_manifest = FingerprintManifest.from_dict(
        predecessor_fingerprints
    )
    predecessor_plan = types.SimpleNamespace(
        fingerprints=predecessor_manifest
    )
    old_source = bytes(
        _git(
            cache_root.parent.parent,
            "show",
            predecessor_source_ref + ":collector/evidence_content.py",
            text=False,
        )
    )
    old_content = types.ModuleType("_req14_predecessor_evidence_content")
    old_content.__file__ = (
        "<git:%s:collector/evidence_content.py>" % predecessor_source_ref
    )
    sys.modules[old_content.__name__] = old_content
    try:
        exec(
            compile(old_source, old_content.__file__, "exec"),
            old_content.__dict__,
        )
    finally:
        sys.modules.pop(old_content.__name__, None)

    def normalized_parser_outcome(module, raw):
        try:
            surfaces = module.parse_notebook_surfaces(raw)
            return {
                "status": "ok",
                "search_text": surfaces.search_text,
                "code_text": surfaces.code_text,
                "recovery": surfaces.recovery,
            }
        except Exception as exc:  # exact typed fail-closed equivalence
            return {
                "status": "error",
                "type": type(exc).__name__,
                "detail": str(exc),
            }

    tasks = list(state.connection.execute(
        """
        SELECT t.*, a.status AS attempt_status,
               a.usage_complete AS attempt_usage_complete,
               a.started_at AS attempt_started_at,
               a.finished_at AS attempt_finished_at,
               a.payload_sha256 AS attempt_payload_sha256,
               a.head_sha AS attempt_head_sha
        FROM tasks t JOIN scan_attempts a
          ON a.task_id=CAST(t.task_id AS TEXT)
         AND a.run_id=t.run_id AND a.attempt=t.attempts
        WHERE t.run_id=? AND t.stage='scan' AND t.status='complete'
        ORDER BY t.task_id
        """,
        (predecessor_run_id,),
    ))
    if len(tasks) != 37:
        raise PipelineError(
            "scan checkpoint completed-task universe changed"
        )

    task_proofs = []
    result_proofs = []
    candidate_proofs = []
    analysis_proofs = []
    target_rows = []
    compatible_pairs: set[tuple[str, str, str]] = set()
    notebook_rows = []
    parsed_oids: dict[str, dict[str, Any]] = {}
    classifications = Counter()
    object_environment = os.environ.copy()
    object_environment["GIT_NO_LAZY_FETCH"] = "1"

    for task in tasks:
        identity = _historical_scan_task_identity(state, task)
        payload = identity["payload"]
        candidate_library_ids = tuple(
            sorted(str(value) for value in payload.get("libraries", ()))
        )
        if (
            task["attempt_status"] != "complete"
            or task["attempt_usage_complete"] != 1
            or int(task["attempts"]) != 1
            or task["attempt_payload_sha256"]
            != identity["payload_sha256"]
            or task["attempt_head_sha"] != identity["head_sha"]
            or not candidate_library_ids
            or not set(candidate_library_ids) <= selected_library_ids
        ):
            raise PipelineError(
                "scan checkpoint task is not an exact completed attempt"
            )
        observed_fingerprints = {
            library_id: _library_fp_values(
                predecessor_plan, library_id
            )["detector"]
            for library_id in candidate_library_ids
        }
        expected_task_key = fingerprint(
            "scan-task-v2",
            {
                "repository_node_id": identity["repository_id"],
                "head_sha": identity["head_sha"],
                "candidate_library_ids": list(candidate_library_ids),
                "analysis_only": False,
                "ai_fingerprint": None,
                "detector_fingerprints": observed_fingerprints,
            },
        )
        if task["task_key"] != expected_task_key:
            raise PipelineError(
                "scan checkpoint task key does not match observed detector "
                "fingerprints"
            )

        scan_rows = list(state.connection.execute(
            """
            SELECT * FROM scan_results
            WHERE repository_id=? AND head_sha=?
              AND scanned_at>=? AND scanned_at<=?
            ORDER BY scan_result_id
            """,
            (
                identity["repository_id"],
                identity["head_sha"],
                task["attempt_finished_at"],
                task["finished_at"],
            ),
        ))
        if not scan_rows:
            raise PipelineError(
                "scan checkpoint task has no atomic result rows"
            )
        rows_by_library = {
            str(row["library_id"]): row for row in scan_rows
        }
        if len(rows_by_library) != len(scan_rows) or not set(
            candidate_library_ids
        ) <= set(rows_by_library):
            raise PipelineError(
                "scan checkpoint result rows do not cover the task payload"
            )
        for row in scan_rows:
            library_id = str(row["library_id"])
            observed_fp = _library_fp_values(
                predecessor_plan, library_id
            )["detector"]
            if row["status"] != "clean" or row["detector_fp"] != observed_fp:
                raise PipelineError(
                    "scan checkpoint row does not match its effective "
                    "predecessor detector"
                )
            try:
                evidence = json.loads(row["evidence_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PipelineError(
                    "scan checkpoint evidence is malformed"
                ) from exc
            document = {
                "scan_result_id": int(row["scan_result_id"]),
                "predecessor_task_id": int(task["task_id"]),
                "repository_id": str(row["repository_id"]),
                "library_id": library_id,
                "head_sha": str(row["head_sha"]),
                "detector_fp": str(row["detector_fp"]),
                "classification": str(row["classification"]),
                "status": str(row["status"]),
                "evidence": evidence,
                "raw_first_commit": row["raw_first_commit"],
                "raw_first_date": row["raw_first_date"],
                "derived_first_date": row["derived_first_date"],
                "scanned_at": str(row["scanned_at"]),
            }
            document["row_sha256"] = _sha256(document)
            result_proofs.append(document)
            classifications[str(row["classification"])] += 1
            target_fp = _library_fp_values(
                successor_plan, library_id
            )["detector"]
            target_rows.append({
                **document,
                "source_detector_fp": document["detector_fp"],
                "target_detector_fp": target_fp,
            })
            if library_id in selected_library_ids:
                compatible_pairs.add((
                    identity["repository_id"],
                    library_id,
                    identity["head_sha"],
                ))

        candidate_rows = list(state.connection.execute(
            """
            SELECT * FROM candidates
            WHERE repository_id=? AND last_seen_at>=? AND last_seen_at<=?
            ORDER BY candidate_id
            """,
            (
                identity["repository_id"],
                task["attempt_finished_at"],
                task["finished_at"],
            ),
        ))
        candidate_proofs.extend({
            "predecessor_task_id": int(task["task_id"]),
            **{key: row[key] for key in row.keys()},
        } for row in candidate_rows)
        analysis_rows = list(state.connection.execute(
            """
            SELECT * FROM repo_analysis
            WHERE repository_id=? AND head_sha=?
              AND analyzed_at>=? AND analyzed_at<=?
            ORDER BY analysis_id
            """,
            (
                identity["repository_id"],
                identity["head_sha"],
                task["attempt_finished_at"],
                task["finished_at"],
            ),
        ))
        analysis_proofs.extend({
            "predecessor_task_id": int(task["task_id"]),
            **{key: row[key] for key in row.keys()},
        } for row in analysis_rows)

        cache_key = hashlib.sha256(
            identity["full_name"].casefold().encode("utf-8")
        ).hexdigest()
        git_dir = cache_root / "repos" / (cache_key + ".git")
        if not git_dir.is_dir():
            raise PipelineError(
                "scan checkpoint exact-head cache is missing"
            )
        listing = subprocess.run(
            [
                "git", "--git-dir", str(git_dir), "ls-tree", "-rz",
                identity["head_sha"],
            ],
            env=object_environment,
            capture_output=True,
            check=False,
            timeout=120,
        )
        if listing.returncode:
            raise PipelineError(
                "scan checkpoint exact HEAD is unavailable locally"
            )
        notebook_entries = []
        for record in listing.stdout.split(b"\0"):
            if not record or b"\t" not in record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            fields = metadata.split()
            if len(fields) != 3 or fields[1] != b"blob":
                continue
            path = raw_path.decode("utf-8", errors="replace")
            if not path.casefold().endswith(".ipynb"):
                continue
            notebook_entries.append((fields[2].decode("ascii"), path))
        eligible_paths = [
            path for _oid, path in notebook_entries if _eligible(path)
        ]
        attributes = _bare_attribute_rows(
            git_dir, identity["head_sha"], eligible_paths
        )
        autocrlf = _bare_config_value(git_dir, "core.autocrlf")
        core_eol = _bare_config_value(git_dir, "core.eol")
        for object_id, path in notebook_entries:
            eligible = bool(_eligible(path))
            present = subprocess.run(
                [
                    "git", "--git-dir", str(git_dir), "cat-file", "-e",
                    object_id + "^{blob}",
                ],
                env=object_environment,
                capture_output=True,
                check=False,
                timeout=30,
            ).returncode == 0
            notebook_rows.append({
                "predecessor_task_id": int(task["task_id"]),
                "head_sha": identity["head_sha"],
                "path": path,
                "object_id": object_id,
                "eligible": eligible,
                "present": present,
            })
            if not eligible:
                if not present and ".ipynb_checkpoints" not in path.casefold():
                    raise PipelineError(
                        "scan checkpoint has an unproved missing notebook"
                    )
                continue
            if not present:
                raise PipelineError(
                    "scan checkpoint eligible notebook object is missing"
                )
            row = attributes.get(path, {})
            transformed = (
                row.get("filter") not in {
                    None, "unspecified", "unset", "lfs"
                }
                or row.get("working-tree-encoding") not in {
                    None, "unspecified", "unset"
                }
                or row.get("ident") == "set"
                or row.get("eol") not in {
                    None, "unspecified", "unset"
                }
                or (
                    autocrlf == "true" and row.get("text") != "unset"
                )
                or (
                    core_eol == "crlf"
                    and row.get("text") in {"set", "auto"}
                )
            )
            if transformed:
                raise PipelineError(
                    "scan checkpoint notebook requires checkout transforms"
                )
            parser_key = identity["repository_id"] + ":" + object_id
            if parser_key in parsed_oids:
                continue
            content = subprocess.run(
                [
                    "git", "--git-dir", str(git_dir), "cat-file", "blob",
                    object_id,
                ],
                env=object_environment,
                capture_output=True,
                check=False,
                timeout=120,
            )
            if content.returncode:
                raise PipelineError(
                    "scan checkpoint notebook content is unavailable"
                )
            old_outcome = normalized_parser_outcome(
                old_content, content.stdout
            )
            current_outcome = normalized_parser_outcome(
                current_content, content.stdout
            )
            if old_outcome != current_outcome:
                raise PipelineError(
                    "scan checkpoint notebook semantics changed"
                )
            parsed_oids[parser_key] = {
                "repository_id": identity["repository_id"],
                "object_id": object_id,
                "outcome_sha256": _sha256(old_outcome),
            }

        task_proofs.append({
            "task_id": int(task["task_id"]),
            "task_key": str(task["task_key"]),
            "repository_id": identity["repository_id"],
            "full_name": identity["full_name"],
            "head_sha": identity["head_sha"],
            "payload_sha256": identity["payload_sha256"],
            "attempt_result_sha256": _sha256(
                json.loads(task["result_json"] or "{}")
            ),
            "result_row_count": len(scan_rows),
            "candidate_postimage_count": len(candidate_rows),
            "analysis_postimage_count": len(analysis_rows),
        })

    if (
        len(result_proofs) != 237
        or len(candidate_proofs) != 421
        or len(analysis_proofs) != 14
        or len(notebook_rows) != 316
        or sum(row["eligible"] for row in notebook_rows) != 192
        or len(parsed_oids) != 181
        or classifications
        != Counter({"rejected": 191, "confirmed": 43, "targeted": 3})
    ):
        raise PipelineError(
            "scan checkpoint certified postimage universe changed: "
            "results=%d candidates=%d analysis=%d notebooks=%d "
            "eligible=%d blobs=%d classifications=%s"
            % (
                len(result_proofs), len(candidate_proofs),
                len(analysis_proofs), len(notebook_rows),
                sum(row["eligible"] for row in notebook_rows),
                len(parsed_oids), dict(sorted(classifications.items())),
            )
        )
    certificate = {
        "version": 1,
        "kind": "phase8-exact-scan-checkpoint-compatibility",
        "predecessor_run_id": predecessor_run_id,
        "predecessor_source_ref": predecessor_source_ref,
        "task_count": len(task_proofs),
        "result_row_count": len(result_proofs),
        "candidate_postimage_count": len(candidate_proofs),
        "analysis_postimage_count": len(analysis_proofs),
        "notebook_path_count": len(notebook_rows),
        "eligible_notebook_path_count": sum(
            row["eligible"] for row in notebook_rows
        ),
        "eligible_notebook_blob_count": len(parsed_oids),
        "parser_difference_count": 0,
        "task_proofs_sha256": _sha256(task_proofs),
        "result_proofs_sha256": _sha256(result_proofs),
        "candidate_postimages_sha256": _sha256(candidate_proofs),
        "analysis_postimages_sha256": _sha256(analysis_proofs),
        "notebook_inventory_sha256": _sha256(notebook_rows),
        "notebook_parser_proofs_sha256": _sha256(
            sorted(
                parsed_oids.values(),
                key=lambda row: (row["repository_id"], row["object_id"]),
            )
        ),
        "classifications": dict(sorted(classifications.items())),
        "target_row_count": len(target_rows),
        "compatible_selected_pair_count": len(compatible_pairs),
    }
    certificate["certificate_sha256"] = _sha256(certificate)
    return (
        _validate_certified_scan_checkpoint_contract(certificate),
        target_rows,
        compatible_pairs,
    )


def _materialize_certified_scan_rows(
    *,
    state: StateDB,
    successor_run_id: str,
    certificate: Mapping[str, Any],
    target_rows: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Copy exact certified rows under target fingerprints atomically."""
    materialized = []
    with state.transaction(immediate=True):
        for source in target_rows:
            existing = state.connection.execute(
                """
                SELECT * FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=?
                """,
                (
                    source["repository_id"],
                    source["library_id"],
                    source["head_sha"],
                    source["target_detector_fp"],
                ),
            ).fetchone()
            values = (
                source["repository_id"], source["library_id"],
                source["head_sha"], source["target_detector_fp"],
                source["classification"], source["status"],
                canonical_json(source["evidence"]),
                source["raw_first_commit"], source["raw_first_date"],
                source["derived_first_date"], source["scanned_at"],
            )
            if existing is None:
                state.connection.execute(
                    """
                    INSERT INTO scan_results(
                        repository_id, library_id, head_sha, detector_fp,
                        classification, status, evidence_json,
                        raw_first_commit, raw_first_date, derived_first_date,
                        scanned_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
                target_id = int(state.connection.execute(
                    "SELECT last_insert_rowid()"
                ).fetchone()[0])
            else:
                existing_document = {
                    "repository_id": existing["repository_id"],
                    "library_id": existing["library_id"],
                    "head_sha": existing["head_sha"],
                    "detector_fp": existing["detector_fp"],
                    "classification": existing["classification"],
                    "status": existing["status"],
                    "evidence_json": existing["evidence_json"],
                    "raw_first_commit": existing["raw_first_commit"],
                    "raw_first_date": existing["raw_first_date"],
                    "derived_first_date": existing["derived_first_date"],
                    "scanned_at": existing["scanned_at"],
                }
                expected_document = {
                    "repository_id": values[0], "library_id": values[1],
                    "head_sha": values[2], "detector_fp": values[3],
                    "classification": values[4], "status": values[5],
                    "evidence_json": values[6],
                    "raw_first_commit": values[7],
                    "raw_first_date": values[8],
                    "derived_first_date": values[9],
                    "scanned_at": values[10],
                }
                if existing_document != expected_document:
                    raise PipelineError(
                        "certified scan target collides with different data"
                    )
                target_id = int(existing["scan_result_id"])
            materialized.append({
                "successor_run_id": successor_run_id,
                "predecessor_task_id": source["predecessor_task_id"],
                "source_scan_result_id": source["scan_result_id"],
                "target_scan_result_id": target_id,
                "source_detector_fp": source["source_detector_fp"],
                "target_detector_fp": source["target_detector_fp"],
                "source_row_sha256": source["row_sha256"],
                "compatibility_sha256": certificate[
                    "certificate_sha256"
                ],
            })
    return {
        "row_count": len(materialized),
        "provenance_sha256": _sha256(materialized),
        "rows": materialized,
    }


def _validate_certified_scan_checkpoint_contract(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PipelineError("certified scan checkpoint is not an object")
    contract = dict(value)
    expected = {
        "version", "kind", "predecessor_run_id",
        "predecessor_source_ref", "task_count", "result_row_count",
        "candidate_postimage_count", "analysis_postimage_count",
        "notebook_path_count", "eligible_notebook_path_count",
        "eligible_notebook_blob_count", "parser_difference_count",
        "task_proofs_sha256", "result_proofs_sha256",
        "candidate_postimages_sha256", "analysis_postimages_sha256",
        "notebook_inventory_sha256", "notebook_parser_proofs_sha256",
        "classifications", "target_row_count",
        "compatible_selected_pair_count", "certificate_sha256",
    }
    if set(contract) != expected:
        raise PipelineError("certified scan checkpoint schema changed")
    if (
        contract["version"] != 1
        or contract["kind"]
        != "phase8-exact-scan-checkpoint-compatibility"
        or contract["predecessor_run_id"]
        != _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY[
            "predecessor_run_id"
        ]
        or contract["task_count"] != 37
        or contract["result_row_count"] != 237
        or contract["candidate_postimage_count"] != 421
        or contract["analysis_postimage_count"] != 14
        or contract["notebook_path_count"] != 316
        or contract["eligible_notebook_path_count"] != 192
        or contract["eligible_notebook_blob_count"] != 181
        or contract["parser_difference_count"] != 0
        or contract["target_row_count"] != 237
        or contract["compatible_selected_pair_count"] != 113
        or contract["classifications"]
        != {"confirmed": 43, "rejected": 191, "targeted": 3}
    ):
        raise PipelineError("certified scan checkpoint scope changed")
    for field in expected:
        if field.endswith("_sha256"):
            _historical_scan_hex_sha256(
                contract[field], label="certified scan " + field
            )
    unsigned = dict(contract)
    digest = unsigned.pop("certificate_sha256")
    if digest != _sha256(unsigned):
        raise PipelineError("certified scan checkpoint digest changed")
    return contract


def _cohort_recovery_preflight(
    *,
    state: StateDB,
    data_dir: Path,
    libraries: list[Mapping[str, Any]],
    validated_tasks: Mapping[
        str, tuple[Mapping[str, Any], Any, int]
    ],
    metadata_rows: list[Mapping[str, Any]],
    plan,
    budgets: RunBudgets,
    repo_root: Path,
    certified_scan_pairs: set[tuple[str, str, str]] | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, tuple[Mapping[str, Any], dict[str, Any], Any]],
]:
    """Derive the exact candidate plan from inherited discovery + metadata."""
    selected_ids = {str(library["id"]) for library in libraries}
    libraries_by_id = {
        str(library["id"]): library for library in libraries
    }
    observations = tuple(
        observation
        for _document, result, _request_count in validated_tasks.values()
        for observation in result.observations
        if observation.library_id in selected_ids
    )

    metadata_tasks = {}
    metadata_items = []
    task_universe = []
    result_universe = []
    seeded_lookups = []
    for ordinal, row in enumerate(metadata_rows):
        payload, document, resolution = _validated_metadata_task(
            row, ordinal=ordinal
        )
        task_key = str(row["task_key"])
        if task_key in metadata_tasks:
            raise PipelineError(
                "metadata predecessor has duplicate task keys"
            )
        metadata_tasks[task_key] = (row, document, resolution)
        metadata_items.extend(resolution.repositories)
        task_universe.append({
            "task_key": task_key,
            "payload": payload,
        })
        result_universe.append({
            "task_key": task_key,
            "result_sha256": hashlib.sha256(
                canonical_json(document).encode("utf-8")
            ).hexdigest(),
        })
        seeded_lookups.extend(
            RepositoryLookup(
                node_id=raw["node_id"],
                full_name=raw["full_name"],
            )
            for raw in payload["lookups"]
        )
    if not metadata_tasks:
        raise PipelineError(
            "cohort recovery has no completed metadata epoch"
        )
    lookup_keys = [lookup.key for lookup in seeded_lookups]
    if len(lookup_keys) != len(set(lookup_keys)):
        raise PipelineError(
            "metadata epoch has duplicate lookups across batches"
        )

    (
        resolved_by_name,
        resolved_by_node,
        publishable_by_name,
    ) = _canonical_metadata_identity_indexes(metadata_items)
    excluded_observation_pairs = set()
    accepted_observation_pairs = set()
    for observation in observations:
        item, _match_kind = _resolve_canonical_observation_identity(
            observation,
            resolved_by_name=resolved_by_name,
            resolved_by_node=resolved_by_node,
        )
        if item is None or not isinstance(item.full_name, str):
            continue
        pair = (item.full_name.casefold(), observation.library_id)
        if _discovery_observation_excluded(
            observation,
            libraries_by_id[observation.library_id],
        ):
            excluded_observation_pairs.add(pair)
        else:
            accepted_observation_pairs.add(pair)
    blocked_pairs = (
        excluded_observation_pairs - accepted_observation_pairs
    )
    persisted_metadata = {}
    for row in state.connection.execute(
        "SELECT node_id, metadata_json FROM repositories"
    ):
        try:
            persisted_metadata[str(row["node_id"])] = json.loads(
                row["metadata_json"] or "{}"
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            persisted_metadata[str(row["node_id"])] = {}

    identity = {
        "observations_total": len(observations),
        "exact_node": 0,
        "name_fallback_after_node_miss": 0,
        "name_only": 0,
        "unresolved": 0,
        "not_publishable": 0,
        "library_excluded": 0,
        "evidence_excluded": 0,
    }
    pairs: dict[str, set[str]] = {}

    def repository_metadata(item):
        node_id = _canonical_repository_identity(item)[0]
        return persisted_metadata.get(
            node_id,
            item.to_dict() if item is not None else {},
        )

    def admit(item, library_ids):
        if (
            item is None
            or not item.publishable
            or not item.node_id
            or not item.full_name
            or _repository_excluded(item.full_name)
        ):
            return 0
        canonical = publishable_by_name.get(
            item.full_name.casefold()
        )
        if (
            canonical is None
            or _canonical_repository_identity(canonical)
            != _canonical_repository_identity(item)
        ):
            raise PipelineError(
                "metadata publication identity changed during preflight"
            )
        added = 0
        for library_id in sorted(set(library_ids) & selected_ids):
            library = libraries_by_id[library_id]
            if (
                item.full_name.casefold(), library_id
            ) in blocked_pairs:
                identity["evidence_excluded"] += 1
                continue
            if _library_repository_excluded(
                item.full_name,
                library,
                repository_metadata(item),
            ):
                identity["library_excluded"] += 1
                continue
            destination = pairs.setdefault(item.full_name, set())
            before = len(destination)
            destination.add(library_id)
            added += len(destination) - before
        return added

    for observation in observations:
        item, match_kind = _resolve_canonical_observation_identity(
            observation,
            resolved_by_name=resolved_by_name,
            resolved_by_node=resolved_by_node,
        )
        identity[match_kind] += 1
        if item is None:
            raise PipelineError(
                "certified discovery observation lacks metadata identity"
            )
        if _discovery_observation_excluded(
            observation,
            libraries_by_id[observation.library_id],
        ):
            continue
        added = admit(item, (observation.library_id,))
        if (
            added == 0
            and (
                not item.publishable
                or _repository_excluded(item.full_name or "")
            )
        ):
            identity["not_publishable"] += 1

    legacy = _legacy_candidates(data_dir)
    state_candidates, state_known = _state_candidates(state)
    recall = {
        "legacy_repositories": len(legacy),
        "state_candidate_repositories": len(state_candidates),
        "legacy_new_pairs": 0,
        "state_new_pairs": 0,
    }
    for label, source in (
        ("legacy", legacy),
        ("state", state_candidates),
    ):
        for name, library_ids in source.items():
            retained = set(library_ids) & selected_ids
            if not retained:
                continue
            item = resolved_by_name.get(str(name).casefold())
            recall[label + "_new_pairs"] += admit(item, retained)

    certified_scan_pairs = certified_scan_pairs or set()
    reusable_pairs = 0
    predicted_scan_names = set()
    missing_pairs_by_library = Counter()
    for full_name, library_ids in pairs.items():
        item = publishable_by_name[full_name.casefold()]
        repository_missing = False
        for library_id in library_ids:
            detector_fp = _library_fp_values(
                plan, library_id
            )["detector"]
            row = state.connection.execute(
                """
                SELECT 1 FROM scan_results
                WHERE repository_id=? AND library_id=? AND head_sha=?
                  AND detector_fp=? AND status='clean'
                LIMIT 1
                """,
                (
                    item.node_id,
                    library_id,
                    item.head_oid,
                    detector_fp,
                ),
            ).fetchone()
            certified = (
                item.node_id,
                library_id,
                item.head_oid,
            ) in certified_scan_pairs
            if row is not None or certified:
                reusable_pairs += 1
            else:
                repository_missing = True
                missing_pairs_by_library[library_id] += 1
        if repository_missing:
            predicted_scan_names.add(full_name)

    final_visibility_requests = math.ceil(
        len(pairs) / METADATA_BATCH_SIZE
    )
    disk = shutil.disk_usage(repo_root)
    hard_budget_checks = {
        "scan_repositories": {
            "predicted": len(predicted_scan_names),
            "limit": budgets.max_scan_repositories,
            "within_limit": (
                len(predicted_scan_names)
                <= budgets.max_scan_repositories
            ),
        },
        "fetches": {
            "predicted_upper": len(predicted_scan_names),
            "limit": budgets.max_fetches,
            "within_limit": (
                len(predicted_scan_names) <= budgets.max_fetches
            ),
        },
        "graphql_points": {
            "initial_metadata_requests_inherited": len(metadata_tasks),
            "final_visibility_requests_upper": final_visibility_requests,
            "planned_request_count": final_visibility_requests,
            "predicted_point_floor": final_visibility_requests,
            "limit": budgets.max_graphql_points,
            "reserve": budgets.min_graphql_remaining,
            "actual_point_cost_runtime_enforced": True,
            "within_limit": (
                final_visibility_requests
                <= budgets.max_graphql_points
            ),
        },
        "disk": {
            "free_bytes": disk.free,
            "cache_hard_bytes": budgets.cache_hard_bytes,
            "operating_margin_bytes": 20 * 1024**3,
            "within_limit": (
                disk.free
                >= budgets.cache_hard_bytes + 20 * 1024**3
            ),
        },
        "wall": {
            "limit_seconds": budgets.max_wall_seconds,
            "reviewed_ceiling_seconds": 36 * 3600,
            "within_limit": budgets.max_wall_seconds == 36 * 3600,
        },
        "rss": {
            "limit_bytes": budgets.max_rss_bytes,
            "within_limit": budgets.max_rss_bytes > 0,
        },
    }
    failed = sorted(
        key
        for key, value in hard_budget_checks.items()
        if value.get("within_limit") is not True
    )
    preseeded_contract = {
        "task_count": len(metadata_tasks),
        "lookup_count": len(seeded_lookups),
        "task_universe_sha256": _sha256(task_universe),
        "result_universe_sha256": _sha256(result_universe),
        "input_context_sha256": _metadata_input_context_sha256(
            observations,
            legacy,
            state_known,
        ),
    }
    return {
        "unique_discovery_repositories": len({
            observation.repo_full_name.casefold()
            for observation in observations
        }),
        "discovery_observations": len(observations),
        "metadata_task_count": len(metadata_tasks),
        "metadata_lookup_count": len(seeded_lookups),
        "metadata_result_count": len(metadata_items),
        "publishable_metadata_repositories": len(
            publishable_by_name
        ),
        "identity": identity,
        "recall": recall,
        "unique_candidate_repositories": len(pairs),
        "repository_library_pairs": sum(
            len(library_ids) for library_ids in pairs.values()
        ),
        "predicted_scan_repositories": len(predicted_scan_names),
        "reusable_repository_library_pairs": reusable_pairs,
        "missing_pairs_by_library": dict(
            sorted(missing_pairs_by_library.items())
        ),
        "preseeded_metadata_epoch": preseeded_contract,
        "hard_budget_checks": hard_budget_checks,
        "failed_hard_budget_checks": failed,
        "within_hard_budgets": not failed,
    }, metadata_tasks


def _assert_cohort_fingerprint_compatibility(
    predecessor: Mapping[str, Any],
    successor: Mapping[str, Any],
    *,
    identity_scan_remediation: bool = False,
    allow_unchanged_detector_fingerprints: bool = False,
) -> dict[str, Any]:
    """Freeze evidence fingerprints while allowing downstream release semantics."""
    old_libraries = predecessor.get("libraries") or {}
    new_libraries = successor.get("libraries") or {}
    changed_libraries = sorted(
        library_id
        for library_id in set(old_libraries) | set(new_libraries)
        if old_libraries.get(library_id) != new_libraries.get(library_id)
    )
    detector_only_changes = {}
    if identity_scan_remediation:
        if set(old_libraries) != set(new_libraries):
            raise PipelineError(
                "cohort recovery changed the library fingerprint universe"
            )
        for library_id in changed_libraries:
            old = old_libraries[library_id]
            new = new_libraries[library_id]
            fields = sorted(
                field
                for field in set(old) | set(new)
                if old.get(field) != new.get(field)
            )
            if fields != ["detector"]:
                raise PipelineError(
                    "cohort recovery changed non-detector fingerprint for "
                    + library_id
                )
            detector_only_changes[library_id] = {
                "predecessor": old["detector"],
                "successor": new["detector"],
            }
        if (
            not detector_only_changes
            and not allow_unchanged_detector_fingerprints
        ):
            raise PipelineError(
                "cohort recovery did not invalidate remediated scans"
            )
    elif changed_libraries:
        changed = sorted(
            library_id
            for library_id in set(old_libraries) | set(new_libraries)
            if old_libraries.get(library_id) != new_libraries.get(library_id)
        )
        raise PipelineError(
            "cohort successor changed approved library fingerprints: "
            + ",".join(changed)
        )
    protected = {"dating", "ai", "filters"}
    changed_protected = sorted(
        key
        for key in protected
        if predecessor.get(key) != successor.get(key)
    )
    if changed_protected:
        raise PipelineError(
            "cohort successor changed evidence fingerprints: "
            + ",".join(changed_protected)
        )
    changes = sorted(
        key
        for key in set(predecessor) | set(successor)
        if predecessor.get(key) != successor.get(key)
        and key != "libraries"
    )
    allowed_global = (
        set()
        if identity_scan_remediation
        else {"aggregation", "publication"}
    )
    if not set(changes) <= allowed_global:
        raise PipelineError(
            "cohort successor changed unsupported global fingerprints"
        )
    return {
        "changed_global_fields": changes,
        "changed_library_ids": changed_libraries,
        "detector_only_changes": detector_only_changes,
        "approved_library_fingerprints_frozen": (
            not identity_scan_remediation
        ),
        "evidence_fingerprints_frozen": True,
        "scan_reuse_compatible": (
            not identity_scan_remediation
            or allow_unchanged_detector_fingerprints
        ),
    }


def _assert_content_diagnostic_fingerprint_contract(
    audit: Mapping[str, Any],
    current: Mapping[str, Any],
) -> dict[str, Any]:
    """Require portfolio-wide detector invalidation and forbid scan reuse."""
    libraries = current.get("libraries") or {}
    if not isinstance(libraries, Mapping) or not libraries:
        raise PipelineError(
            "cohort content/diagnostic recovery has no detector universe"
        )
    expected = set(libraries)
    changed = set((audit.get("detector_only_changes") or {}).keys())
    if changed != expected:
        missing = sorted(expected - changed)
        unexpected = sorted(changed - expected)
        raise PipelineError(
            "cohort content/diagnostic recovery did not invalidate the "
            "exact detector universe"
            + ("; missing=" + ",".join(missing) if missing else "")
            + (
                "; unexpected=" + ",".join(unexpected)
                if unexpected else ""
            )
        )
    if audit.get("scan_reuse_compatible") is not False:
        raise PipelineError(
            "cohort content/diagnostic recovery cannot reuse old scans"
        )
    return {
        "all_detector_fingerprints_changed": True,
        "changed_detector_count": len(changed),
        "old_scan_reuse_allowed": False,
    }


def _derive_certified_cohort(
    predecessor_by_key: Mapping[str, Mapping[str, Any]],
    libraries: list[Mapping[str, Any]],
    specs_by_key: Mapping[str, Mapping[str, Any]],
    *,
    require_strict_reduction: bool = True,
) -> tuple[
    list[Mapping[str, Any]],
    dict[str, tuple[Mapping[str, Any], Any, int]],
    dict[str, Any],
]:
    """Select only libraries whose exact current task universe is certified."""
    specs_by_library: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
    for key, spec in specs_by_key.items():
        specs_by_library.setdefault(str(spec["library_id"]), []).append(
            (key, spec)
        )
    selected = []
    validated: dict[str, tuple[Mapping[str, Any], Any, int]] = {}
    excluded = {}
    policies = {
        "github-code-search": "required",
        "sourcegraph": "advisory",
    }
    for library in libraries:
        library_id = str(library["id"])
        task_specs = sorted(specs_by_library.get(library_id, ()))
        if not task_specs:
            raise PipelineError(
                "active library has no discovery task universe: " + library_id
            )
        rows = [
            predecessor_by_key.get(key) for key, _spec in task_specs
        ]
        if any(row is None for row in rows):
            raise PipelineError(
                "predecessor lacks a current discovery task: " + library_id
            )
        statuses = Counter(str(row["status"]) for row in rows if row)
        if statuses.get("complete", 0) != len(task_specs):
            excluded[library_id] = {
                "reason": "discovery_incomplete",
                "task_count": len(task_specs),
                "statuses": dict(sorted(statuses.items())),
            }
            continue
        library_validated = {}
        for (key, spec), row in zip(task_specs, rows):
            assert row is not None
            if row["payload_json"] != canonical_json(spec):
                raise PipelineError(
                    "completed cohort task payload changed: " + key
                )
            try:
                document = json.loads(row["result_json"] or "")
                result, request_count = _public_only_result(
                    document,
                    spec,
                    source_policy=policies[str(spec["source"])],
                )
            except (
                TypeError,
                ValueError,
                json.JSONDecodeError,
                PipelineError,
            ) as exc:
                raise PipelineError(
                    "completed cohort task is not certifiable: " + key
                ) from exc
            library_validated[key] = (document, result, request_count)
        selected.append(library)
        validated.update(library_validated)
    if not selected:
        raise PipelineError("no discovery-complete cohort can be derived")
    if require_strict_reduction and len(selected) == len(libraries):
        raise PipelineError(
            "cohort successor is not a strict partial-portfolio reduction"
        )
    return selected, validated, {
        "selected_library_ids": sorted(
            str(library["id"]) for library in selected
        ),
        "excluded_libraries": {
            key: excluded[key] for key in sorted(excluded)
        },
        "active_library_count": len(libraries),
        "selected_library_count": len(selected),
        "excluded_library_count": len(excluded),
    }


def _cohort_candidate_preflight(
    *,
    state: StateDB,
    data_dir: Path,
    libraries: list[Mapping[str, Any]],
    validated_tasks: Mapping[
        str, tuple[Mapping[str, Any], Any, int]
    ],
    plan,
    budgets: RunBudgets,
    repo_root: Path,
) -> dict[str, Any]:
    """Calculate the exact conservative work set available before metadata."""
    selected_ids = {str(library["id"]) for library in libraries}
    libraries_by_id = {
        str(library["id"]): library for library in libraries
    }
    raw_pairs: dict[str, set[str]] = {}
    excluded_observation_pairs = set()
    accepted_observation_pairs = set()
    for _document, result, _request_count in validated_tasks.values():
        for observation in result.observations:
            if observation.library_id in selected_ids:
                pair = (
                    observation.repo_full_name.casefold(),
                    observation.library_id,
                )
                if _discovery_observation_excluded(
                    observation,
                    libraries_by_id[observation.library_id],
                ):
                    excluded_observation_pairs.add(pair)
                    continue
                accepted_observation_pairs.add(pair)
                raw_pairs.setdefault(
                    observation.repo_full_name, set()
                ).add(observation.library_id)
    blocked_pairs = (
        excluded_observation_pairs - accepted_observation_pairs
    )
    legacy = _legacy_candidates(data_dir)
    for name, library_ids in legacy.items():
        retained = {
            library_id
            for library_id in set(library_ids) & selected_ids
            if (name.casefold(), library_id) not in blocked_pairs
        }
        if retained:
            raw_pairs.setdefault(name, set()).update(retained)
    state_candidates, _ = _state_candidates(state)
    for name, library_ids in state_candidates.items():
        retained = {
            library_id
            for library_id in set(library_ids) & selected_ids
            if (name.casefold(), library_id) not in blocked_pairs
        }
        if retained:
            raw_pairs.setdefault(name, set()).update(retained)

    repository_rows = {}
    alias_to_name = {}
    for row in state.connection.execute(
        """
        SELECT node_id, full_name, visibility, is_fork, is_archived,
               head_sha, metadata_json
        FROM repositories
        """
    ):
        record = dict(row)
        name = str(record["full_name"])
        repository_rows[name] = record
        alias_to_name[name.casefold()] = name
        try:
            metadata = json.loads(record.get("metadata_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        requested = metadata.get("requested_full_name")
        if isinstance(requested, str) and requested:
            alias_to_name[requested.casefold()] = name

    filtered_pairs: dict[str, set[str]] = {}
    excluded_repositories = Counter()
    for requested_name, library_ids in raw_pairs.items():
        name = alias_to_name.get(
            requested_name.casefold(), requested_name
        )
        if _repository_excluded(name):
            excluded_repositories["global_policy"] += 1
            continue
        repository = repository_rows.get(name)
        metadata = {}
        if repository is not None:
            try:
                metadata = json.loads(
                    repository.get("metadata_json") or "{}"
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                metadata = {}
            if repository.get("visibility") in {"private", "excluded"}:
                excluded_repositories["known_nonpublic"] += 1
                continue
            if int(repository.get("is_fork") or 0):
                excluded_repositories["known_fork"] += 1
                continue
            if int(repository.get("is_archived") or 0):
                excluded_repositories["known_archived"] += 1
                continue
        for library_id in library_ids:
            if _library_repository_excluded(
                name,
                libraries_by_id[library_id],
                metadata,
            ):
                excluded_repositories["library_policy_pairs"] += 1
                continue
            filtered_pairs.setdefault(name, set()).add(library_id)

    reusable_pairs = 0
    predicted_scan_names = set()
    for name, library_ids in filtered_pairs.items():
        repository = repository_rows.get(name)
        for library_id in library_ids:
            reusable = False
            if (
                repository is not None
                and repository.get("visibility") == "public"
                and not int(repository.get("is_fork") or 0)
                and not int(repository.get("is_archived") or 0)
                and repository.get("head_sha")
            ):
                detector_fp = _library_fp_values(
                    plan, library_id
                )["detector"]
                row = state.connection.execute(
                    """
                    SELECT status FROM scan_results
                    WHERE repository_id=? AND library_id=? AND head_sha=?
                      AND detector_fp=?
                    """,
                    (
                        repository["node_id"],
                        library_id,
                        repository["head_sha"],
                        detector_fp,
                    ),
                ).fetchone()
                reusable = bool(row and row["status"] == "clean")
            if reusable:
                reusable_pairs += 1
            else:
                predicted_scan_names.add(name)

    # Metadata resolves the raw deduplicated names before visibility, fork,
    # archive, global-owner, alias, and per-library policy filtering. Budget
    # exactly that executable universe; filtered_pairs is the later scan
    # universe and cannot safely size the initial GraphQL epoch.
    metadata_names = set(raw_pairs)
    metadata_graphql_requests = math.ceil(
        len(metadata_names) / METADATA_BATCH_SIZE
    )
    # Every admitted repository is resolved once before scanning and rechecked
    # by stable node ID immediately before publication. GitHub reports the
    # actual point cost at runtime; the production query normally costs one
    # point, and the journaled runtime gate rejects any higher cumulative cost.
    planned_graphql_requests = metadata_graphql_requests * 2
    disk = shutil.disk_usage(repo_root)
    hard_budget_checks = {
        "scan_repositories": {
            "predicted": len(predicted_scan_names),
            "limit": budgets.max_scan_repositories,
            "within_limit": (
                len(predicted_scan_names)
                <= budgets.max_scan_repositories
            ),
        },
        "fetches": {
            "predicted_upper": len(predicted_scan_names),
            "limit": budgets.max_fetches,
            "within_limit": (
                len(predicted_scan_names) <= budgets.max_fetches
            ),
        },
        "graphql_points": {
            "initial_metadata_requests": metadata_graphql_requests,
            "final_visibility_requests_upper": metadata_graphql_requests,
            "planned_request_count": planned_graphql_requests,
            "predicted_point_floor": planned_graphql_requests,
            "limit": budgets.max_graphql_points,
            "reserve": budgets.min_graphql_remaining,
            "actual_point_cost_runtime_enforced": True,
            "within_limit": (
                planned_graphql_requests <= budgets.max_graphql_points
            ),
        },
        "disk": {
            "free_bytes": disk.free,
            "cache_hard_bytes": budgets.cache_hard_bytes,
            "operating_margin_bytes": 20 * 1024**3,
            "within_limit": (
                disk.free
                >= budgets.cache_hard_bytes + 20 * 1024**3
            ),
        },
        "wall": {
            "limit_seconds": budgets.max_wall_seconds,
            "reviewed_ceiling_seconds": 36 * 3600,
            "within_limit": budgets.max_wall_seconds == 36 * 3600,
        },
        "rss": {
            "limit_bytes": budgets.max_rss_bytes,
            "within_limit": budgets.max_rss_bytes > 0,
        },
    }
    failed_checks = sorted(
        key
        for key, value in hard_budget_checks.items()
        if value.get("within_limit") is not True
    )
    return {
        "unique_candidate_repositories": len(filtered_pairs),
        "repository_library_pairs": sum(
            len(library_ids) for library_ids in filtered_pairs.values()
        ),
        "raw_unique_candidate_repositories": len(raw_pairs),
        "raw_repository_library_pairs": sum(
            len(library_ids) for library_ids in raw_pairs.values()
        ),
        "predicted_scan_repositories": len(predicted_scan_names),
        "reusable_repository_library_pairs": reusable_pairs,
        "metadata_repository_universe": len(metadata_names),
        "estimated_graphql_requests": metadata_graphql_requests,
        "planned_graphql_requests": planned_graphql_requests,
        "excluded_by_available_policy": dict(
            sorted(excluded_repositories.items())
        ),
        "hard_budget_checks": hard_budget_checks,
        "failed_hard_budget_checks": failed_checks,
        "within_hard_budgets": not failed_checks,
    }


def _assert_fingerprint_scope(
    predecessor: Mapping[str, Any],
    successor: Mapping[str, Any],
    *,
    allowed_library_id: str,
) -> dict[str, Any]:
    top_level_changes = sorted(
        key
        for key in set(predecessor) | set(successor)
        if key != "libraries" and predecessor.get(key) != successor.get(key)
    )
    if top_level_changes:
        raise PipelineError(
            "scope reduction changed global fingerprints: "
            + ",".join(top_level_changes)
        )
    old_libraries = predecessor.get("libraries") or {}
    new_libraries = successor.get("libraries") or {}
    if set(old_libraries) != set(new_libraries):
        raise PipelineError("scope reduction changed the library universe")
    unrelated = sorted(
        library_id
        for library_id in old_libraries
        if library_id != allowed_library_id
        and old_libraries[library_id] != new_libraries[library_id]
    )
    if unrelated:
        raise PipelineError(
            "scope reduction changed unrelated library fingerprints: "
            + ",".join(unrelated)
        )
    changed_fields = sorted(
        key
        for key in set(old_libraries[allowed_library_id])
        | set(new_libraries[allowed_library_id])
        if old_libraries[allowed_library_id].get(key)
        != new_libraries[allowed_library_id].get(key)
    )
    if not changed_fields or not set(changed_fields) <= {
        "discovery",
        "detector",
        "presentation",
    }:
        raise PipelineError(
            "scope reduction changed unexpected library fingerprints"
        )
    return {
        "library_id": allowed_library_id,
        "changed_fields": changed_fields,
        "predecessor": old_libraries[allowed_library_id],
        "successor": new_libraries[allowed_library_id],
    }


def prepare_scope_reduction_successor(
    *,
    repo_root: str | Path,
    state_path: str | Path,
    data_dir: str | Path,
    predecessor_run_id: str,
    allowed_library_id: str,
    reason: str,
    budgets: RunBudgets | None = None,
) -> dict[str, Any]:
    """Prepare and seed a clean, resumable reconciliation successor."""
    root = Path(repo_root).resolve()
    state_file = (root / state_path).resolve()
    data_path = (root / data_dir).resolve()
    budgets = budgets or RunBudgets.reconcile()
    libraries = list(config.LIBRARIES)
    selected_ids = sorted(library["id"] for library in libraries)
    if allowed_library_id not in selected_ids:
        raise PipelineError("scope-reduction library is not active")
    scoped_library = next(
        library
        for library in libraries
        if library["id"] == allowed_library_id
    )
    if (
        tuple(scoped_library.get("classification_coverage") or ())
        != ("confirmed",)
        or scoped_library.get("targeted_build_signals")
        or {pack.kind for pack in query_packs(scoped_library)} != {"header"}
    ):
        raise PipelineError(
            "reviewed scope reduction is not confirmed/header-only"
        )

    plan = build_plan(
        mode="reconcile",
        state_path=state_file,
        data_dir=data_path,
        libraries=libraries,
        weekly_scan_budget=budgets.max_scan_repositories,
        max_graphql_points=budgets.max_graphql_points,
        min_graphql_remaining=budgets.min_graphql_remaining,
    )
    executable_sha256 = _network_task_source_sha256()
    execution_contract = {
        "mode": "reconcile",
        "selected_library_ids": selected_ids,
        "metadata_batch_size": METADATA_BATCH_SIZE,
        "network_task_source_sha256": executable_sha256,
    }
    base_release_id = _live_release_id(data_path)
    current_specs = _discovery_specs(libraries)
    current_by_key = {_task_key(spec): spec for spec in current_specs}
    if len(current_by_key) != len(current_specs):
        raise PipelineError("current discovery plan has duplicate task keys")

    with StateDB(state_file) as state:
        predecessor = state.connection.execute(
            """
            SELECT mode, plan_json, budgets_json, fingerprints_json,
                   base_release_id, status
            FROM runs WHERE run_id=?
            """,
            (predecessor_run_id,),
        ).fetchone()
        if predecessor is None:
            raise PipelineError("predecessor run does not exist")
        if predecessor["status"] != "abandoned":
            raise PipelineError(
                "predecessor must be explicitly abandoned"
            )
        if predecessor["mode"] != "reconcile":
            raise PipelineError("predecessor was not a reconciliation")
        predecessor_plan = json.loads(predecessor["plan_json"] or "{}")
        predecessor_execution = (
            predecessor_plan.get("execution_contract") or {}
        )
        if predecessor_execution != execution_contract:
            differing = sorted(
                key
                for key in set(predecessor_execution) | set(execution_contract)
                if predecessor_execution.get(key)
                != execution_contract.get(key)
            )
            raise PipelineError(
                "network execution contract changed: "
                + ",".join(differing)
            )
        if json.loads(predecessor["budgets_json"]) != budgets.to_dict():
            raise PipelineError("successor hard budgets changed")
        if predecessor["base_release_id"] != base_release_id:
            raise PipelineError("successor base release changed")
        predecessor_fingerprints = json.loads(
            predecessor["fingerprints_json"]
        )
        current_fingerprints = plan.fingerprints.as_dict()
        fingerprint_change = _assert_fingerprint_scope(
            predecessor_fingerprints,
            current_fingerprints,
            allowed_library_id=allowed_library_id,
        )

        predecessor_rows = list(
            state.connection.execute(
                """
                SELECT task_id, task_key, library_id, payload_json,
                       result_json, status
                FROM tasks
                WHERE run_id=? AND stage='discovery-query'
                ORDER BY task_id
                """,
                (predecessor_run_id,),
            )
        )
        predecessor_by_key = {
            str(row["task_key"]): row for row in predecessor_rows
        }
        if len(predecessor_by_key) != len(predecessor_rows):
            raise PipelineError(
                "predecessor discovery plan has duplicate task keys"
            )
        expanded = sorted(set(current_by_key) - set(predecessor_by_key))
        if expanded:
            raise PipelineError(
                "scope reduction would add discovery tasks"
            )
        changed_payloads = sorted(
            key
            for key, spec in current_by_key.items()
            if predecessor_by_key[key]["payload_json"]
            != canonical_json(spec)
        )
        if changed_payloads:
            raise PipelineError(
                "retained discovery task payload changed"
            )
        removed_keys = sorted(
            set(predecessor_by_key) - set(current_by_key)
        )
        if not removed_keys:
            raise PipelineError("successor is not a strict scope reduction")
        removed = []
        for key in removed_keys:
            payload = json.loads(predecessor_by_key[key]["payload_json"])
            if (
                payload.get("library_id") != allowed_library_id
                or payload.get("pack_kind") != "broad"
            ):
                raise PipelineError(
                    "scope reduction removed an unapproved task"
                )
            removed.append(
                {
                    "task_key": key,
                    "source": payload.get("source"),
                    "library_id": payload.get("library_id"),
                    "pack_kind": payload.get("pack_kind"),
                    "predecessor_status": predecessor_by_key[key][
                        "status"
                    ],
                }
            )

        source_policies = {
            "github-code-search": "required",
            "sourcegraph": "advisory",
        }
        compatibility = {
            "version": SUCCESSOR_CONTRACT_VERSION,
            "kind": "discovery-scope-reduction",
            "predecessor_run_id": predecessor_run_id,
            "reason": reason,
            "base_release_id": base_release_id,
            "mode": "reconcile",
            "selected_library_ids": selected_ids,
            "allowed_library_id": allowed_library_id,
            "network_task_source_sha256": executable_sha256,
            "source_policies": source_policies,
            "budgets_sha256": _sha256(budgets.to_dict()),
            "predecessor_fingerprints_sha256": _sha256(
                predecessor_fingerprints
            ),
            "successor_fingerprints_sha256": _sha256(
                current_fingerprints
            ),
            "retained_task_universe_sha256": _sha256(
                {
                    key: current_by_key[key]
                    for key in sorted(current_by_key)
                }
            ),
            "removed_tasks": removed,
            "fingerprint_change": fingerprint_change,
        }
        successor_id = (
            datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y%m%dT%H%M%SZ-")
            + uuid.uuid4().hex[:8]
        )
        run_plan = {
            **plan.to_dict(),
            "execution_contract": execution_contract,
            "successor_lineage": compatibility,
        }
        successor_id, created = state.create_successor_run(
            successor_id,
            predecessor_run_id=predecessor_run_id,
            reason=reason,
            compatibility=compatibility,
            mode="reconcile",
            plan=run_plan,
            budgets=budgets.to_dict(),
            fingerprints=current_fingerprints,
            base_release_id=base_release_id,
        )
        state.update_stage(successor_id, "discovery", status="running")

        successor_task_ids = {}
        for key, spec in current_by_key.items():
            successor_task_ids[key] = state.enqueue_task(
                successor_id,
                "discovery-query",
                key,
                library_id=spec["library_id"],
                payload=spec,
                max_attempts=3,
            )

        inherited = 0
        inherited_requests = Counter()
        refused = Counter()
        for key in sorted(current_by_key):
            predecessor_task = predecessor_by_key[key]
            if (
                predecessor_task["status"] != "complete"
                or predecessor_task["result_json"] is None
            ):
                refused["not_completed"] += 1
                continue
            spec = current_by_key[key]
            policy = source_policies[spec["source"]]
            try:
                document = json.loads(predecessor_task["result_json"])
                result, request_count = _public_only_result(
                    document,
                    spec,
                    source_policy=policy,
                )
            except (
                TypeError,
                ValueError,
                json.JSONDecodeError,
                PipelineError,
            ):
                refused[
                    "invalid_required"
                    if policy == "required"
                    else "invalid_advisory"
                ] += 1
                continue
            state.inherit_completed_task(
                successor_task_id=successor_task_ids[key],
                predecessor_task_id=int(predecessor_task["task_id"]),
                predecessor_run_id=predecessor_run_id,
                payload=spec,
                result=document,
                network_task_source_sha256=executable_sha256,
                source_policy=policy,
                inherited_request_count=request_count,
            )
            # Re-record from the validated current task document. This is
            # idempotent and intentionally does not copy predecessor rows.
            _record_coverage(state, successor_id, result)
            inherited += 1
            inherited_requests[spec["source"]] += request_count

        if (
            inherited_requests["sourcegraph"]
            > budgets.max_sourcegraph_requests
            or inherited_requests["github-code-search"]
            > budgets.max_github_search_requests
        ):
            raise PipelineError(
                "inherited request usage exceeds successor budgets"
            )
        pending = state.connection.execute(
            """
            SELECT COUNT(*) FROM tasks
            WHERE run_id=? AND stage='discovery-query'
              AND status!='complete'
            """,
            (successor_id,),
        ).fetchone()[0]
        provenance_rows = state.connection.execute(
            """
            SELECT COUNT(*) FROM task_inheritance
            WHERE successor_run_id=?
            """,
            (successor_id,),
        ).fetchone()[0]
        if provenance_rows != inherited:
            raise PipelineError(
                "successor inheritance provenance is incomplete"
            )
        diagnostics = state.discovery_publication_diagnostics(
            successor_id
        )
    return {
        "successor_run_id": successor_id,
        "predecessor_run_id": predecessor_run_id,
        "created": created,
        "current_task_count": len(current_by_key),
        "removed_tasks": removed,
        "inherited_tasks": inherited,
        "pending_tasks": int(pending),
        "refused_completed_tasks": dict(sorted(refused.items())),
        "inherited_requests": dict(sorted(inherited_requests.items())),
        "network_task_source_sha256": executable_sha256,
        "compatibility_sha256": _sha256(compatibility),
        "coverage_diagnostics": diagnostics,
    }


def prepare_transport_policy_successor(
    *,
    repo_root: str | Path,
    state_path: str | Path,
    data_dir: str | Path,
    predecessor_run_id: str,
    predecessor_source_ref: str,
    reason: str,
    historical_github_request_attempts: int = 0,
    budgets: RunBudgets | None = None,
) -> dict[str, Any]:
    """Carry exact certified work across a reviewed network-execution fix.

    The discovery task universe, canonical payloads, library fingerprints,
    base release, and hard budgets must be identical. The predecessor source
    ref must reproduce its recorded executable hash. The successor
    records both full executable hashes and both transport-source hashes, then
    revalidates every inherited result under the current schema/query/public
    evidence contract. Query decomposition additionally proves that every
    exact member lane reconstructs its predecessor logical OR pack.
    """
    if (
        not isinstance(historical_github_request_attempts, int)
        or historical_github_request_attempts < 0
    ):
        raise PipelineError(
            "historical GitHub request attempts must be non-negative"
        )
    root = Path(repo_root).resolve()
    state_file = (root / state_path).resolve()
    data_path = (root / data_dir).resolve()
    budgets = budgets or RunBudgets.reconcile()
    libraries = list(config.LIBRARIES)
    selected_ids = sorted(library["id"] for library in libraries)
    historical_usage = {
        "github-code-search": historical_github_request_attempts,
        "sourcegraph": 0,
    }
    plan = build_plan(
        mode="reconcile",
        state_path=state_file,
        data_dir=data_path,
        libraries=libraries,
        weekly_scan_budget=budgets.max_scan_repositories,
        max_graphql_points=budgets.max_graphql_points,
        min_graphql_remaining=budgets.min_graphql_remaining,
    )
    base_release_id = _live_release_id(data_path)
    current_specs = _discovery_specs(libraries)
    current_by_key = {_task_key(spec): spec for spec in current_specs}
    query_execution_equivalence = _query_execution_equivalence(libraries)
    if len(current_by_key) != len(current_specs):
        raise PipelineError("current discovery plan has duplicate task keys")
    source_policies = {
        "github-code-search": "required",
        "sourcegraph": "advisory",
    }

    with StateDB(state_file) as state:
        predecessor = state.connection.execute(
            """
            SELECT mode, plan_json, budgets_json, fingerprints_json,
                   base_release_id, status, started_at, finished_at
            FROM runs WHERE run_id=?
            """,
            (predecessor_run_id,),
        ).fetchone()
        if predecessor is None:
            raise PipelineError("predecessor run does not exist")
        if predecessor["status"] != "abandoned":
            raise PipelineError(
                "predecessor must be explicitly abandoned"
            )
        if predecessor["mode"] != "reconcile":
            raise PipelineError("predecessor was not a reconciliation")
        if json.loads(predecessor["budgets_json"]) != budgets.to_dict():
            raise PipelineError("transport successor hard budgets changed")
        if predecessor["base_release_id"] != base_release_id:
            raise PipelineError("transport successor base release changed")
        predecessor_fingerprints = json.loads(
            predecessor["fingerprints_json"]
        )
        current_fingerprints = plan.fingerprints.as_dict()
        if predecessor_fingerprints != current_fingerprints:
            raise PipelineError(
                "transport successor changed collection fingerprints"
            )
        predecessor_plan = json.loads(predecessor["plan_json"] or "{}")
        predecessor_execution = (
            predecessor_plan.get("execution_contract") or {}
        )
        recorded_predecessor_executable_sha256 = str(
            predecessor_execution.get("network_task_source_sha256") or ""
        )
        source_audit = _transport_policy_source_audit(
            root,
            predecessor_source_ref,
            recorded_predecessor_executable_sha256,
        )
        current_executable_sha256 = str(
            source_audit["successor_network_task_source_sha256"]
        )
        predecessor_executable_sha256 = str(
            source_audit["predecessor_network_task_source_sha256"]
        )
        execution_contract = {
            "mode": "reconcile",
            "selected_library_ids": selected_ids,
            "metadata_batch_size": METADATA_BATCH_SIZE,
            "network_task_source_sha256": current_executable_sha256,
        }
        common_execution = {
            "mode": "reconcile",
            "selected_library_ids": selected_ids,
            "metadata_batch_size": METADATA_BATCH_SIZE,
        }
        for key, value in common_execution.items():
            if predecessor_execution.get(key) != value:
                raise PipelineError(
                    "transport successor changed execution field: " + key
                )
        if (
            predecessor_execution.get("network_task_source_sha256")
            != predecessor_executable_sha256
        ):
            raise PipelineError(
                "predecessor source ref does not reproduce its recorded "
                "network executable"
            )
        unexpected_predecessor_execution = (
            set(predecessor_execution)
            - set(common_execution)
            - {"network_task_source_sha256"}
        )
        if unexpected_predecessor_execution:
            raise PipelineError(
                "predecessor has an unsupported execution contract"
            )
        if predecessor_executable_sha256 == current_executable_sha256:
            raise PipelineError(
                "transport successor executable did not change"
            )

        predecessor_rows = list(
            state.connection.execute(
                """
                SELECT task_id, task_key, library_id, payload_json,
                       result_json, status
                FROM tasks
                WHERE run_id=? AND stage='discovery-query'
                ORDER BY task_id
                """,
                (predecessor_run_id,),
            )
        )
        predecessor_by_key = {
            str(row["task_key"]): row for row in predecessor_rows
        }
        if len(predecessor_by_key) != len(predecessor_rows):
            raise PipelineError(
                "predecessor discovery plan has duplicate task keys"
            )
        if set(predecessor_by_key) != set(current_by_key):
            raise PipelineError(
                "transport successor changed the discovery task universe"
            )
        changed_payloads = sorted(
            key
            for key, spec in current_by_key.items()
            if predecessor_by_key[key]["payload_json"]
            != canonical_json(spec)
        )
        if changed_payloads:
            raise PipelineError(
                "transport successor changed a canonical task payload"
            )

        compatibility = {
            "version": TRANSPORT_SUCCESSOR_CONTRACT_VERSION,
            "kind": source_audit.get(
                "remediation_kind",
                "transport-policy-remediation",
            ),
            "predecessor_run_id": predecessor_run_id,
            "reason": reason,
            "base_release_id": base_release_id,
            "mode": "reconcile",
            "selected_library_ids": selected_ids,
            # State-level task provenance stores the executable that produced
            # the inherited result. The successor executable is recorded
            # separately and in the new run's execution contract.
            "network_task_source_sha256": predecessor_executable_sha256,
            "predecessor_network_task_source_sha256": (
                predecessor_executable_sha256
            ),
            "successor_network_task_source_sha256": (
                current_executable_sha256
            ),
            "predecessor_transport_source_sha256": source_audit[
                "predecessor_transport_source_sha256"
            ],
            "successor_transport_source_sha256": source_audit[
                "successor_transport_source_sha256"
            ],
            "source_audit": source_audit,
            "query_execution_equivalence": (
                query_execution_equivalence
            ),
            "source_policies": source_policies,
            "historical_network_request_attempts": historical_usage,
            "budgets_sha256": _sha256(budgets.to_dict()),
            "fingerprints_sha256": _sha256(current_fingerprints),
            "task_universe_sha256": _sha256(
                {
                    key: current_by_key[key]
                    for key in sorted(current_by_key)
                }
            ),
        }
        successor_id = (
            datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y%m%dT%H%M%SZ-")
            + uuid.uuid4().hex[:8]
        )
        run_plan = {
            **plan.to_dict(),
            "execution_contract": execution_contract,
            "successor_lineage": compatibility,
        }
        successor_id, created = state.create_successor_run(
            successor_id,
            predecessor_run_id=predecessor_run_id,
            reason=reason,
            compatibility=compatibility,
            mode="reconcile",
            plan=run_plan,
            budgets=budgets.to_dict(),
            fingerprints=current_fingerprints,
            base_release_id=base_release_id,
        )
        state.update_stage(successor_id, "discovery", status="running")
        successor_task_ids = {
            key: state.enqueue_task(
                successor_id,
                "discovery-query",
                key,
                library_id=spec["library_id"],
                payload=spec,
                max_attempts=3,
            )
            for key, spec in current_by_key.items()
        }

        inherited = 0
        inherited_requests = Counter()
        refused = Counter()
        for key in sorted(current_by_key):
            predecessor_task = predecessor_by_key[key]
            if (
                predecessor_task["status"] != "complete"
                or predecessor_task["result_json"] is None
            ):
                refused["not_completed"] += 1
                continue
            spec = current_by_key[key]
            policy = source_policies[spec["source"]]
            try:
                document = json.loads(predecessor_task["result_json"])
                result, request_count = _public_only_result(
                    document,
                    spec,
                    source_policy=policy,
                )
            except (
                TypeError,
                ValueError,
                json.JSONDecodeError,
                PipelineError,
            ):
                refused[
                    "invalid_required"
                    if policy == "required"
                    else "invalid_advisory"
                ] += 1
                continue
            state.inherit_completed_task(
                successor_task_id=successor_task_ids[key],
                predecessor_task_id=int(predecessor_task["task_id"]),
                predecessor_run_id=predecessor_run_id,
                payload=spec,
                result=document,
                network_task_source_sha256=predecessor_executable_sha256,
                source_policy=policy,
                inherited_request_count=request_count,
            )
            _record_coverage(state, successor_id, result)
            inherited += 1
            inherited_requests[spec["source"]] += request_count

        charged_github = (
            inherited_requests["github-code-search"]
            + historical_github_request_attempts
        )
        if (
            inherited_requests["sourcegraph"]
            > budgets.max_sourcegraph_requests
            or charged_github > budgets.max_github_search_requests
        ):
            raise PipelineError(
                "transport successor inherited usage exceeds hard budgets"
            )
        pending = state.connection.execute(
            """
            SELECT COUNT(*) FROM tasks
            WHERE run_id=? AND stage='discovery-query'
              AND status!='complete'
            """,
            (successor_id,),
        ).fetchone()[0]
        provenance_rows = state.connection.execute(
            """
            SELECT COUNT(*) FROM task_inheritance
            WHERE successor_run_id=?
            """,
            (successor_id,),
        ).fetchone()[0]
        if provenance_rows != inherited:
            raise PipelineError(
                "transport successor inheritance provenance is incomplete"
            )
        diagnostics = state.discovery_publication_diagnostics(
            successor_id
        )
    return {
        "successor_run_id": successor_id,
        "predecessor_run_id": predecessor_run_id,
        "created": created,
        "current_task_count": len(current_by_key),
        "inherited_tasks": inherited,
        "pending_tasks": int(pending),
        "refused_completed_tasks": dict(sorted(refused.items())),
        "inherited_requests": dict(sorted(inherited_requests.items())),
        "historical_network_request_attempts": historical_usage,
        "charged_github_request_attempts": int(charged_github),
        "predecessor_network_task_source_sha256": (
            predecessor_executable_sha256
        ),
        "successor_network_task_source_sha256": (
            current_executable_sha256
        ),
        "compatibility_sha256": _sha256(compatibility),
        "coverage_diagnostics": diagnostics,
        "source_audit": source_audit,
        "query_execution_equivalence": query_execution_equivalence,
    }


def prepare_phase8_cohort_successor(
    *,
    repo_root: str | Path,
    state_path: str | Path,
    data_dir: str | Path,
    predecessor_run_id: str,
    predecessor_source_ref: str,
    reason: str,
    budgets: RunBudgets | None = None,
    recovery_remediation: bool = False,
    control_plane_remediation: bool = False,
    scan_runtime_remediation: bool = False,
    candidate_policy_remediation: bool = False,
    preflight_reuse_remediation: bool = False,
    preflight_budget_remediation: bool = False,
    checkpoint_continuation_remediation: bool = False,
) -> dict[str, Any]:
    """Create the reviewed 36-hour partial-cohort reconciliation successor."""
    root = Path(repo_root).resolve()
    state_file = (root / state_path).resolve()
    data_path = (root / data_dir).resolve()
    budgets = budgets or RunBudgets.reconcile()
    if budgets.to_dict() != RunBudgets.reconcile().to_dict():
        raise PipelineError(
            "Phase 8 Cohort A requires the frozen reconciliation budgets"
        )
    libraries = list(config.LIBRARIES)
    plan = build_plan(
        mode="reconcile",
        state_path=state_file,
        data_dir=data_path,
        libraries=libraries,
        weekly_scan_budget=budgets.max_scan_repositories,
        max_graphql_points=budgets.max_graphql_points,
        min_graphql_remaining=budgets.min_graphql_remaining,
    )
    base_release_id = _live_release_id(data_path)
    current_specs = _discovery_specs(libraries)
    current_by_key = {_task_key(spec): spec for spec in current_specs}
    if len(current_by_key) != len(current_specs):
        raise PipelineError("current discovery plan has duplicate task keys")

    with StateDB(state_file) as state:
        predecessor = state.connection.execute(
            """
            SELECT mode, plan_json, budgets_json, fingerprints_json,
                   base_release_id, status, started_at, finished_at
            FROM runs WHERE run_id=?
            """,
            (predecessor_run_id,),
        ).fetchone()
        if predecessor is None:
            raise PipelineError("predecessor run does not exist")
        if predecessor["status"] != "abandoned":
            raise PipelineError(
                "predecessor must be explicitly abandoned"
            )
        if predecessor["mode"] != "reconcile":
            raise PipelineError("predecessor was not a reconciliation")
        if predecessor["base_release_id"] != base_release_id:
            raise PipelineError("cohort successor base release changed")
        if json.loads(predecessor["budgets_json"]) != budgets.to_dict():
            raise PipelineError("cohort successor hard budgets changed")
        predecessor_plan = json.loads(predecessor["plan_json"] or "{}")
        predecessor_execution = (
            predecessor_plan.get("execution_contract") or {}
        )
        predecessor_is_cohort = (
            predecessor_execution.get("run_class")
            == "phase8-cohort-a"
            and predecessor_execution.get("release_scope")
            == "partial-portfolio"
        )
        if recovery_remediation and not predecessor_is_cohort:
            raise PipelineError(
                "identity/scan recovery requires a Phase 8 cohort predecessor"
            )
        if control_plane_remediation and not recovery_remediation:
            raise PipelineError(
                "control-plane remediation requires cohort recovery"
            )
        if scan_runtime_remediation and not recovery_remediation:
            raise PipelineError(
                "scan-runtime remediation requires cohort recovery"
            )
        if candidate_policy_remediation and not recovery_remediation:
            raise PipelineError(
                "candidate-policy remediation requires cohort recovery"
            )
        if preflight_reuse_remediation and not recovery_remediation:
            raise PipelineError(
                "preflight-reuse remediation requires cohort recovery"
            )
        if preflight_budget_remediation and not recovery_remediation:
            raise PipelineError(
                "preflight-budget remediation requires cohort recovery"
            )
        if checkpoint_continuation_remediation and not recovery_remediation:
            raise PipelineError(
                "checkpoint continuation requires cohort recovery"
            )
        if sum(bool(value) for value in (
            control_plane_remediation,
            scan_runtime_remediation,
            candidate_policy_remediation,
            preflight_reuse_remediation,
            preflight_budget_remediation,
            checkpoint_continuation_remediation,
        )) > 1:
            raise PipelineError(
                "control-plane, scan-runtime, candidate-policy, "
                "preflight-reuse, preflight-budget, and checkpoint "
                "continuation remediation are mutually exclusive"
            )
        predecessor_completed_scan_tasks = int(
            state.connection.execute(
                """
                SELECT COUNT(*) FROM tasks
                WHERE run_id=? AND stage='scan' AND status='complete'
                """,
                (predecessor_run_id,),
            ).fetchone()[0]
        )
        if (
            (
                control_plane_remediation
                or preflight_reuse_remediation
                or preflight_budget_remediation
            )
            and predecessor_completed_scan_tasks != 0
        ):
            raise PipelineError(
                "non-network successor refuses a predecessor with "
                "completed scans"
            )
        source_audit = _cohort_successor_source_audit(
            root,
            predecessor_source_ref,
            str(
                predecessor_execution.get(
                    "network_task_source_sha256"
                )
                or ""
            ),
            metadata_remediation=predecessor_is_cohort,
            identity_scan_remediation=recovery_remediation,
            control_plane_remediation=control_plane_remediation,
            scan_runtime_remediation=(
                scan_runtime_remediation
                or checkpoint_continuation_remediation
            ),
            candidate_policy_remediation=(
                candidate_policy_remediation
            ),
            preflight_reuse_remediation=(
                preflight_reuse_remediation
            ),
            preflight_budget_remediation=(
                preflight_budget_remediation
            ),
            checkpoint_continuation_remediation=(
                checkpoint_continuation_remediation
            ),
        )
        predecessor_executable_sha256 = str(
            source_audit["predecessor_network_task_source_sha256"]
        )
        current_executable_sha256 = str(
            source_audit["successor_network_task_source_sha256"]
        )
        predecessor_fingerprints = json.loads(
            predecessor["fingerprints_json"]
        )
        current_fingerprints = plan.fingerprints.as_dict()
        fingerprint_audit = _assert_cohort_fingerprint_compatibility(
            predecessor_fingerprints,
            current_fingerprints,
            identity_scan_remediation=recovery_remediation,
            allow_unchanged_detector_fingerprints=(
                control_plane_remediation
                or preflight_reuse_remediation
                or preflight_budget_remediation
            ),
        )
        if (
            source_audit.get("remediation_kind")
            == _CONTENT_DIAGNOSTIC_REMEDIATION_KIND
        ):
            fingerprint_audit["content_diagnostic_contract"] = (
                _assert_content_diagnostic_fingerprint_contract(
                    fingerprint_audit,
                    current_fingerprints,
                )
            )
        historical_scan_usage = _derive_historical_scan_usage(
            state=state,
            predecessor_run_id=predecessor_run_id,
            predecessor_plan=predecessor_plan,
            cache_root=root / ".state" / "git-cache",
            predecessor_lfs_transfer_bound=source_audit.get(
                "predecessor_lfs_transfer_bound"
            ),
            unknown_usage_policy=(
                {
                    **_CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY,
                    "policy_sha256": _sha256(
                        _CHECKPOINT_CONTINUATION_UNKNOWN_USAGE_POLICY
                    ),
                }
                if checkpoint_continuation_remediation
                else None
            ),
        )

        predecessor_rows = list(
            state.connection.execute(
                """
                SELECT task_id, task_key, library_id, payload_json,
                       result_json, status, attempts, error_code
                FROM tasks
                WHERE run_id=? AND stage='discovery-query'
                ORDER BY task_id
                """,
                (predecessor_run_id,),
            )
        )
        predecessor_by_key = {
            str(row["task_key"]): row for row in predecessor_rows
        }
        if len(predecessor_by_key) != len(predecessor_rows):
            raise PipelineError(
                "predecessor discovery plan has duplicate task keys"
            )
        if predecessor_is_cohort:
            contracted_selected = predecessor_execution.get(
                "selected_library_ids"
            )
            contracted_excluded = predecessor_execution.get(
                "excluded_library_ids"
            )
            active_ids = {
                str(library["id"]) for library in libraries
            }
            if (
                not isinstance(contracted_selected, list)
                or not isinstance(contracted_excluded, list)
                or contracted_selected != sorted(contracted_selected)
                or contracted_excluded != sorted(contracted_excluded)
                or set(contracted_selected)
                | set(contracted_excluded) != active_ids
                or set(contracted_selected) & set(contracted_excluded)
            ):
                raise PipelineError(
                    "predecessor cohort execution scope is invalid"
                )
            contracted_set = set(contracted_selected)
            scoped_libraries = [
                library
                for library in libraries
                if library["id"] in contracted_set
            ]
            scoped_by_key = {
                key: spec
                for key, spec in current_by_key.items()
                if spec["library_id"] in contracted_set
            }
            if set(predecessor_by_key) != set(scoped_by_key):
                raise PipelineError(
                    "metadata remediation changed the cohort task universe"
                )
            selected_libraries, validated, scoped_derivation = (
                _derive_certified_cohort(
                    predecessor_by_key,
                    scoped_libraries,
                    scoped_by_key,
                    require_strict_reduction=False,
                )
            )
            if (
                scoped_derivation["selected_library_ids"]
                != contracted_selected
            ):
                raise PipelineError(
                    "metadata remediation lost a certified cohort library"
                )
            derivation = {
                "selected_library_ids": contracted_selected,
                "excluded_libraries": {
                    library_id: {
                        "reason": "inherited_cohort_scope",
                        "collection_status": "not_collected",
                    }
                    for library_id in contracted_excluded
                },
                "active_library_count": len(libraries),
                "selected_library_count": len(contracted_selected),
                "excluded_library_count": len(contracted_excluded),
                "predecessor_cohort_derivation": scoped_derivation,
            }
        else:
            if set(predecessor_by_key) != set(current_by_key):
                raise PipelineError(
                    "cohort successor changed the all-library task universe"
                )
            selected_libraries, validated, derivation = (
                _derive_certified_cohort(
                    predecessor_by_key,
                    libraries,
                    current_by_key,
                )
            )
        selected_ids = derivation["selected_library_ids"]
        selected_id_set = set(selected_ids)
        selected_by_key = {
            key: spec
            for key, spec in current_by_key.items()
            if spec["library_id"] in selected_id_set
        }
        if set(validated) != set(selected_by_key):
            raise PipelineError(
                "certified cohort does not equal its current task universe"
            )
        removed_task_count = len(current_by_key) - len(selected_by_key)
        if removed_task_count <= 0:
            raise PipelineError("cohort successor did not reduce task scope")

        scan_checkpoint_certificate = None
        certified_scan_target_rows: list[dict[str, Any]] = []
        certified_scan_pairs: set[tuple[str, str, str]] = set()
        if checkpoint_continuation_remediation:
            (
                scan_checkpoint_certificate,
                certified_scan_target_rows,
                certified_scan_pairs,
            ) = _certify_completed_scan_checkpoint(
                state=state,
                predecessor_run_id=predecessor_run_id,
                predecessor_fingerprints=predecessor_fingerprints,
                successor_plan=plan,
                selected_library_ids=selected_id_set,
                cache_root=root / ".state" / "git-cache",
                predecessor_source_ref=predecessor_source_ref,
            )

        predecessor_usage = _durable_discovery_request_usage(
            state, predecessor_run_id
        )
        inherited_requests = Counter()
        for key, (_document, _result, request_count) in validated.items():
            inherited_requests[
                str(selected_by_key[key]["source"])
            ] += request_count
        historical_usage = {}
        for source in ("github-code-search", "sourcegraph"):
            charged = int(
                predecessor_usage["sources"][source]["charged"]
            )
            inherited = int(inherited_requests[source])
            if inherited > charged:
                raise PipelineError(
                    "cohort inherited request charge exceeds predecessor usage"
                )
            historical_usage[source] = charged - inherited
        charged_github = (
            inherited_requests["github-code-search"]
            + historical_usage["github-code-search"]
        )
        charged_sourcegraph = (
            inherited_requests["sourcegraph"]
            + historical_usage["sourcegraph"]
        )
        if charged_github > budgets.max_github_search_requests:
            raise PipelineError(
                "cohort predecessor GitHub usage exceeds hard budget"
            )
        if charged_sourcegraph > budgets.max_sourcegraph_requests:
            raise PipelineError(
                "cohort predecessor Sourcegraph usage exceeds hard budget"
            )

        predecessor_graphql = {
            "request_count": 0,
            "points_used": 0,
            "remaining": None,
            "reset_at": None,
        }
        historical_wall_seconds = 0.0
        if predecessor_is_cohort:
            predecessor_graphql = _graphql_journal_budget(
                state, predecessor_run_id
            )
            prior_wall = predecessor_execution.get(
                "historical_wall_seconds", 0
            )
            if (
                not isinstance(prior_wall, (int, float))
                or isinstance(prior_wall, bool)
                or prior_wall < 0
            ):
                raise PipelineError(
                    "predecessor cohort historical wall usage is invalid"
                )
            try:
                run_started = datetime.datetime.fromisoformat(
                    str(predecessor["started_at"]).replace("Z", "+00:00")
                )
                run_finished = datetime.datetime.fromisoformat(
                    str(predecessor["finished_at"]).replace("Z", "+00:00")
                )
            except (TypeError, ValueError) as exc:
                raise PipelineError(
                    "predecessor cohort runtime interval is invalid"
                ) from exc
            elapsed = (run_finished - run_started).total_seconds()
            if elapsed < 0:
                raise PipelineError(
                    "predecessor cohort runtime interval is negative"
                )
            historical_wall_seconds = float(prior_wall) + elapsed
            if historical_wall_seconds >= budgets.max_wall_seconds:
                raise PipelineError(
                    "cohort lineage exhausted the reviewed wall budget"
                )
        if predecessor_graphql["points_used"] > budgets.max_graphql_points:
            raise PipelineError(
                "cohort lineage exhausted the GraphQL point budget"
            )

        metadata_tasks = {}
        if recovery_remediation:
            metadata_rows = list(state.connection.execute(
                """
                SELECT task_id, task_key, library_id, payload_json,
                       result_json, status, attempts, error_code
                FROM tasks
                WHERE run_id=? AND stage='github-metadata-batch'
                ORDER BY task_id
                """,
                (predecessor_run_id,),
            ))
            preflight, metadata_tasks = _cohort_recovery_preflight(
                state=state,
                data_dir=data_path,
                libraries=selected_libraries,
                validated_tasks=validated,
                metadata_rows=metadata_rows,
                plan=plan,
                budgets=budgets,
                repo_root=root,
                certified_scan_pairs=certified_scan_pairs,
            )
            inherited_graphql_requests = sum(
                int(resolution.request_count)
                for _row, _document, resolution
                in metadata_tasks.values()
            )
            inherited_graphql_points = sum(
                int(resolution.points_used)
                for _row, _document, resolution
                in metadata_tasks.values()
            )
            if (
                inherited_graphql_requests
                > int(predecessor_graphql["request_count"])
                or inherited_graphql_points
                > int(predecessor_graphql["points_used"])
            ):
                raise PipelineError(
                    "inherited metadata charge exceeds predecessor GraphQL "
                    "usage"
                )
            historical_graphql = {
                "request_count": (
                    int(predecessor_graphql["request_count"])
                    - inherited_graphql_requests
                ),
                "points_used": (
                    int(predecessor_graphql["points_used"])
                    - inherited_graphql_points
                ),
                "remaining": predecessor_graphql["remaining"],
                "reset_at": predecessor_graphql["reset_at"],
            }
        else:
            preflight = _cohort_candidate_preflight(
                state=state,
                data_dir=data_path,
                libraries=selected_libraries,
                validated_tasks=validated,
                plan=plan,
                budgets=budgets,
                repo_root=root,
            )
            historical_graphql = predecessor_graphql
        historical_scan_attempts = int(
            historical_scan_usage["attempt_count"]
        )
        planned_scan_attempts = int(
            preflight["predicted_scan_repositories"]
        )
        combined_scan_attempts = (
            historical_scan_attempts + planned_scan_attempts
        )
        fetch_check = preflight["hard_budget_checks"]["fetches"]
        fetch_check.update({
            "historical_charged": historical_scan_attempts,
            "planned_new": planned_scan_attempts,
            "predicted_upper": combined_scan_attempts,
            "within_limit": (
                combined_scan_attempts <= budgets.max_fetches
            ),
        })
        preflight["scan_dispatch_attempts"] = {
            "historical_charged": historical_scan_attempts,
            "planned_new": planned_scan_attempts,
            "combined_upper": combined_scan_attempts,
            "limit": budgets.max_fetches,
            "within_limit": (
                combined_scan_attempts <= budgets.max_fetches
            ),
        }
        graphql_check = preflight["hard_budget_checks"]["graphql_points"]
        planned_graphql = int(graphql_check["planned_request_count"])
        total_graphql_upper = (
            int(predecessor_graphql["points_used"]) + planned_graphql
        )
        graphql_check.update({
            "historical_request_count": int(
                predecessor_graphql["request_count"]
            ),
            "historical_points_used": int(
                predecessor_graphql["points_used"]
            ),
            "historical_remaining": predecessor_graphql["remaining"],
            "historical_reset_at": predecessor_graphql["reset_at"],
            "successor_residual_historical_request_count": int(
                historical_graphql["request_count"]
            ),
            "successor_residual_historical_points_used": int(
                historical_graphql["points_used"]
            ),
            "lineage_point_upper": total_graphql_upper,
            "lineage_point_margin": (
                budgets.max_graphql_points - total_graphql_upper
            ),
            "within_limit": (
                total_graphql_upper <= budgets.max_graphql_points
            ),
        })
        wall_check = preflight["hard_budget_checks"]["wall"]
        wall_check.update({
            "historical_seconds": historical_wall_seconds,
            "remaining_seconds": (
                budgets.max_wall_seconds - historical_wall_seconds
            ),
            "within_limit": (
                historical_wall_seconds < budgets.max_wall_seconds
            ),
        })
        preflight["hard_budget_checks"]["github_search_requests"] = {
            "charged": int(charged_github),
            "limit": budgets.max_github_search_requests,
            "within_limit": (
                charged_github <= budgets.max_github_search_requests
            ),
        }
        preflight["hard_budget_checks"]["sourcegraph_requests"] = {
            "charged": int(charged_sourcegraph),
            "limit": budgets.max_sourcegraph_requests,
            "within_limit": (
                charged_sourcegraph <= budgets.max_sourcegraph_requests
            ),
        }
        citation_library_upper = sum(
            bool(library.get("citation_query"))
            for library in selected_libraries
        )
        preflight["hard_budget_checks"]["openalex_requests"] = {
            "predicted_library_upper": citation_library_upper,
            "limit": budgets.max_openalex_requests,
            "within_limit": (
                citation_library_upper <= budgets.max_openalex_requests
            ),
        }
        existing_cff = 0
        for row in state.connection.execute(
            """
            SELECT analysis_json FROM repo_analysis
            WHERE status='clean'
            """
        ):
            try:
                analysis = json.loads(row["analysis_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                analysis = {}
            if analysis.get("citation_cff"):
                existing_cff += 1
        preflight["hard_budget_checks"]["citation_source_extractions"] = {
            "known_existing_cff_repositories": existing_cff,
            "limit": budgets.max_citation_source_extractions,
            "runtime_enforced_for_new_scan_results": True,
            "within_limit": (
                existing_cff <= budgets.max_citation_source_extractions
            ),
        }
        failed_checks = sorted(
            key
            for key, value in preflight["hard_budget_checks"].items()
            if value.get("within_limit") is not True
        )
        preflight["failed_hard_budget_checks"] = failed_checks
        preflight["within_hard_budgets"] = not failed_checks
        if failed_checks:
            raise PipelineError(
                "cohort preflight exceeds hard budgets: "
                + ",".join(failed_checks)
            )

        excluded_ids = sorted(
            set(library["id"] for library in libraries)
            - selected_id_set
        )
        execution_contract = {
            "mode": "reconcile",
            "run_class": "phase8-cohort-a",
            "release_scope": "partial-portfolio",
            "release_label": "Phase 8 Cohort A",
            "selected_library_ids": selected_ids,
            "excluded_library_ids": excluded_ids,
            "metadata_batch_size": METADATA_BATCH_SIZE,
            "network_task_source_sha256": current_executable_sha256,
            "historical_network_request_attempts": historical_usage,
            "historical_graphql_usage": historical_graphql,
            "historical_wall_seconds": historical_wall_seconds,
            "reviewed_slo": {
                "class": "partial_cohort_reconciliation",
                "target_seconds": 24 * 3600,
                "ceiling_seconds": 36 * 3600,
            },
        }
        execution_contract["historical_scan_usage"] = (
            historical_scan_usage
        )
        if scan_checkpoint_certificate is not None:
            execution_contract["certified_scan_checkpoint"] = (
                scan_checkpoint_certificate
            )
        if recovery_remediation:
            execution_contract["preseeded_metadata_epoch"] = (
                preflight["preseeded_metadata_epoch"]
            )
        stable_preflight = {
            key: value
            for key, value in preflight.items()
            if key != "hard_budget_checks"
        }
        if preflight_budget_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-preflight-budget-recovery"
            )
        elif preflight_reuse_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-preflight-reuse-recovery"
            )
        elif control_plane_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-control-plane-recovery"
            )
        elif candidate_policy_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-candidate-policy-recovery"
            )
        elif scan_runtime_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-scan-runtime-recovery"
            )
        elif checkpoint_continuation_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-checkpoint-continuation"
            )
        elif recovery_remediation:
            compatibility_kind = (
                "phase8-partial-cohort-identity-scan-recovery"
            )
        elif predecessor_is_cohort:
            compatibility_kind = (
                "phase8-partial-cohort-metadata-remediation"
            )
        else:
            compatibility_kind = (
                "phase8-partial-cohort-reconciliation"
            )
        compatibility = {
            "version": (
                COHORT_RECOVERY_CONTRACT_VERSION
                if recovery_remediation
                else COHORT_SUCCESSOR_CONTRACT_VERSION
            ),
            "kind": compatibility_kind,
            "predecessor_run_id": predecessor_run_id,
            "reason": reason,
            "base_release_id": base_release_id,
            "mode": "reconcile",
            "run_class": "phase8-cohort-a",
            "selected_library_ids": selected_ids,
            "excluded_library_ids": excluded_ids,
            "network_task_source_sha256": (
                predecessor_executable_sha256
            ),
            "predecessor_network_task_source_sha256": (
                predecessor_executable_sha256
            ),
            "successor_network_task_source_sha256": (
                current_executable_sha256
            ),
            "source_audit": source_audit,
            "fingerprint_audit": fingerprint_audit,
            "source_policies": {
                "github-code-search": "required",
                "sourcegraph": "advisory",
            },
            "historical_network_request_attempts": historical_usage,
            "historical_graphql_usage": historical_graphql,
            "predecessor_graphql_usage": predecessor_graphql,
            "historical_wall_seconds": historical_wall_seconds,
            "budgets_sha256": _sha256(budgets.to_dict()),
            "predecessor_fingerprints_sha256": _sha256(
                predecessor_fingerprints
            ),
            "successor_fingerprints_sha256": _sha256(
                current_fingerprints
            ),
            "retained_task_universe_sha256": _sha256(
                {
                    key: selected_by_key[key]
                    for key in sorted(selected_by_key)
                }
            ),
            "preflight_sha256": _sha256(stable_preflight),
            "predecessor_usage": predecessor_usage,
            "scan_reuse": {
                "compatible": (
                    not recovery_remediation
                    or control_plane_remediation
                    or candidate_policy_remediation
                    or preflight_reuse_remediation
                    or preflight_budget_remediation
                    or checkpoint_continuation_remediation
                ),
                "reason": (
                    "lineage_scan_budget_preflight"
                    if preflight_budget_remediation
                    else (
                        "effective_detector_fingerprint_reuse"
                        if preflight_reuse_remediation
                        else (
                            "no_predecessor_scan_tasks"
                            if control_plane_remediation
                            else (
                                "certified_completed_checkpoint"
                                if checkpoint_continuation_remediation
                                else "detector_fingerprint_changed"
                                if (
                                    recovery_remediation
                                    and not candidate_policy_remediation
                                )
                                else (
                                    "changed_libraries_only"
                                    if candidate_policy_remediation
                                    else "unchanged"
                                )
                            )
                        )
                    )
                ),
                "certificate_sha256": (
                    scan_checkpoint_certificate["certificate_sha256"]
                    if scan_checkpoint_certificate is not None
                    else None
                ),
            },
        }
        compatibility["historical_scan_usage_sha256"] = (
            historical_scan_usage["contract_sha256"]
        )
        successor_id = (
            datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y%m%dT%H%M%SZ-")
            + uuid.uuid4().hex[:8]
        )
        run_plan = {
            **plan.to_dict(),
            "execution_contract": execution_contract,
            "successor_lineage": compatibility,
            "cohort_derivation": derivation,
            "cohort_preflight": preflight,
        }
        successor_id, created = state.create_successor_run(
            successor_id,
            predecessor_run_id=predecessor_run_id,
            reason=reason,
            compatibility=compatibility,
            mode="reconcile",
            plan=run_plan,
            budgets=budgets.to_dict(),
            fingerprints=current_fingerprints,
            base_release_id=base_release_id,
        )
        certified_scan_materialization = None
        if scan_checkpoint_certificate is not None:
            certified_scan_materialization = (
                _materialize_certified_scan_rows(
                    state=state,
                    successor_run_id=successor_id,
                    certificate=scan_checkpoint_certificate,
                    target_rows=certified_scan_target_rows,
                )
            )
            state.update_stage(
                successor_id,
                "scan_checkpoint_reuse",
                status="complete",
                counters={
                    "tasks": scan_checkpoint_certificate["task_count"],
                    "rows": certified_scan_materialization["row_count"],
                },
                checkpoint=certified_scan_materialization,
            )
        state.update_stage(successor_id, "discovery", status="running")
        successor_task_ids = {
            key: state.enqueue_task(
                successor_id,
                "discovery-query",
                key,
                library_id=spec["library_id"],
                payload=spec,
                max_attempts=3,
            )
            for key, spec in selected_by_key.items()
        }
        inherited = 0
        inherited_by_source = Counter()
        for key in sorted(selected_by_key):
            predecessor_task = predecessor_by_key[key]
            document, result, request_count = validated[key]
            source = str(selected_by_key[key]["source"])
            changed = state.inherit_completed_task(
                successor_task_id=successor_task_ids[key],
                predecessor_task_id=int(predecessor_task["task_id"]),
                predecessor_run_id=predecessor_run_id,
                payload=selected_by_key[key],
                result=document,
                network_task_source_sha256=(
                    predecessor_executable_sha256
                ),
                source_policy=(
                    "required"
                    if source == "github-code-search"
                    else "advisory"
                ),
                inherited_request_count=request_count,
            )
            _record_coverage(state, successor_id, result)
            inherited += int(changed)
            inherited_by_source[source] += request_count

        inherited_metadata = 0
        inherited_metadata_requests = 0
        if recovery_remediation:
            for task_key in sorted(metadata_tasks):
                predecessor_task, document, resolution = (
                    metadata_tasks[task_key]
                )
                payload = json.loads(
                    predecessor_task["payload_json"]
                )
                successor_task_id = state.enqueue_task(
                    successor_id,
                    "github-metadata-batch",
                    task_key,
                    payload=payload,
                    max_attempts=3,
                )
                changed = state.inherit_completed_task(
                    successor_task_id=successor_task_id,
                    predecessor_task_id=int(
                        predecessor_task["task_id"]
                    ),
                    predecessor_run_id=predecessor_run_id,
                    payload=payload,
                    result=document,
                    network_task_source_sha256=(
                        predecessor_executable_sha256
                    ),
                    source_policy="required",
                    inherited_request_count=int(
                        resolution.request_count
                    ),
                )
                inherited_metadata += int(changed)
                inherited_metadata_requests += int(
                    resolution.request_count
                )

        pending_discovery = state.connection.execute(
            """
            SELECT COUNT(*) FROM tasks
            WHERE run_id=? AND stage='discovery-query'
              AND status!='complete'
            """,
            (successor_id,),
        ).fetchone()[0]
        pending_metadata = state.connection.execute(
            """
            SELECT COUNT(*) FROM tasks
            WHERE run_id=? AND stage='github-metadata-batch'
              AND status!='complete'
            """,
            (successor_id,),
        ).fetchone()[0]
        if int(pending_discovery) != 0 or int(pending_metadata) != 0:
            raise PipelineError(
                "certified cohort successor contains pending inherited work"
            )
        provenance_rows = state.connection.execute(
            """
            SELECT COUNT(*) FROM task_inheritance
            WHERE successor_run_id=?
            """,
            (successor_id,),
        ).fetchone()[0]
        expected_provenance = (
            len(selected_by_key) + len(metadata_tasks)
        )
        if int(provenance_rows) != expected_provenance:
            raise PipelineError(
                "cohort successor inheritance provenance is incomplete"
            )
        diagnostics = state.discovery_publication_diagnostics(
            successor_id
        )
        try:
            state.assert_run_publishable(successor_id)
        except RuntimeError as exc:
            raise PipelineError(
                "cohort successor has blocking required-source coverage"
            ) from exc
        predecessor_inherited = state.connection.execute(
            """
            SELECT COUNT(*) FROM task_inheritance
            WHERE successor_run_id=?
            """,
            (predecessor_run_id,),
        ).fetchone()[0]
        refused_scan_tasks = state.connection.execute(
            """
            SELECT COUNT(*) FROM tasks
            WHERE run_id=? AND stage='scan' AND status='complete'
            """,
            (predecessor_run_id,),
        ).fetchone()[0]
    return {
        "successor_run_id": successor_id,
        "predecessor_run_id": predecessor_run_id,
        "created": created,
        "run_class": "phase8-cohort-a",
        "release_scope": "partial-portfolio",
        "selected_library_ids": selected_ids,
        "excluded_library_ids": excluded_ids,
        "selected_library_count": len(selected_ids),
        "current_task_count": len(selected_by_key),
        "removed_task_count": removed_task_count,
        "inherited_tasks": len(selected_by_key),
        "newly_inherited_tasks": inherited,
        "inherited_metadata_tasks": len(metadata_tasks),
        "newly_inherited_metadata_tasks": inherited_metadata,
        "inherited_metadata_requests": inherited_metadata_requests,
        "pending_tasks": (
            int(pending_discovery) + int(pending_metadata)
        ),
        "pending_discovery_tasks": int(pending_discovery),
        "pending_metadata_tasks": int(pending_metadata),
        "refused_scan_tasks": int(refused_scan_tasks),
        "scan_reuse_refusal_reason": (
            None
            if (
                control_plane_remediation
                or candidate_policy_remediation
                or preflight_reuse_remediation
                or preflight_budget_remediation
                or checkpoint_continuation_remediation
            )
            else (
                "detector_fingerprint_changed"
                if recovery_remediation
                else None
            )
        ),
        "predecessor_inherited_tasks": int(predecessor_inherited),
        "inherited_requests": dict(sorted(inherited_by_source.items())),
        "historical_network_request_attempts": historical_usage,
        "historical_graphql_usage": historical_graphql,
        "predecessor_graphql_usage": predecessor_graphql,
        "historical_wall_seconds": historical_wall_seconds,
        "historical_scan_usage": historical_scan_usage,
        "certified_scan_checkpoint": scan_checkpoint_certificate,
        "certified_scan_materialization": (
            certified_scan_materialization
        ),
        "charged_network_request_attempts": {
            "github-code-search": int(charged_github),
            "sourcegraph": int(charged_sourcegraph),
        },
        "cohort_derivation": derivation,
        "preflight": preflight,
        "predecessor_network_task_source_sha256": (
            predecessor_executable_sha256
        ),
        "successor_network_task_source_sha256": (
            current_executable_sha256
        ),
        "compatibility_sha256": _sha256(compatibility),
        "coverage_diagnostics": diagnostics,
        "source_audit": source_audit,
        "fingerprint_audit": fingerprint_audit,
    }
