"""REQ-14 deterministic publication, validation, and frontend-loading tests."""
from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from collector.pipeline import (
    CollectorPipeline,
    PipelineError,
    _close_and_validate_v2,
)
from collector.publish_v2 import (
    LEGACY_VISIBILITY_ATTESTATION,
    PublicationError,
    STATE_VISIBILITY_ATTESTATION,
    _effective_entry,
    _install_staged_tree,
    _pack_json_rows,
    build_v2_tree,
    canonical_json,
    publish_v2,
    stage_v2,
)
from collector.scanner_v2 import SCAN_FRESHNESS, SCAN_POLICY
from collector.state import StateDB
from collector.validate_v2 import compare_v1_v2, validate_v2


ROOT = Path(__file__).resolve().parents[1]


def fixture():
    current = {
        "generated_at": "2026-07-27T12:00:00Z",
        "method_version": "fixture",
        "detection_hash": "detector-fixture",
        "prev_refresh": "2026-07-20",
        "is_bootstrap": False,
        "caveats": ["Fixture caveat."],
        "totals": {"confirmed_integrator_repos": 1},
        "discovery_stats": {"dx": {"coverage_gaps": []}},
        "scan_quality": {
            "mode": "refresh",
            "coverage_claim": "bounded-run",
            "selected_repositories": 2,
            "files_examined": 2,
            "bytes_examined": 40,
            "skipped_large_files": 0,
            "pruned_large_assets": 1,
            "policy": dict(SCAN_POLICY),
            "freshness": dict(SCAN_FRESHNESS),
            "complete": True,
        },
        "libraries": [
            {
                "id": "dx",
                "name": "Device Library",
                "description": "Fully classified fixture.",
                "released_on": "2021-01",
                "language": "cpp",
                "confirmed_count": 1,
                "bundled_count": 0,
                "targeted_count": 1,
                "headline_count": 1,
                "adoption_counts_build": False,
                "delta_since_last": 0,
                "sparkline": [0, 1],
                "sparkline_months": ["2026-06", "2026-07"],
            },
            {
                "id": "xxl",
                "name": "XXL Library",
                "description": "Direct integration only.",
                "released_on": "2020-01",
                "language": "cpp",
                "confirmed_count": 1,
                "bundled_count": 0,
                "targeted_count": 0,
                "headline_count": 1,
                "adoption_counts_build": False,
                "classification_coverage": {
                    "confirmed": "evaluated",
                    "bundled": "not_evaluated",
                    "targeted": "not_evaluated",
                },
                "delta_since_last": 0,
                "sparkline": [1],
                "sparkline_months": ["2026-07"],
            },
        ],
        "repos": [
            {
                "full_name": "public/example",
                "html_url": "https://github.com/public/example",
                "owner": "public",
                "description": "confirmed",
                "stars": 2,
                "forks": 0,
                "language": "C++",
                "visibility": "PUBLIC",
                "owner_type": "Organization",
                "topics": ["cuda"],
                "license": "Apache-2.0",
                "libraries": [
                    {
                        "library_id": "dx",
                        "classification": "confirmed",
                        "first_integration": "2026-01-02",
                        "first_integration_commit": "abc",
                        "operators": ["FFT"],
                    },
                    {
                        "library_id": "xxl",
                        "classification": "confirmed",
                        "first_integration": "2026-02-03",
                        "first_integration_commit": "def",
                        "operators": ["API"],
                    },
                ],
            },
            {
                "full_name": "public/target",
                "html_url": "https://github.com/public/target",
                "owner": "public",
                "description": "target only",
                "stars": 0,
                "forks": 0,
                "language": "CMake",
                "visibility": "PUBLIC",
                "libraries": [
                    {
                        "library_id": "dx",
                        "classification": "targeted",
                        "first_integration": "2026-07-24",
                        "first_integration_commit": "",
                        "operators": [],
                    }
                ],
            },
        ],
    }
    timeseries = {
        "dx": {
            "released_on": "2021-01",
            "as_of": "2026-07-27T12:00:00Z",
            "points": [
                {
                    "month": "2026-07",
                    "confirmed": 1,
                    "bundled": 0,
                    "targeted": 1,
                }
            ],
        },
        "xxl": {
            "released_on": "2020-01",
            "as_of": "2026-07-27T12:00:00Z",
            "points": [
                {
                    "month": "2026-07",
                    "confirmed": 1,
                    "bundled": 0,
                    "targeted": 0,
                }
            ],
        },
    }
    citations = {
        "generated_at": "2026-07-27T12:00:00Z",
        "source": "fixture",
        "method_version": "fixture",
        "caveats": ["Citation fixture."],
        "libraries": {
            "dx": {
                "name": "Device Library",
                "total": 1,
                "new_since_last": 0,
                "new_7d": 1,
                "monthly": [{"month": "2026-07", "cumulative": 1}],
                "growth_90d": {"current": 1, "prev": 0},
                "growth_365d": None,
                "papers_capped": False,
                "repo_papers": {},
                "papers": [
                    {
                        "title": "A paper",
                        "doi": "10.example/one",
                        "publication_date": "2026-07-25",
                        "year": 2026,
                    }
                ],
            }
        },
    }
    deltas = {
        "generated_at": "2026-07-27T12:00:00Z",
        "per_library": [
            {"id": "dx", "delta": 0},
            {"id": "xxl", "delta": 0},
        ],
    }
    return current, timeseries, citations, deltas


def tree_bytes(root: Path):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class PublicationTests(unittest.TestCase):
    def test_partial_cohort_labels_scope_and_separates_stale_v1_rows(self):
        current, timeseries, citations, deltas = fixture()
        cards = {card["id"]: card for card in current["libraries"]}
        cards["dx"]["collection_status"] = "collected"
        cards["xxl"].update({
            "collection_status": "not_collected",
            "classification_coverage": {
                "confirmed": "not_evaluated",
                "bundled": "not_evaluated",
                "targeted": "not_evaluated",
            },
            "confirmed_count": None,
            "bundled_count": None,
            "targeted_count": None,
            "headline_count": None,
        })
        xxl_entry = next(
            entry
            for entry in current["repos"][0]["libraries"]
            if entry["library_id"] == "xxl"
        )
        xxl_entry.update({
            "carried_forward": True,
            "stale": True,
            "as_of": "2026-07-15T00:00:00Z",
        })
        current["release_metadata"] = {
            "scope": "partial-portfolio",
            "label": "Phase 8 Cohort A",
            "run_class": "phase8-cohort-a",
            "portfolio_complete": False,
        }
        current["portfolio_coverage"] = {
            "selected_library_ids": ["dx"],
            "excluded_library_ids": ["xxl"],
        }
        current["scan_quality"].update({
            "mode": "reconcile",
            "run_class": "phase8-cohort-a",
            "coverage_claim": "partial-cohort-reconcile",
        })
        current["migration_quality"] = {
            "mixed_v1_v2": True,
            "stale": True,
            "carried_forward_library_ids": ["xxl"],
            "selected_library_ids": ["dx"],
            "legacy_as_of": "2026-07-15T00:00:00Z",
        }
        current["discovery_stats"]["xxl"] = {
            "evidence_kind": "carried-forward-v1",
            "coverage_gaps": [],
            "sources": {},
            "source_lag_max_seconds": None,
            "stale": True,
            "carried_forward": True,
            "as_of": "2026-07-15T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ordinary-cohort"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            self.assertEqual([], validate_v2(root))
            cards = {card["id"]: card for card in manifest["libraries"]}
            self.assertEqual(1, cards["dx"]["new_repos_7d"])
            self.assertEqual(1, cards["dx"]["citation_new_7d"])
            self.assertEqual(0, cards["xxl"]["new_repos_7d"])
            self.assertIsNone(cards["xxl"]["citation_new_7d"])
            self.assertEqual(
                "partial-portfolio", manifest["release"]["scope"]
            )
            xxl = next(
                card
                for card in manifest["libraries"]
                if card["id"] == "xxl"
            )
            self.assertEqual("not_collected", xxl["collection_status"])
            self.assertIsNone(xxl["confirmed_count"])
            index = json.loads(
                (root / xxl["index"]["path"]).read_text()
            )
            self.assertEqual(0, index["current_row_count"])
            self.assertEqual(1, index["carried_forward_row_count"])
            self.assertEqual(
                current["generated_at"], index["timeseries"]["as_of"]
            )
            self.assertEqual(
                None, index["classification_counts"]["confirmed"]
            )

            current["scan_quality"].update({
                "coverage_claim": "partial-cohort-owner-deferred-tail",
                "owner_deferred": True,
                "completed_repositories": 1,
                "deferred_repositories": 1,
                "task_universe_repositories": 2,
                "deferred_task_keys_sha256": "1" * 64,
                "deferred_repository_proof_sha256": "2" * 64,
                "deferral_contract_sha256": "3" * 64,
                "complete": False,
            })
            owner_deferred = Path(temporary) / "owner-deferred"
            build_v2_tree(
                current, timeseries, citations, deltas, owner_deferred
            )
            self.assertEqual([], validate_v2(owner_deferred))

    def test_scan_quality_distinguishes_policy_pruning_from_source_skips(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            valid = Path(temporary) / "valid"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, valid
            )
            quality = json.loads(
                (valid / manifest["quality"]["path"]).read_text()
            )
            self.assertEqual(quality["scan"]["skipped_large_files"], 0)
            self.assertEqual(quality["scan"]["pruned_large_assets"], 1)
            self.assertEqual(quality["scan"]["policy"], SCAN_POLICY)
            self.assertEqual(quality["scan"]["freshness"], SCAN_FRESHNESS)
            self.assertTrue(quality["scan"]["complete"])
            self.assertEqual([], validate_v2(valid))

            invalid_current = copy.deepcopy(current)
            invalid_current["scan_quality"]["skipped_large_files"] = 1
            invalid = Path(temporary) / "invalid"
            build_v2_tree(
                invalid_current, timeseries, citations, deltas, invalid
            )
            self.assertTrue(
                any(
                    "completeness does not reflect skipped files" in error
                    for error in validate_v2(invalid)
                )
            )

    def test_legacy_scan_quality_defaults_declare_unknown_new_metrics(self):
        current, timeseries, citations, deltas = fixture()
        current.pop("scan_quality")
        for repo in current["repos"]:
            repo.pop("visibility", None)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "legacy"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            quality = json.loads(
                (root / manifest["quality"]["path"]).read_text()
            )
            self.assertEqual(
                {
                    "evidence_kind": "legacy-summary",
                    "mode": "legacy",
                    "coverage_claim": "legacy-summary",
                    "selected_repositories": None,
                    "files_examined": None,
                    "bytes_examined": None,
                    "skipped_large_files": None,
                    "pruned_large_assets": None,
                    "policy": None,
                    "freshness": None,
                    "complete": None,
                },
                quality["scan"],
            )
            self.assertEqual(
                LEGACY_VISIBILITY_ATTESTATION,
                manifest["release"]["source_visibility_attestation"],
            )
            self.assertEqual([], validate_v2(root))

    def test_legacy_visibility_attestation_cannot_cover_state_quality(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            manifest_path = root / "manifest.json"
            manifest["release"]["source_visibility_attestation"] = (
                LEGACY_VISIBILITY_ATTESTATION
            )
            manifest_path.write_bytes(canonical_json(manifest))
            errors = validate_v2(root)
            self.assertTrue(
                any("legacy visibility attestation" in error for error in errors),
                errors,
            )

    def test_legacy_component_card_projects_parent_rows_without_new_flag(self):
        repo = {
            "libraries": [
                {
                    "library_id": "nvpl",
                    "classification": "bundled",
                    "operators": ["BLAS"],
                    "first_integration": "2025-01-01",
                }
            ]
        }
        legacy_card = {
            "id": "nvpl-blas",
            "parent_id": "nvpl",
            "is_component": True,
            "component_label": "BLAS",
        }
        projected = _effective_entry(repo, legacy_card)
        self.assertIsNotNone(projected)
        self.assertEqual("nvpl-blas", projected["library_id"])
        self.assertEqual("bundled", projected["classification"])

    def test_direct_component_entry_wins_over_legacy_parent_projection(self):
        repo = {
            "libraries": [
                {
                    "library_id": "cublas",
                    "classification": "confirmed",
                    "operators": ["cuBLASLt"],
                    "first_integration": "2020-01-01",
                },
                {
                    "library_id": "cublaslt",
                    "classification": "confirmed",
                    "operators": ["cublasLt.h"],
                    "first_integration": "2024-01-01",
                },
            ]
        }
        library = {
            "id": "cublaslt",
            "parent_id": "cublas",
            "component_label": "cuBLASLt",
            "projected_from_parent": False,
        }
        self.assertEqual(
            "2024-01-01",
            _effective_entry(repo, library)["first_integration"],
        )

    def test_atomic_install_replaces_manifest_last(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "staging"
            live = Path(temporary) / "live"
            build_v2_tree(current, timeseries, citations, deltas, staging)
            real_replace = os.replace
            destinations = []

            def recording_replace(source, destination):
                destinations.append(Path(destination).name)
                return real_replace(source, destination)

            with mock.patch(
                "collector.publish_v2.os.replace", side_effect=recording_replace
            ):
                _install_staged_tree(staging, live)
            self.assertEqual("manifest.json", destinations[-1])
            self.assertNotIn("manifest.json", destinations[:-1])
            self.assertEqual([], validate_v2(live))

    def test_exact_encoded_boundary_and_split(self):
        base = {
            "schema_version": "2.0",
            "kind": "repositories",
            "library_id": "fixture",
        }
        row = {"full_name": "public/" + ("x" * 80), "visibility": "PUBLIC"}
        one = _pack_json_rows(base, [row], 10_000)[0][0]
        exact = _pack_json_rows(base, [row], len(one) + 1)
        self.assertEqual(len(exact), 1)
        self.assertEqual(len(exact[0][0]), len(one))
        with self.assertRaisesRegex(PublicationError, "one record exceeds"):
            _pack_json_rows(base, [row], len(one))
        split = _pack_json_rows(base, [row, row], len(one) + 1)
        self.assertEqual([count for _data, count in split], [1, 1])
        self.assertTrue(all(len(data) < len(one) + 1 for data, _count in split))

    def test_validator_rejects_artifact_exactly_at_exclusive_limit(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            descriptor = manifest["libraries"][0]["index"]
            errors = validate_v2(root, target_bytes=descriptor["bytes"])
            self.assertTrue(
                any("target limit is strictly below" in error for error in errors),
                errors,
            )

    def test_oversized_single_record_fails_without_output(self):
        current, timeseries, citations, deltas = fixture()
        current["repos"][0]["description"] = "z" * 10_000
        with tempfile.TemporaryDirectory() as temporary:
            live = Path(temporary) / "v2"
            with self.assertRaisesRegex(PublicationError, "one record exceeds"):
                publish_v2(
                    current,
                    timeseries,
                    citations,
                    deltas,
                    live,
                    target_bytes=700,
                )
            self.assertFalse((live / "manifest.json").exists())

    def test_deterministic_bytes_and_release_metadata_isolation(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "one"
            second = Path(temporary) / "two"
            third = Path(temporary) / "three"
            build_v2_tree(current, timeseries, citations, deltas, first)
            build_v2_tree(current, timeseries, citations, deltas, second)
            self.assertEqual(tree_bytes(first), tree_bytes(second))

            changed = copy.deepcopy(current)
            changed["generated_at"] = "2026-07-28T12:00:00Z"
            build_v2_tree(changed, timeseries, citations, deltas, third)
            first_bytes = tree_bytes(first)
            third_bytes = tree_bytes(third)
            self.assertNotEqual(
                first_bytes.pop("manifest.json"), third_bytes.pop("manifest.json")
            )
            self.assertEqual(first_bytes, third_bytes)

    def test_release_identity_covers_manifest_card_semantics(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            original = build_v2_tree(
                current, timeseries, citations, deltas, first
            )
            changed = copy.deepcopy(current)
            changed["libraries"][0]["description"] = "Changed presentation."
            updated = build_v2_tree(
                changed, timeseries, citations, deltas, second
            )
            self.assertNotEqual(
                original["release"]["id"], updated["release"]["id"]
            )
            self.assertEqual(
                original["libraries"][0]["index"]["sha256"],
                updated["libraries"][0]["index"]["sha256"],
            )

            manifest_path = first / "manifest.json"
            tampered = json.loads(manifest_path.read_text())
            tampered["libraries"][0]["description"] = "Undeclared mutation."
            manifest_path.write_bytes(canonical_json(tampered))
            self.assertTrue(
                any(
                    "manifest semantics" in error
                    for error in validate_v2(first)
                )
            )

    def test_successful_publish_removes_unreferenced_superseded_artifacts(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            live = Path(temporary) / "v2"
            publish_v2(current, timeseries, citations, deltas, live)
            first_files = set(tree_bytes(live))
            stray = live / "unreferenced-private-scratch.txt"
            stray.write_text("must not remain deployable")

            changed = copy.deepcopy(current)
            changed["repos"][0]["description"] = "changed shard bytes"
            publish_v2(changed, timeseries, citations, deltas, live)
            second_files = set(tree_bytes(live))
            self.assertEqual([], validate_v2(live))
            self.assertFalse(stray.exists())
            superseded = first_files - second_files
            self.assertTrue(superseded)
            self.assertTrue(
                all(not (live / relative).exists() for relative in superseded)
            )

    def test_publication_and_validation_refuse_symlink_trees(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external = root / "external"
            external.mkdir()
            sentinel = external / "sentinel.txt"
            sentinel.write_text("must remain unchanged")
            linked_live = root / "linked-v2"
            linked_live.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(PublicationError, "symlink"):
                publish_v2(
                    current, timeseries, citations, deltas, linked_live
                )
            self.assertEqual("must remain unchanged", sentinel.read_text())

            live = root / "v2"
            publish_v2(current, timeseries, citations, deltas, live)
            manifest = json.loads((live / "manifest.json").read_text())
            artifact = live / manifest["libraries"][0]["index"]["path"]
            external_artifact = external / "artifact.json"
            external_artifact.write_bytes(artifact.read_bytes())
            artifact.unlink()
            artifact.symlink_to(external_artifact)
            errors = validate_v2(live)
            self.assertTrue(
                any("symlink" in error for error in errors), errors
            )
            with self.assertRaisesRegex(PublicationError, "symlink"):
                publish_v2(current, timeseries, citations, deltas, live)

    def test_wrong_hash_and_missing_artifact_are_rejected(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            build_v2_tree(current, timeseries, citations, deltas, root)
            manifest = json.loads((root / "manifest.json").read_text())
            indexed = root / manifest["libraries"][0]["index"]["path"]
            original = indexed.read_bytes()
            indexed.write_bytes(original + b" ")
            self.assertTrue(
                any("SHA-256" in error for error in validate_v2(root)),
                validate_v2(root),
            )
            indexed.write_bytes(original)
            indexed.unlink()
            self.assertTrue(
                any("missing" in error for error in validate_v2(root)),
                validate_v2(root),
            )

    def test_private_source_rejected_and_live_manifest_unchanged(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            live = Path(temporary) / "v2"
            publish_v2(current, timeseries, citations, deltas, live)
            prior = (live / "manifest.json").read_bytes()
            for field, value in (
                ("private", True),
                ("is_private", True),
                ("visibility_excluded", True),
                ("is_public", False),
                ("is_private", "false"),
            ):
                private = copy.deepcopy(current)
                private["repos"][0][field] = value
                with self.assertRaises(PublicationError) as raised:
                    publish_v2(private, timeseries, citations, deltas, live)
                self.assertNotIn("public/example", str(raised.exception))
                self.assertEqual(prior, (live / "manifest.json").read_bytes())

    def test_validator_rejects_private_duplicate_and_bad_aggregate(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            build_v2_tree(current, timeseries, citations, deltas, root)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            index_descriptor = manifest["libraries"][0]["index"]
            index_path = root / index_descriptor["path"]
            index = json.loads(index_path.read_text())
            shard_descriptor = index["repo_parts"][0]
            shard_path = root / shard_descriptor["path"]
            shard = json.loads(shard_path.read_text())
            shard["rows"][0]["visibility"] = "PRIVATE"
            shard["rows"][0]["is_private"] = True
            shard["rows"][0]["visibility_excluded"] = True
            shard["rows"].append(copy.deepcopy(shard["rows"][0]))
            encoded = canonical_json(shard)
            shard_path.write_bytes(encoded)
            shard_descriptor["bytes"] = len(encoded)
            shard_descriptor["sha256"] = hashlib.sha256(encoded).hexdigest()
            shard_descriptor["rows"] = len(shard["rows"])
            index["row_count"] = len(shard["rows"])
            index_data = canonical_json(index)
            index_path.write_bytes(index_data)
            index_descriptor["bytes"] = len(index_data)
            index_descriptor["sha256"] = hashlib.sha256(index_data).hexdigest()
            manifest["libraries"][0]["confirmed_count"] = 99
            manifest_path.write_bytes(canonical_json(manifest))
            errors = validate_v2(root)
            self.assertTrue(any("PUBLIC" in error for error in errors), errors)
            self.assertTrue(
                any("private repository row" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("visibility marker fields" in error for error in errors),
                errors,
            )
            self.assertTrue(any("duplicate" in error for error in errors), errors)
            self.assertTrue(any("reconcile" in error for error in errors), errors)

    def test_v1_parity_and_explicit_not_evaluated_coverage(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            self.assertEqual(
                STATE_VISIBILITY_ATTESTATION,
                manifest["release"]["source_visibility_attestation"],
            )
            self.assertEqual([], validate_v2(root))
            self.assertEqual(
                [], compare_v1_v2(
                    current, timeseries, citations, root, deltas
                )
            )

    def test_csv_exports_neutralize_formula_leading_repository_text(self):
        current, timeseries, citations, deltas = fixture()
        current["repos"][0]["description"] = " \t=HYPERLINK(\"bad\")"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            export_index = json.loads(
                (root / manifest["exports"]["path"]).read_text()
            )
            csv_part = root / export_index["csv_parts"][0]["path"]
            rows = list(csv.DictReader(io.StringIO(csv_part.read_text())))
            description = next(
                row["description"]
                for row in rows
                if row["full_name"] == "public/example"
            )
            self.assertTrue(description.startswith("'"))
            self.assertEqual([], validate_v2(root))
            changed_deltas = copy.deepcopy(deltas)
            changed_deltas["generated_at"] = "2099-01-01T00:00:00Z"
            self.assertIn(
                "V1/V2 deltas differ",
                compare_v1_v2(
                    current,
                    timeseries,
                    citations,
                    root,
                    changed_deltas,
                ),
            )
            index = json.loads(
                (root / manifest["libraries"][0]["index"]["path"]).read_text()
            )
            shard = json.loads(
                (root / index["repo_parts"][0]["path"]).read_text()
            )
            self.assertTrue(shard["rows"])
            for key in ("owner_type", "topics", "license"):
                self.assertNotIn(key, shard["rows"][0])
            xxl = next(card for card in manifest["libraries"] if card["id"] == "xxl")
            self.assertEqual(
                "not_evaluated",
                xxl["classification_coverage"]["bundled"],
            )
            self.assertEqual(
                "not_evaluated",
                xxl["classification_coverage"]["targeted"],
            )
            self.assertIsNone(xxl["bundled_count"])
            self.assertIsNone(xxl["targeted_count"])

    def test_frontend_fetch_boundaries_and_v2_fail_closed_cutover(self):
        home = (ROOT / "web/js/home.js").read_text()
        library = (ROOT / "web/js/library.js").read_text()
        loader = (ROOT / "web/js/data-v2.js").read_text()
        index_html = (ROOT / "web/index.html").read_text()
        library_html = (ROOT / "web/library.html").read_text()
        for source in (home, library):
            self.assertNotIn('loadJSON("data/current.json")', source)
            self.assertNotIn('loadJSON("data/citations.json")', source)
            self.assertNotIn('loadJSON("data/timeseries.json")', source)
        self.assertIn("paper sample capped", library)
        self.assertNotIn("incomplete coverage", library)
        self.assertNotIn("last-good carried-forward citation data", library)
        self.assertNotIn("badge warn\">stale", library)
        self.assertIn("headline is the source total", library)
        self.assertIn('loadJSON("data/v2/manifest.json")', loader)
        self.assertNotIn("optionalJSON", loader)
        self.assertIn("loadNextRepositoryPart", loader)
        self.assertIn("loadCitations", loader)
        self.assertIn("loadNextCitationPart", loader)
        self.assertIn("loadAllCitationParts", loader)
        self.assertNotIn('loadJSON("data/current.json")', loader)
        self.assertNotIn('loadJSON("data/citations.json")', loader)
        self.assertNotIn('mode: "v1"', loader)
        self.assertLess(index_html.index("data-v2.js"), index_html.index("home.js"))
        self.assertLess(
            library_html.index("data-v2.js"), library_html.index("library.js")
        )

    def test_public_ci_checks_source_without_data_or_collection(self):
        github_ci = (ROOT / ".github/workflows/tests.yml").read_text()
        self.assertIn("bash ops/run_tests.sh", github_ci)
        self.assertNotIn("python -m collector.cli validate", github_ci)
        self.assertNotIn("collector.cli refresh", github_ci)
        self.assertNotIn("collector.cli reconcile", github_ci)
        self.assertFalse((ROOT / ".gitlab-ci.yml").exists())
        self.assertIn("data/", (ROOT / ".gitignore").read_text())


class PublicationRecoveryRegressionTests(unittest.TestCase):
    def test_recovery_closure_prunes_unindexed_files_and_rejects_tampering(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, root
            )
            stray = root / "private-unindexed-scratch.json"
            stray.write_text('{"must":"be pruned"}\n')
            _close_and_validate_v2(root)
            self.assertFalse(stray.exists())
            self.assertEqual([], validate_v2(root))

            descriptor = manifest["libraries"][0]["index"]
            artifact = root / descriptor["path"]
            artifact.write_bytes(artifact.read_bytes() + b" ")
            with self.assertRaisesRegex(
                PipelineError, "recovering V2 release is invalid"
            ):
                _close_and_validate_v2(root)

    def test_matching_manifest_recovery_rolls_forward_and_finalizes_checkpoint(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            live = data / "v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, live
            )
            (live / "unindexed.json").write_text("{}\n")
            release_id = manifest["release"]["id"]
            pipeline = CollectorPipeline(repo_root=root)
            # Production journals use the pipeline's resolved data path.
            backup = (
                data / ".state-checkpoint-previous-fixture"
            ).resolve()
            backup.mkdir(parents=True)
            (backup / "sentinel").write_text("old checkpoint")
            quarantine = data / ".v2-superseded-fixture"
            quarantine.mkdir()
            (quarantine / "sentinel").write_text("old v2")

            with StateDB(root / ".state/collector.sqlite3") as state:
                state.create_run(
                    "recover-run", mode="reconcile", status="running"
                )
                state.update_stage(
                    "recover-run", "publication", status="running"
                )
                provisional = data / "state-checkpoint"
                state.export_checkpoint_shards(provisional)
                pipeline._write_publication_journal(
                    phase="v2_installed",
                    run_id="recover-run",
                    release_id=release_id,
                    artifacts=[{
                        "path": "data/v2/manifest.json",
                        "bytes": (live / "manifest.json").stat().st_size,
                    }],
                    counters={"artifacts": 1},
                    checkpoint_backup=str(backup),
                    checkpoint_had_live=True,
                    v2_quarantine=str(quarantine),
                )

                pipeline._recover_publication(state)

                self.assertFalse(pipeline._publication_journal_path.exists())
                self.assertFalse(backup.exists())
                self.assertFalse(quarantine.exists())
                self.assertFalse((live / "unindexed.json").exists())
                self.assertEqual([], validate_v2(live))
                run = state.connection.execute(
                    "SELECT status FROM runs WHERE run_id='recover-run'"
                ).fetchone()
                release = state.connection.execute(
                    """
                    SELECT status, validation_json FROM releases
                    WHERE release_id=?
                    """,
                    (release_id,),
                ).fetchone()
                self.assertEqual("complete", run["status"])
                self.assertEqual("published", release["status"])
                self.assertTrue(
                    json.loads(release["validation_json"])["recovered"]
                )

            with StateDB(root / "restored.sqlite3") as restored:
                restored.import_checkpoint(data / "state-checkpoint")
                self.assertEqual(
                    "complete",
                    restored.connection.execute(
                        "SELECT status FROM runs WHERE run_id='recover-run'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    "published",
                    restored.connection.execute(
                        "SELECT status FROM releases WHERE release_id=?",
                        (release_id,),
                    ).fetchone()[0],
                )

    def test_nonmatching_manifest_rollback_removes_first_provisional_checkpoint(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            build_v2_tree(
                current, timeseries, citations, deltas, data / "v2"
            )
            provisional = data / "state-checkpoint"
            provisional.mkdir()
            (provisional / "manifest.json").write_text(
                '{"provisional":true}\n'
            )
            pipeline = CollectorPipeline(repo_root=root)
            with StateDB(root / ".state/collector.sqlite3") as state:
                state.create_run(
                    "rollback-run", mode="reconcile", status="running"
                )
                pipeline._write_publication_journal(
                    phase="checkpoint_installed",
                    run_id="rollback-run",
                    release_id="not-the-live-release",
                    artifacts=[],
                    counters={},
                    checkpoint_had_live=False,
                )
                pipeline._recover_publication(state)
                self.assertFalse(provisional.exists())
                self.assertFalse(pipeline._publication_journal_path.exists())
                self.assertEqual(
                    "running",
                    state.connection.execute(
                        "SELECT status FROM runs WHERE run_id='rollback-run'"
                    ).fetchone()[0],
                )

    def test_invalid_roll_forward_keeps_journal_and_running_state_for_diagnosis(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            live = root / "data/v2"
            manifest = build_v2_tree(
                current, timeseries, citations, deltas, live
            )
            descriptor = manifest["libraries"][0]["index"]
            artifact = live / descriptor["path"]
            artifact.write_bytes(artifact.read_bytes() + b"tamper")
            pipeline = CollectorPipeline(repo_root=root)
            with StateDB(root / ".state/collector.sqlite3") as state:
                state.create_run(
                    "invalid-run", mode="reconcile", status="running"
                )
                pipeline._write_publication_journal(
                    phase="v2_installed",
                    run_id="invalid-run",
                    release_id=manifest["release"]["id"],
                    artifacts=[],
                    counters={},
                    checkpoint_had_live=False,
                )
                with self.assertRaisesRegex(
                    PipelineError, "recovering V2 release is invalid"
                ):
                    pipeline._recover_publication(state)
                self.assertTrue(pipeline._publication_journal_path.exists())
                self.assertEqual(
                    "running",
                    state.connection.execute(
                        "SELECT status FROM runs WHERE run_id='invalid-run'"
                    ).fetchone()[0],
                )
                self.assertIsNone(
                    state.connection.execute(
                        "SELECT 1 FROM releases WHERE release_id=?",
                        (manifest["release"]["id"],),
                    ).fetchone()
                )

    def test_injected_closure_failure_rolls_provisional_install_back_exactly(self):
        current, timeseries, citations, deltas = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            live = root / "v2"
            publish_v2(current, timeseries, citations, deltas, live)
            prior = tree_bytes(live)
            changed = copy.deepcopy(current)
            changed["repos"][0]["description"] = (
                "changed before injected closure failure"
            )
            real_validate = validate_v2
            calls = {"count": 0}

            def injected(root_path, **kwargs):
                calls["count"] += 1
                errors = real_validate(root_path, **kwargs)
                if calls["count"] == 2:
                    return errors + ["injected closure failure"]
                return errors

            with stage_v2(
                changed, timeseries, citations, deltas, live
            ) as staged:
                with mock.patch(
                    "collector.validate_v2.validate_v2",
                    side_effect=injected,
                ):
                    with self.assertRaisesRegex(
                        PublicationError, "closure validation failed"
                    ):
                        staged.provisional_install(live)
            self.assertEqual(prior, tree_bytes(live))
            self.assertFalse(
                any(live.rglob("*.publishing"))
            )
            self.assertEqual(
                [],
                list(root.glob(".v2-superseded-*")),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
