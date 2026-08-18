"""REQ-14 Phase 1 state, recovery, checkpoint and fingerprint tests.

Run: python3 test_req14_state.py
"""

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collector import fingerprints
from collector.catalog import CATALOG_EVENTS
from collector.state import StateDB
from collector.state_migrations import SCHEMA_VERSION


P = 0
F = 0


def check(name, condition):
    global P, F
    if condition:
        P += 1
        print("  PASS  " + name)
    else:
        F += 1
        print("  FAIL  " + name)


def fp(char):
    return {
        "discovery": char * 64,
        "detector": char * 64,
        "citation": char * 64,
        "dating": char * 64,
        "aggregation": char * 64,
        "presentation": char * 64,
        "release": char * 64,
    }


def seed(db):
    db.upsert_library("cublas", catalog={"name": "cuBLAS"}, fingerprints=fp("a"))
    admitted = db.upsert_repository(
        {
            "node_id": "R_public",
            "full_name": "acme/linear",
            "visibility": "public",
            "default_branch": "main",
            "head_sha": "abc",
        }
    )
    return admitted


print("1) schema migration is idempotent and WAL-backed")
with tempfile.TemporaryDirectory() as temporary:
    path = Path(temporary) / "state.sqlite3"
    with StateDB(path) as db:
        first = db.schema_version
        second = db.migrate()
        journal = db.connection.execute("PRAGMA journal_mode").fetchone()[0]
        migration_count = db.connection.execute(
            "SELECT COUNT(*) FROM schema_migrations"
        ).fetchone()[0]
    with StateDB(path) as reopened:
        check("schema reaches expected version", first == second == SCHEMA_VERSION)
        check(
            "each migration row is recorded exactly once",
            migration_count == SCHEMA_VERSION,
        )
        check("WAL mode remains enabled", journal.lower() == "wal")
        check("reopened database is integral", reopened.integrity_check() == "ok")
with tempfile.TemporaryDirectory() as temporary:
    legacy_path = Path(temporary) / "legacy.sqlite3"
    legacy = sqlite3.connect(legacy_path)
    legacy.execute("CREATE TABLE legacy_marker(value TEXT)")
    legacy.execute("INSERT INTO legacy_marker VALUES ('before')")
    legacy.commit()
    legacy.close()
    with StateDB(legacy_path):
        pass
    automatic_backup = Path(
        str(legacy_path) + ".pre-migration-v0-to-v1.backup"
    )
    backup_connection = sqlite3.connect(automatic_backup)
    marker = backup_connection.execute("SELECT value FROM legacy_marker").fetchone()[0]
    has_new_schema = backup_connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name='repositories'"
    ).fetchone()
    backup_connection.close()
    check("non-pristine database is backed up before migration",
          marker == "before" and has_new_schema is None)

print("\n2) transaction rollback and crash/reopen preserve only committed work")
with tempfile.TemporaryDirectory() as temporary:
    path = Path(temporary) / "state.sqlite3"
    db = StateDB(path)
    seed(db)
    try:
        with db.transaction(immediate=True):
            db.connection.execute(
                """
                INSERT INTO repositories(
                    node_id, full_name, visibility, first_seen_at, last_seen_at
                ) VALUES ('R_rollback', 'acme/rollback', 'public', 't', 't')
                """
            )
            raise RuntimeError("injected crash")
    except RuntimeError:
        pass
    db.close()
    with StateDB(path) as reopened:
        count = reopened.connection.execute(
            "SELECT COUNT(*) FROM repositories WHERE node_id='R_rollback'"
        ).fetchone()[0]
        check("injected crash rolls transaction back", count == 0)
        check("previous committed state survives reopen", reopened.get_repository("R_public") is not None)

print("\n3) stale task leases recover without losing task identity")
with tempfile.TemporaryDirectory() as temporary:
    task_path = Path(temporary) / "state.sqlite3"
    db = StateDB(task_path)
    seed(db)
    db.create_run("run-1", mode="incremental", status="running")
    task_id = db.enqueue_task(
        "run-1", "scan", "R_public:cublas", repository_id="R_public",
        library_id="cublas", payload={"visibility": "public"}
    )
    leased = db.lease_task(
        run_id="run-1", worker="worker-a", lease_seconds=10, now_epoch=100
    )
    db.close()  # simulate the coordinator dying while a worker owns the lease
    with StateDB(task_path) as db:
        recovered = db.recover_stale_tasks(now_epoch=111)
        leased_again = db.lease_task(
            run_id="run-1", worker="worker-b", lease_seconds=10, now_epoch=111
        )
        check("expected task was leased", leased["task_id"] == task_id)
        check("one stale task recovered", recovered == 1)
        check(
            "unknown stale-attempt usage blocks a new worker",
            leased_again is None,
        )
        try:
            db.complete_task(task_id, worker="worker-a", now_epoch=112)
            old_owner_blocked = False
        except RuntimeError:
            old_owner_blocked = True
        check("stale owner cannot commit", old_owner_blocked)
        attempt = db.connection.execute(
            """
            SELECT status, usage_complete FROM scan_attempts
            WHERE task_id=? AND attempt=1
            """,
            (str(task_id),),
        ).fetchone()
        check(
            "stale attempt remains an explicit incomplete interruption",
            attempt["status"] == "interrupted"
            and attempt["usage_complete"] == 0,
        )

print("\n4) public-only admission quarantines private/unknown repositories")
with tempfile.TemporaryDirectory() as temporary:
    with StateDB(Path(temporary) / "state.sqlite3") as db:
        seed(db)
        db.add_candidate(
            repository_id="R_public", library_id="cublas", source="github",
            query_fp="q", coverage_epoch="week-1", path="src/a.cu"
        )
        admitted = db.upsert_repository(
            {
                "node_id": "R_public",
                "full_name": "secret/private-name",
                "visibility": "private",
            }
        )
        unknown = db.upsert_repository(
            {"node_id": "R_unknown", "full_name": "secret/unknown"}
        )
        checkpoint = db.checkpoint_bytes().decode("utf-8")
        check("private transition is not admitted", admitted is None)
        check("missing visibility fails closed", unknown is None)
        check("prior repository and dependent candidate are purged",
              db.get_repository("R_public") is None)
        check("private names are absent from checkpoint",
              "secret/private-name" not in checkpoint and "secret/unknown" not in checkpoint)
        try:
            db.enqueue_task(
                "missing", "scan", "bad", payload={"visibility": "private"}
            )
            payload_blocked = False
        except ValueError:
            payload_blocked = True
        check("private markers are rejected at payload boundary", payload_blocked)
        try:
            db.create_run(
                "private-plan",
                mode="incremental",
                plan={
                    "is_public": False,
                    "full_name": "secret/private-plan",
                },
            )
            inverse_alias_blocked = False
        except ValueError:
            inverse_alias_blocked = True
        checkpoint = db.checkpoint_bytes().decode("utf-8")
        check(
            "inverse public alias is rejected before checkpoint export",
            inverse_alias_blocked
            and "secret/private-plan" not in checkpoint
            and "is_public" not in checkpoint,
        )
        db.create_run(
            "private-transition-journal",
            mode="incremental",
            plan={
                "outliers": [{
                    "full_name": "secret/private-transition",
                    "matched_path": "src/private-evidence.cu",
                }],
                "diagnostic": (
                    "secret/private-transition matched "
                    "src/private-evidence.cu"
                ),
            },
            status="running",
        )
        discovery_task = db.enqueue_task(
            "private-transition-journal",
            "discovery-query",
            "sg:cublas:private-transition",
            library_id="cublas",
            payload={"query": "fixture"},
        )
        db.lease_task_by_id(
            discovery_task,
            worker="audit",
            now_epoch=100,
        )
        db.complete_task(
            discovery_task,
            worker="audit",
            now_epoch=101,
            result={
                "version": 1,
                "kind": "discovery-query",
                "observations": [{
                    "repo_full_name": "secret/private-transition",
                    "repo_node_id": "R_private_transition",
                    "matched_path": "src/private-evidence.cu",
                }],
                "quarantined_observations": [],
                "certificate": {
                    "observations_count": 1,
                    "quarantined_count": 0,
                    "metrics": {},
                    "gaps": [{
                        "code": "fixture",
                        "detail": (
                            "secret/private-transition matched "
                            "src/private-evidence.cu"
                        ),
                    }],
                },
            },
        )
        metadata_task = db.enqueue_task(
            "private-transition-journal",
            "github-metadata-batch",
            "batch:private-transition",
            payload={
                "version": 1,
                "lookups": [{
                    "node_id": "R_private_transition",
                    "full_name": "secret/private-transition",
                }],
            },
        )
        db.lease_task_by_id(
            metadata_task,
            worker="audit",
            now_epoch=100,
        )
        db.complete_task(
            metadata_task,
            worker="audit",
            now_epoch=101,
            result={
                "version": 2,
                "kind": "github-metadata-batch",
                "repositories": [{
                    "request_key": "node:R_private_transition",
                    "requested_node_id": "R_private_transition",
                    "requested_full_name": "secret/private-transition",
                    "admitted_public": False,
                    "status": "private",
                    "error_count": 0,
                }],
                "error_count": 0,
                "request_count": 1,
                "points_used": 1,
                "remaining": 4999,
                "reset_at": None,
            },
        )
        local_task_journal = db.connection.execute(
            "SELECT payload_json, result_json FROM tasks WHERE task_id=?",
            (metadata_task,),
        ).fetchone()
        checkpoint_document = db.checkpoint_document()
        checkpoint = db.checkpoint_bytes().decode("utf-8")
        checkpoint_tasks = {
            row["task_key"]: row
            for row in checkpoint_document["tables"]["tasks"]["rows"]
        }
        discovery_result = json.loads(
            checkpoint_tasks[
                "sg:cublas:private-transition"
            ]["result_json"]
        )
        metadata_payload = json.loads(
            checkpoint_tasks[
                "batch:private-transition"
            ]["payload_json"]
        )
        metadata_result = json.loads(
            checkpoint_tasks[
                "batch:private-transition"
            ]["result_json"]
        )
        check(
            "local journal retains resumable private transition diagnostics",
            "secret/private-transition" in local_task_journal["payload_json"]
            and "secret/private-transition" in local_task_journal["result_json"],
        )
        check(
            "public checkpoint strips private transition identities and paths",
            "secret/private-transition" not in checkpoint
            and "src/private-evidence.cu" not in checkpoint
            and discovery_result["observations"] == []
            and metadata_payload["lookups"] == []
            and metadata_result["repositories"] == [],
        )
        unsafe_checkpoint = json.loads(json.dumps(checkpoint_document))
        unsafe_tasks = unsafe_checkpoint["tables"]["tasks"]["rows"]
        unsafe_metadata = next(
            row
            for row in unsafe_tasks
            if row["task_key"] == "batch:private-transition"
        )
        unsafe_metadata["payload_json"] = json.dumps({
            "lookups": [{
                "node_id": "R_private_transition",
                "full_name": "secret/private-transition",
            }],
        })
        try:
            db._validate_checkpoint(unsafe_checkpoint)
            unsafe_import_blocked = False
        except ValueError:
            unsafe_import_blocked = True
        check(
            "checkpoint import rejects unsanitized private task identity",
            unsafe_import_blocked,
        )

print("\n5) checkpoint bytes and shards are deterministic and importable")
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    with StateDB(root / "source.sqlite3") as source:
        seed(source)
        source.add_candidate(
            repository_id="R_public", library_id="cublas", source="github",
            query_fp="query", coverage_epoch="epoch", signal="header",
            path="src/a.cu", ref="main"
        )
        source.record_scan_result(
            repository_id="R_public", library_id="cublas", head_sha="abc",
            detector_fp="a" * 64, classification="confirmed", status="clean",
            evidence={"path": "src/a.cu"}, raw_first_commit="first"
        )
        source.record_repo_analysis(
            repository_id="R_public", head_sha="abc", ai_fp="ai",
            cff_fp="cff", analysis={"has_cff": False}, status="clean"
        )
        source.create_run("checkpoint-run", mode="incremental", status="running")
        source.update_stage(
            "checkpoint-run", "discover", status="complete",
            counters={"queries": 1}, checkpoint={"partition": "done"}
        )
        source.enqueue_task(
            "checkpoint-run", "scan", "R_public:cublas",
            repository_id="R_public", library_id="cublas"
        )
        source.record_discovery_coverage(
            run_id="checkpoint-run", library_id="cublas", source="github",
            query_fp="query", partition_key="all", complete=True,
            result_count=1, certificate={"terminal": True}
        )
        source.put_citation_cache(
            library_id="cublas", query_fp="cite", work_id="W1",
            payload_fp="payload", payload={"title": "Paper"}, sources={},
            status="fresh"
        )
        source.record_release(
            "release-1", run_id="checkpoint-run", state_txn="txn-1",
            manifest_path="data/v2/manifest.json", artifacts=[],
            validation={"ok": True}, status="validated"
        )
        bytes_one = source.checkpoint_bytes()
        bytes_two = source.checkpoint_bytes()
        first_file = source.export_checkpoint(root / "checkpoint-a.json").read_bytes()
        second_file = source.export_checkpoint(root / "checkpoint-b.json").read_bytes()
        source.export_checkpoint_shards(root / "shards-a", rows_per_shard=1)
        source.export_checkpoint_shards(root / "shards-b", rows_per_shard=1)
        manifests_equal = (
            (root / "shards-a/manifest.json").read_bytes()
            == (root / "shards-b/manifest.json").read_bytes()
        )
    with StateDB(root / "restored.sqlite3") as restored:
        restored.import_checkpoint(root / "shards-a")
        restored_bytes = restored.checkpoint_bytes()
    check("checkpoint serialization is byte deterministic",
          bytes_one == bytes_two == first_file == second_file)
    check("shard manifests are deterministic", manifests_equal)
    check("sharded checkpoint round-trips exactly", restored_bytes == bytes_one)

print("\n6) backup uses SQLite backup API and is independently readable")
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    with StateDB(root / "state.sqlite3") as db:
        seed(db)
        backup_path = db.backup(root / "backup.sqlite3")
        db.upsert_repository(
            {
                "node_id": "R_after",
                "full_name": "acme/after",
                "visibility": "public",
            }
        )
    with StateDB(backup_path) as backup:
        check("backup passes integrity check", backup.integrity_check() == "ok")
        check("backup captured committed pre-backup row",
              backup.get_repository("R_public") is not None)
        check("backup is an independent snapshot",
              backup.get_repository("R_after") is None)

print("\n7) positive dating refresh reuses raw evidence without changing verdicts")
with tempfile.TemporaryDirectory() as temporary:
    with StateDB(Path(temporary) / "state.sqlite3") as db:
        seed(db)
        positive_id = db.record_scan_result(
            repository_id="R_public",
            library_id="cublas",
            head_sha="abc",
            detector_fp="a" * 64,
            classification="confirmed",
            status="clean",
            evidence={
                "classification": "confirmed",
                "first_integration": "2020-01-02",
                "first_integration_commit": "first-commit",
                "own_source_files": ["src/a.cu"],
                "_dating_fp": "old-dating",
            },
            raw_first_commit="first-commit",
            raw_first_date="2020-01-02",
            derived_first_date="2020-01-02",
        )
        rejected_id = db.record_scan_result(
            repository_id="R_public",
            library_id="cublas",
            head_sha="abc",
            detector_fp="b" * 64,
            classification="rejected",
            status="clean",
            evidence={},
        )
        before = dict(db.connection.execute(
            "SELECT * FROM scan_results WHERE scan_result_id=?",
            (positive_id,),
        ).fetchone())
        pending = db.positive_scan_results_needing_redate(
            dating_fp="new-dating"
        )
        db.redate_positive_scan_result(
            positive_id, dating_fp="new-dating"
        )
        after = dict(db.connection.execute(
            "SELECT * FROM scan_results WHERE scan_result_id=?",
            (positive_id,),
        ).fetchone())
        evidence = json.loads(after["evidence_json"])
        rejected = dict(db.connection.execute(
            "SELECT * FROM scan_results WHERE scan_result_id=?",
            (rejected_id,),
        ).fetchone())
        check(
            "only the current positive row is selected for redating",
            [row["scan_result_id"] for row in pending] == [positive_id],
        )
        check(
            "redating preserves detector verdict and raw first-use evidence",
            all(
                after[key] == before[key]
                for key in (
                    "repository_id",
                    "library_id",
                    "head_sha",
                    "detector_fp",
                    "classification",
                    "status",
                    "raw_first_commit",
                    "raw_first_date",
                    "scanned_at",
                )
            )
            and evidence["classification"] == "confirmed"
            and evidence["own_source_files"] == ["src/a.cu"],
        )
        check(
            "redating updates only derived date and internal dating fingerprint",
            after["derived_first_date"] == "2020-01-02"
            and evidence["first_integration"] == "2020-01-02"
            and evidence["_dating_fp"] == "new-dating",
        )
        check(
            "rejected verdicts are not redating work and the update is idempotent",
            json.loads(rejected["evidence_json"]) == {}
            and db.positive_scan_results_needing_redate(
                dating_fp="new-dating"
            ) == [],
        )

print("\n8) canonical fingerprints are stable and selectively invalidate")
base_libraries = {
    "cublas": {
        "discovery": {"queries": ["cublas_v2.h"]},
        "detector": {"includes": ["cublas_v2.h"]},
        "citation": {"terms": ["cuBLAS"]},
        "presentation": {"name": "cuBLAS", "order": 1},
        "release": {"released_on": "2008-01-01"},
    },
    "cudnn": {
        "discovery": {"queries": ["cudnn.h"]},
        "detector": {"includes": ["cudnn.h"]},
        "citation": {"terms": ["cuDNN"]},
        "presentation": {"name": "cuDNN", "order": 2},
        "release": {"released_on": "2014-01-01"},
    },
}


def manifest(libraries):
    return fingerprints.build_manifest(
        libraries,
        dating_semantics={"version": 1},
        ai_semantics={"version": 1},
        filter_profiles={"native": {"vendor_roots": ["third_party"]}},
        aggregation_semantics={"headline": "confirmed"},
        publication_semantics={"schema": 2},
    )


first = manifest(base_libraries)
reordered = manifest(dict(reversed(list(base_libraries.items()))))
check("map ordering cannot change a fingerprint", first.as_dict() == reordered.as_dict())

release_change = json.loads(json.dumps(base_libraries))
release_change["cublas"]["release"]["released_on"] = "2007-01-01"
release_plan = fingerprints.invalidation_plan(first, manifest(release_change))
check("release date only reaggregates affected library",
      release_plan.reaggregate == {"cublas"}
      and not release_plan.scan and not release_plan.discover)

detector_change = json.loads(json.dumps(base_libraries))
detector_change["cublas"]["detector"]["symbols"] = ["cublasSgemm"]
detector_plan = fingerprints.invalidation_plan(first, manifest(detector_change))
check("detector change scans only affected library",
      detector_plan.scan == {"cublas"} and detector_plan.reaggregate == {"cublas"})

presentation_change = json.loads(json.dumps(base_libraries))
presentation_change["cudnn"]["presentation"]["name"] = "NVIDIA cuDNN"
presentation_plan = fingerprints.invalidation_plan(first, manifest(presentation_change))
check("presentation change only republishes affected library",
      presentation_plan.republish == {"cudnn"}
      and not presentation_plan.scan and not presentation_plan.reaggregate)

discovery_change = json.loads(json.dumps(base_libraries))
discovery_change["cudnn"]["discovery"]["queries"].append("cudnn_frontend.h")
discovery_plan = fingerprints.invalidation_plan(first, manifest(discovery_change))
check("discovery change reruns only affected discovery",
      discovery_plan.discover == {"cudnn"} and not discovery_plan.scan)

citation_change = json.loads(json.dumps(base_libraries))
citation_change["cublas"]["citation"]["terms"].append("Basic Linear Algebra")
citation_plan = fingerprints.invalidation_plan(first, manifest(citation_change))
check("citation change requeries only affected research data",
      citation_plan.cite == {"cublas"} and not citation_plan.scan)

dating_changed = fingerprints.build_manifest(
    base_libraries,
    dating_semantics={"version": 2},
    ai_semantics={"version": 1},
    filter_profiles={"native": {"vendor_roots": ["third_party"]}},
    aggregation_semantics={"headline": "confirmed"},
    publication_semantics={"schema": 2},
)
dating_plan = fingerprints.invalidation_plan(first, dating_changed)
check("dating change redates positives without current-tree rescan",
      dating_plan.redate_all_positives and not dating_plan.scan)

filter_changed = fingerprints.build_manifest(
    base_libraries,
    dating_semantics={"version": 1},
    ai_semantics={"version": 1},
    filter_profiles={"native": {"vendor_roots": ["third_party", "vendor"]}},
    aggregation_semantics={"headline": "confirmed"},
    publication_semantics={"schema": 2},
)
filter_plan = fingerprints.invalidation_plan(
    first, filter_changed, profile_libraries={"native": ["cublas"]}
)
check("shared filter invalidates only libraries using its profile",
      filter_plan.scan == {"cublas"} and filter_plan.refilter_profiles == {"native"})

print("\n9) catalog events are immutable and survive public checkpoints")
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    event = next(
        item for item in CATALOG_EVENTS if item["library_id"] == "cublas"
    )
    with StateDB(root / "state.sqlite3") as state:
        seed(state)
        first_insert = state.record_catalog_events([event])
        duplicate_insert = state.record_catalog_events([event])
        altered = dict(event, name="Changed without a rename event")
        try:
            state.record_catalog_events([altered])
            immutable = False
        except ValueError:
            immutable = True
        checkpoint = state.checkpoint_bytes()
    with StateDB(root / "restored.sqlite3") as restored:
        checkpoint_path = root / "checkpoint.json"
        checkpoint_path.write_bytes(checkpoint)
        restored.import_checkpoint(checkpoint_path)
        restored_event = restored.connection.execute(
            "SELECT * FROM catalog_events WHERE library_id='cublas'"
        ).fetchone()
    check("new catalog event is inserted once", first_insert == 1)
    check("identical catalog event is idempotent", duplicate_insert == 0)
    check("an event identity cannot be silently rewritten", immutable)
    check(
        "catalog event is present after checkpoint round-trip",
        restored_event is not None and restored_event["name"] == "cuBLAS",
    )

print("\n%d passed, %d failed" % (P, F))
if __name__ == "__main__":
    sys.exit(1 if F else 0)
if F:
    raise AssertionError(f"REQ-14 state tests failed during import: {F}")
