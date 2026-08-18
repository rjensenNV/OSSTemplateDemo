"""Local-only deterministic refresh-gate tests."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from collector.publish_v2 import build_v2_tree
from collector.run import _detection_hash
from collector.validate_refresh import _count_anomalies, component_counts
from test_req14_publication import fixture as publication_fixture

ROOT = os.path.dirname(os.path.abspath(__file__))
OLD_HASH = "75c876497a5e544c"
NEW_HASH = _detection_hash()


def git(cwd, *args):
    return subprocess.run(["git"] + list(args), cwd=cwd, check=True,
                          capture_output=True, text=True)


def document(count, detection_hash, generated_at):
    repos = [
        {
            "full_name": "fixture/repo-%d" % i,
            "libraries": [{"library_id": "fixture", "classification": "confirmed"}],
        }
        for i in range(count)
    ]
    return {
        "generated_at": generated_at,
        "detection_hash": detection_hash,
        "totals": {"confirmed_integrator_repos": count},
        "libraries": [{
            "id": "fixture",
            "confirmed_count": count,
            "bundled_count": 0,
            "targeted_count": 0,
            "headline_count": count,
        }],
        "repos": repos,
    }


def write_json(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(value, fh)


def validate(cwd):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run(
        [sys.executable, "-m", "collector.validate_refresh", "--baseline", "HEAD"],
        cwd=cwd, env=env, capture_output=True, text=True)


def validate_v2_command(cwd):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "collector.validate_refresh",
            "--v2",
            "--baseline",
            "HEAD",
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


def main():
    v2_baseline = {
        "libraries": [
            {
                "id": "direct",
                "confirmed_count": 10,
                "bundled_count": None,
                "targeted_count": None,
                "headline_count": 10,
            },
            {
                "id": "pending",
                "confirmed_count": None,
                "bundled_count": None,
                "targeted_count": None,
                "headline_count": None,
            },
        ],
        "totals": {"confirmed_integrator_repos": 10},
    }
    assert _count_anomalies(v2_baseline, v2_baseline) == []
    v2_anomaly = json.loads(json.dumps(v2_baseline))
    v2_anomaly["libraries"][0]["confirmed_count"] = 30
    v2_anomaly["libraries"][0]["headline_count"] = 30
    v2_anomaly["totals"]["confirmed_integrator_repos"] = 40
    v2_errors = _count_anomalies(v2_baseline, v2_anomaly)
    assert any("direct confirmed_count" in item for item in v2_errors)
    assert any("portfolio confirmed total" in item for item in v2_errors)
    print("PASS V2 null metrics and unattended count anomalies are handled")

    projected = component_counts({
        "generated_at": "2026-07-24T00:00:00Z",
        "repos": [{
            "full_name": "fixture/nvpl",
            "ai_assisted": False,
            "libraries": [{
                "library_id": "nvpl",
                "classification": "bundled",
                "operators": ["BLAS"],
                "first_integration": "2026-01-01",
            }],
        }],
    })
    assert projected["nvpl-blas"]["bundled_count"] == 1
    assert projected["nvpl-blas"]["headline_count"] == 1
    print("PASS component counts are re-projected from parent repo entries")

    with tempfile.TemporaryDirectory(prefix="cxit_validate_v2_") as repo:
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "user.name", "Test")
        current, timeseries, citations, deltas = publication_fixture()
        build_v2_tree(
            current,
            timeseries,
            citations,
            deltas,
            Path(repo) / "data" / "v2",
        )
        git(repo, "add", "data/v2")
        git(repo, "commit", "-q", "-m", "V2 baseline")
        result = validate_v2_command(repo)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "V2 refresh validation PASSED" in result.stdout
        print("PASS V2 artifact, ledger, and manifest anomaly gate")

    with tempfile.TemporaryDirectory(prefix="cxit_validate_") as repo:
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "user.name", "Test")
        write_json(os.path.join(repo, "data", "current.json"),
                   document(1, OLD_HASH, "2026-07-15T00:00:00Z"))
        write_json(os.path.join(repo, "data", "timeseries.json"), {})
        write_json(os.path.join(repo, "data", "deltas.json"), {"scan_error_count": 0})
        write_json(os.path.join(repo, "scanned_ledger.json"),
                   {"detection_hash": OLD_HASH, "shas": {}})
        git(repo, "add", "data")
        git(repo, "add", "scanned_ledger.json")
        git(repo, "commit", "-q", "-m", "baseline")

        write_json(os.path.join(repo, "data", "current.json"),
                   document(1, NEW_HASH, "2026-07-24T00:00:00Z"))
        write_json(os.path.join(repo, "scanned_ledger.json"),
                   {"detection_hash": NEW_HASH, "shas": {}})
        result = validate(repo)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "refresh validation PASSED" in result.stdout
        print("PASS full-reconcile detection-hash transition accepted by validation")

        write_json(os.path.join(repo, "data", "current.json"),
                   document(20, NEW_HASH, "2026-07-24T00:00:00Z"))
        result = validate(repo)
        assert result.returncode == 1
        assert "unattended anomaly" in result.stdout
        print("PASS unexplained count anomaly blocked")

        write_json(os.path.join(repo, "data", "current.json"),
                   document(1, NEW_HASH, "2026-07-24T00:00:00Z"))
        write_json(os.path.join(repo, "scanned_ledger.json"),
                   {"detection_hash": "wrong-hash", "shas": {}})
        result = validate(repo)
        assert result.returncode == 1
        assert "ledger detection hash" in result.stdout
        print("PASS mismatched scanned ledger blocked")

        current = document(1, NEW_HASH, "2026-07-24T00:00:00Z")
        current["discovery_stats"] = {
            "fixture": {"coverage_gaps": ["fixture query"]},
        }
        write_json(os.path.join(repo, "data", "current.json"), current)
        write_json(os.path.join(repo, "scanned_ledger.json"),
                   {"detection_hash": NEW_HASH, "shas": {}})
        result = validate(repo)
        assert result.returncode == 1
        assert "discovery contains 1 incomplete/capped" in result.stdout
        print("PASS incomplete discovery coverage blocks publication")

    print("\n7 passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
