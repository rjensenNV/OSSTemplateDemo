"""REQ-14 safety regressions that must hold before the V2 cutover."""

import contextlib
import io
import tempfile
from pathlib import Path
from unittest import mock

from collector import citation_extract, citations, publish_v2, run, scan

ROOT = Path(__file__).resolve().parent


def _entry(name, libraries, stars=0):
    return {
        "full_name": name,
        "stars": stars,
        "total_commits": 10,
        "ai_assisted": False,
        "libraries": libraries,
    }


def _lib(library_id, commit, files):
    return {
        "library_id": library_id,
        "classification": "confirmed",
        "first_integration_commit": commit,
        "own_source_files": files,
        "operators": [],
    }


def test_dedup_keeps_diverged_reuploads():
    shared = "abc123"
    repos = [
        _entry("org/original", [_lib("cufftdx", shared, ["src/a.cu"])], stars=2),
        _entry("org/diverged", [
            _lib("cufftdx", shared, ["src/a.cu"]),
            _lib("cublasdx", "later456", ["src/new.cu"]),
        ], stars=1),
    ]
    messages = []
    kept, dropped = run._dedup_mirrors(repos, messages.append)
    assert {r["full_name"] for r in kept} == {"org/original", "org/diverged"}
    assert dropped == []
    assert any("diverged" in message for message in messages)


def test_dedup_collapses_only_identical_evidence():
    shared = "abc123"
    evidence = [_lib("cufftdx", shared, ["src/a.cu"])]
    repos = [
        _entry("org/low", evidence, stars=1),
        _entry("org/high", [dict(evidence[0])], stars=10),
    ]
    kept, dropped = run._dedup_mirrors(repos, lambda _message: None)
    assert [r["full_name"] for r in kept] == ["org/high"]
    assert dropped[0]["dropped"] == "org/low"


def test_retired_v1_command_is_network_and_write_free():
    stderr = io.StringIO()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "must-not-exist"
        with mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("retired command attempted network"),
        ) as connect, mock.patch(
            "urllib.request.urlopen",
            side_effect=AssertionError("retired command attempted network"),
        ) as urlopen, mock.patch(
            "builtins.open",
            side_effect=AssertionError("retired command attempted a file write"),
        ) as file_open, contextlib.redirect_stderr(stderr):
            status = run.main([
                "--incremental",
                "--libraries", "fixture",
                "--out", str(out),
            ])

        assert status == 2
        assert not out.exists()
        connect.assert_not_called()
        urlopen.assert_not_called()
        file_open.assert_not_called()
    assert "collector.cli refresh" in stderr.getvalue()


def test_mac_refresh_validates_local_data_without_publishing_it():
    script = (ROOT / "refresh.sh").read_text()
    v2_gate = "\nif ! python3 -m collector.cli validate; then"
    assert v2_gate in script
    assert "git add" not in script
    assert "git commit" not in script
    assert "push_data_refresh" not in script
    assert "generated artifacts remain local under data/" in script
    assert "supported weekly collection driver" in script


def test_child_process_environments_do_not_inherit_collector_secrets():
    with mock.patch.dict(
        "os.environ",
        {
            "GITHUB_TOKEN": "github-secret",
            "GH_TOKEN": "alternate-secret",
            "OPENALEX_API_KEY": "openalex-secret",
            "PATH": "/usr/bin:/bin",
        },
        clear=True,
    ):
        git_environment = scan._git_auth_env()
        parser_environment = citation_extract._native_parser_env()

    assert "GITHUB_TOKEN" not in git_environment
    assert "GH_TOKEN" not in git_environment
    assert "OPENALEX_API_KEY" not in git_environment
    assert git_environment["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert "Authorization: Basic " in git_environment["GIT_CONFIG_VALUE_0"]
    assert parser_environment == {"PATH": "/usr/bin:/bin"}


def test_retired_v1_mutation_commands_refuse_before_work():
    stderr = io.StringIO()
    with mock.patch(
        "collector.publish_v2.publish_from_v1",
        side_effect=AssertionError("retired publication command mutated data"),
    ), mock.patch(
        "collector.citations.run",
        side_effect=AssertionError("retired citation command collected"),
    ), contextlib.redirect_stderr(stderr):
        assert publish_v2.main(["--data-dir", "data"]) == 2
        assert citations.main(["--data", "data"]) == 2
    assert "collector.cli refresh" in stderr.getvalue()


def main():
    test_dedup_keeps_diverged_reuploads()
    test_dedup_collapses_only_identical_evidence()
    test_retired_v1_command_is_network_and_write_free()
    test_mac_refresh_validates_local_data_without_publishing_it()
    test_child_process_environments_do_not_inherit_collector_secrets()
    test_retired_v1_mutation_commands_refuse_before_work()
    print("req14 safety tests passed")


if __name__ == "__main__":
    main()
