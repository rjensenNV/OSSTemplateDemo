"""Focused clone-corruption, retry, and whole-repository-timeout smoke tests.

Uses only local temporary git repositories; it never touches GitHub or data/.
"""
import os
import subprocess
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collector import scan
from collector.config import LIBRARIES


def git(*args, cwd=None):
    return subprocess.run(["git"] + list(args), cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def commit_at(repo, message, date):
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = date
    env["GIT_COMMITTER_DATE"] = date
    subprocess.run(
        ["git", "commit", "-q", "-m", message],
        cwd=repo,
        env=env,
        check=True,
    )
    return git("rev-parse", "HEAD", cwd=repo)


def init_repo(path):
    os.makedirs(path)
    git("init", "-q", "-b", "main", cwd=path)
    git("config", "user.email", "test@example.com", cwd=path)
    git("config", "user.name", "Test", cwd=path)


def fixture_remote(root):
    source = os.path.join(root, "source")
    remote = os.path.join(root, "origin.git")
    os.makedirs(source)
    git("init", "-q", "-b", "main", cwd=source)
    git("config", "user.email", "test@example.com", cwd=source)
    git("config", "user.name", "Test", cwd=source)
    with open(os.path.join(source, "kernel.cu"), "w") as fh:
        fh.write("#include <cufftdx.hpp>\n")
    git("add", "kernel.cu", cwd=source)
    git("commit", "-q", "-m", "add cufftdx", cwd=source)
    git("clone", "-q", "--bare", source, remote)
    return remote


def clone_from(remote, dest):
    p = subprocess.run(["git", "clone", "-q", "--no-local", remote, dest],
                       capture_output=True, text=True, timeout=20)
    return (p.returncode == 0, p.stderr.strip())


def corrupt_commit_graph(dest):
    git("commit-graph", "write", "--reachable", cwd=dest)
    candidates = [
        os.path.join(dest, ".git", "objects", "info", "commit-graph"),
        os.path.join(dest, ".git", "objects", "info", "commit-graphs",
                     "commit-graph-chain"),
    ]
    graph = next(p for p in candidates if os.path.exists(p))
    os.chmod(graph, 0o600)
    with open(graph, "r+b") as fh:
        fh.truncate(16)


def main():
    cufftdx = next(lib for lib in LIBRARIES if lib["id"] == "cufftdx")
    nvshmem = next(lib for lib in LIBRARIES if lib["id"] == "nvshmem")
    with tempfile.TemporaryDirectory(prefix="cxit_resilience_") as root:
        remote = fixture_remote(root)

        print("1) corrupt commit-graph -> reject clone -> fresh re-clone -> success")
        calls = []

        def corrupted_then_clean(_full_name, dest):
            ok, reason = clone_from(remote, dest)
            calls.append(dest)
            if ok and len(calls) == 1:
                corrupt_commit_graph(dest)
            return ok, reason

        logs = []
        with mock.patch.object(scan, "_clone", side_effect=corrupted_then_clean):
            result = scan.scan_repo("fixture/corrupt-cache", [cufftdx], logs.append,
                                    repo_timeout=30, clone_attempts=2, retry_delay=0)
        assert result and result["libraries"]["cufftdx"]["classification"] == "confirmed"
        assert len(calls) == 2
        assert any("retrying with a fresh clone" in line for line in logs)
        assert any("recovered after fresh re-clone" in line for line in logs)
        print("  PASS corrupted clone was discarded and the clean retry completed")

        print("2) transient clone failure -> retry -> success")
        calls.clear()

        def failed_then_clean(_full_name, dest):
            calls.append(dest)
            if len(calls) == 1:
                return False, "synthetic transport failure"
            return clone_from(remote, dest)

        logs = []
        with mock.patch.object(scan, "_clone", side_effect=failed_then_clean):
            result = scan.scan_repo("fixture/retry", [cufftdx], logs.append,
                                    repo_timeout=30, clone_attempts=2, retry_delay=0)
        assert result and len(calls) == 2
        assert any("synthetic transport failure" in line for line in logs)
        print("  PASS transient clone failure recovered on attempt 2")

        print("3) per-command timeout -> fresh re-clone -> success")
        calls.clear()

        def command_timeout_then_clean(_full_name, dest):
            calls.append(dest)
            if len(calls) == 1:
                scan._run_command(
                    [sys.executable, "-c", "import time; time.sleep(30)"], 0.2)
            return clone_from(remote, dest)

        logs = []
        with mock.patch.object(scan, "_clone", side_effect=command_timeout_then_clean):
            result = scan.scan_repo("fixture/command-timeout", [cufftdx], logs.append,
                                    repo_timeout=30, clone_attempts=2, retry_delay=0)
        assert result and len(calls) == 2
        assert any("retrying with a fresh clone" in line for line in logs)
        print("  PASS per-command timeout used the remaining repository retry budget")

        print("4) whole-repository deadline -> process group killed -> clean skip")
        logs = []

        def hanging_clone(_full_name, _dest):
            scan._run_command(
                [sys.executable, "-c", "import time; time.sleep(30)"], 30)
            return False, "unreachable"

        started = time.monotonic()
        with mock.patch.object(scan, "_clone", side_effect=hanging_clone):
            result = scan.scan_repo("fixture/hang", [cufftdx], logs.append,
                                    repo_timeout=0.25, clone_attempts=2, retry_delay=0)
        elapsed = time.monotonic() - started
        assert result is None
        assert elapsed < 3, elapsed
        assert any("repo timeout" in line for line in logs)
        print("  PASS deadline fired in %.2fs and the repo was skipped" % elapsed)

        print("5) non-UTF8 git metadata is decoded without aborting the repository")
        result = scan._run_command(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(bytes([255, 10]))",
            ],
            5,
        )
        assert "\ufffd" in result.stdout
        print("  PASS undecodable bytes were safely replaced")

        print("6) nested mature scan preserves the outer repository deadline")
        outer_deadline = time.monotonic() + 5
        previous_deadline = scan._ACTIVE_REPO_DEADLINE[0]
        scan._ACTIVE_REPO_DEADLINE[0] = outer_deadline
        observed = []

        def observe_deadline(*_args, **_kwargs):
            observed.append(scan._ACTIVE_REPO_DEADLINE[0])
            return {}

        try:
            with mock.patch.object(
                scan, "_scan_repo_once", side_effect=observe_deadline
            ):
                result = scan.scan_repo(
                    "fixture/nested-deadline",
                    [cufftdx],
                    lambda _message: None,
                    repo_timeout=30,
                    clone_attempts=1,
                    checkout=root,
                )
        finally:
            scan._ACTIVE_REPO_DEADLINE[0] = previous_deadline
        assert result == {}
        assert observed and observed[0] == outer_deadline
        print("  PASS inner detector did not reset cache/triage time budget")

        print("7) commented includes and prefix headers do not confirm")
        precision_repo = os.path.join(root, "include-precision")
        init_repo(precision_repo)
        fixtures = {
            "line.cu": "// #include <nvshmem.h>\n",
            "block.cu": "/* #include <nvshmem.h> */\n",
            "prefix.cu": "#include <fake_nvshmem.h>\n",
        }
        for name, content in fixtures.items():
            with open(
                os.path.join(precision_repo, name),
                "w",
                encoding="utf-8",
            ) as stream:
                stream.write(content)
        git("add", ".", cwd=precision_repo)
        commit_at(
            precision_repo,
            "commented and colliding includes",
            "2020-01-01T00:00:00+00:00",
        )
        result = scan.scan_repo(
            "fixture/include-precision",
            [nvshmem],
            lambda _message: None,
            repo_timeout=30,
            clone_attempts=1,
            checkout=precision_repo,
        )
        assert result
        assert result["libraries"]["nvshmem"]["classification"] == "targeted"
        assert result["libraries"]["nvshmem"]["own_source_file_count"] == 0
        print("  PASS comment and exact-header boundaries preserve targeted")

        print("8) first use requires a historical uncommented include")
        history_repo = os.path.join(root, "include-history")
        init_repo(history_repo)
        source_path = os.path.join(history_repo, "use.cu")
        with open(source_path, "w", encoding="utf-8") as stream:
            stream.write("// #include <nvshmem.h>\n")
        git("add", "use.cu", cwd=history_repo)
        commit_at(
            history_repo,
            "line-commented include",
            "2021-01-01T00:00:00+00:00",
        )
        with open(source_path, "w", encoding="utf-8") as stream:
            stream.write("/*\n#include <nvshmem.h>\n*/\n")
        git("add", "use.cu", cwd=history_repo)
        commit_at(
            history_repo,
            "block-commented include",
            "2022-01-01T00:00:00+00:00",
        )
        with open(source_path, "w", encoding="utf-8") as stream:
            stream.write("#include <nvshmem.h>\n")
        git("add", "use.cu", cwd=history_repo)
        confirmed_commit = commit_at(
            history_repo,
            "activate exact include",
            "2023-01-01T00:00:00+00:00",
        )
        result = scan.scan_repo(
            "fixture/include-history",
            [nvshmem],
            lambda _message: None,
            repo_timeout=30,
            clone_attempts=1,
            checkout=history_repo,
        )
        row = result["libraries"]["nvshmem"]
        assert row["classification"] == "confirmed"
        assert row["own_source_files"] == ["use.cu"]
        assert row["first_integration"] == "2023-01-01"
        assert row["first_integration_commit"] == confirmed_commit[:12]
        print("  PASS first-use boundary is the real exact include commit")

    print("\n8 passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
