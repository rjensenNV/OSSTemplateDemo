"""Focused content-materialization safety regressions for REQ-14."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector import repo_cache as repo_cache_module
from collector.config import LIBRARIES
from collector.repo_cache import CacheError, RepoCache
from collector.scanner_v2 import (
    _assert_lfs_history_compatible,
    _scan_error_contract,
)
from collector.triage import triage_tree


def _git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout


def _pointer(payload):
    oid = hashlib.sha256(payload).hexdigest()
    return (
        oid,
        (
            "version https://git-lfs.github.com/spec/v1\n"
            "oid sha256:%s\n"
            "size %d\n" % (oid, len(payload))
        ),
    )


class PublicLFSMaterializationTests(unittest.TestCase):
    def _fixture(self, root, body):
        checkout = root / "checkout"
        checkout.mkdir()
        _git(checkout, "init", "-q")
        _git(checkout, "config", "user.name", "REQ14 Test")
        _git(checkout, "config", "user.email", "req14@example.invalid")
        path = checkout / "src" / "evidence.py"
        path.parent.mkdir()
        path.write_text(body)
        _git(checkout, "add", ".")
        cache = RepoCache(
            root / "cache",
            target_bytes=10**8,
            hard_bytes=2 * 10**8,
        )
        repo = cache.repo_path("public/example")
        repo.mkdir()
        cache.metadata_path("public/example").write_text(json.dumps({
            "full_name": "public/example",
            "head_sha": "a" * 40,
            "last_access": 1,
            "bytes": 0,
        }))
        cache.usage_path.write_text('{"total_bytes":0}')
        return cache, checkout, path

    def test_public_lfs_environment_strips_every_reusable_credential(self):
        with mock.patch.dict(
            os.environ,
            {
                "GH_TOKEN": "secret",
                "GITHUB_TOKEN": "secret",
                "OPENALEX_API_KEY": "secret",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": "Authorization: secret",
                "GIT_ASKPASS": "/tmp/secret-helper",
            },
            clear=False,
        ):
            env = RepoCache._public_lfs_env()
        for key in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "OPENALEX_API_KEY",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
        ):
            self.assertNotIn(key, env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_exact_public_object_is_hydrated_and_certified(self):
        payload = b"from cuquantum import CircuitToEinsum\n"
        oid, pointer = _pointer(payload)
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, path = self._fixture(Path(td), pointer)

            def lfs_command(_checkout, operation, *args):
                if operation == "fetch":
                    object_path = (
                        cache.repo_path("public/example")
                        / "lfs" / "objects"
                        / oid[:2] / oid[2:4] / oid
                    )
                    object_path.parent.mkdir(parents=True)
                    object_path.write_bytes(payload)
                elif operation == "checkout":
                    path.write_bytes(payload)
                else:
                    raise AssertionError(operation)
                return ""

            with (
                mock.patch.object(
                    cache, "_assert_public_lfs_policy"
                ),
                mock.patch.object(
                    cache,
                    "_run_public_lfs",
                    side_effect=lfs_command,
                ),
                mock.patch.object(
                    repo_cache_module,
                    "lfs_evidence_path_relevant",
                    return_value=True,
                ),
            ):
                materialized = cache._materialize_relevant_lfs(
                    "public/example",
                    checkout,
                    "a" * 40,
                    ("cuquantum",),
                )
            self.assertEqual(materialized, ("src/evidence.py",))
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(cache.network_fetch_count, 1)
            self.assertEqual(
                cache.network_materialized_bytes, len(payload)
            )
            certificate = cache._read_metadata(
                "public/example"
            )["lfs_materialization"]
            self.assertEqual(certificate["policy"], "exact-public-head-v1")
            self.assertTrue(
                certificate["objects"][0]["public_unauthenticated"]
            )

    def test_valid_crlf_pointer_on_relevant_path_is_hydrated(self):
        payload = b"from cuquantum import CircuitToEinsum\n"
        oid, pointer = _pointer(payload)
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, path = self._fixture(
                Path(td), pointer.replace("\n", "\r\n")
            )

            def lfs_command(_checkout, operation, *args):
                if operation == "fetch":
                    object_path = (
                        cache.repo_path("public/example")
                        / "lfs" / "objects"
                        / oid[:2] / oid[2:4] / oid
                    )
                    object_path.parent.mkdir(parents=True)
                    object_path.write_bytes(payload)
                elif operation == "checkout":
                    path.write_bytes(payload)
                else:
                    raise AssertionError(operation)
                return ""

            with (
                mock.patch.object(
                    cache, "_assert_public_lfs_policy"
                ),
                mock.patch.object(
                    cache,
                    "_run_public_lfs",
                    side_effect=lfs_command,
                ),
                mock.patch.object(
                    repo_cache_module,
                    "lfs_evidence_path_relevant",
                    return_value=True,
                ),
            ):
                materialized = cache._materialize_relevant_lfs(
                    "public/example",
                    checkout,
                    "a" * 40,
                    ("cuquantum",),
                )
            self.assertEqual(materialized, ("src/evidence.py",))
            self.assertEqual(path.read_bytes(), payload)

    def test_irrelevant_pointer_requires_no_network_or_policy_exception(self):
        _oid, pointer = _pointer(b"irrelevant")
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, _path = self._fixture(Path(td), pointer)
            with (
                mock.patch.object(
                    repo_cache_module,
                    "lfs_evidence_path_relevant",
                    return_value=False,
                ),
                mock.patch.object(
                    cache, "_assert_public_lfs_policy"
                ) as policy,
                mock.patch.object(cache, "_run_public_lfs") as lfs,
            ):
                self.assertEqual(
                    cache._materialize_relevant_lfs(
                        "public/example",
                        checkout,
                        "a" * 40,
                        ("cublas",),
                    ),
                    (),
                )
            policy.assert_not_called()
            lfs.assert_not_called()

    def test_missing_tracked_symlink_is_not_treated_as_an_lfs_pointer(self):
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, _path = self._fixture(
                Path(td), "ordinary\n"
            )
            invalid_target = (
                "cmake_minimum_required(VERSION 3.20)\n"
                "project(Kairos)\n"
            )
            blob_result = subprocess.run(
                ["git", "-C", str(checkout), "hash-object", "-w", "--stdin"],
                input=invalid_target,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(blob_result.returncode, 0, blob_result.stderr)
            _git(
                checkout,
                "update-index",
                "--add",
                "--cacheinfo",
                "120000,%s,CMakeLists.txt" % blob_result.stdout.strip(),
            )
            (checkout / "CMakeLists.txt").unlink(missing_ok=True)
            with (
                mock.patch.object(
                    repo_cache_module,
                    "lfs_evidence_path_relevant",
                    return_value=True,
                ),
                mock.patch.object(cache, "_assert_public_lfs_policy") as policy,
                mock.patch.object(cache, "_run_public_lfs") as lfs,
            ):
                self.assertEqual(
                    cache._materialize_relevant_lfs(
                        "public/example",
                        checkout,
                        "a" * 40,
                        ("cufft",),
                    ),
                    (),
                )
            policy.assert_not_called()
            lfs.assert_not_called()

    def test_missing_regular_detector_path_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, path = self._fixture(
                Path(td), "ordinary\n"
            )
            path.unlink()
            with mock.patch.object(
                repo_cache_module,
                "lfs_evidence_path_relevant",
                return_value=True,
            ):
                with self.assertRaisesRegex(
                    CacheError,
                    "detector-relevant sparse path is unavailable: src/evidence.py",
                ):
                    cache._materialize_relevant_lfs(
                        "public/example",
                        checkout,
                        "a" * 40,
                        ("cuquantum",),
                    )

    def test_failed_public_fetch_is_conservatively_charged(self):
        payload = b"from cuquantum import CircuitToEinsum\n"
        _oid, pointer = _pointer(payload)
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, _path = self._fixture(
                Path(td), pointer
            )
            with (
                mock.patch.object(
                    cache, "_assert_public_lfs_policy"
                ),
                mock.patch.object(
                    cache,
                    "_run_public_lfs",
                    side_effect=CacheError(
                        "public Git LFS object is unavailable"
                    ),
                ),
                mock.patch.object(
                    repo_cache_module,
                    "lfs_evidence_path_relevant",
                    return_value=True,
                ),
            ):
                with self.assertRaisesRegex(
                    CacheError, "unavailable"
                ):
                    cache._materialize_relevant_lfs(
                        "public/example",
                        checkout,
                        "a" * 40,
                        ("cuquantum",),
                    )
        self.assertEqual(cache.network_fetch_count, 1)
        self.assertEqual(
            cache.network_materialized_bytes, len(payload)
        )

    def test_failed_regular_fetch_is_counted_with_materialized_growth(self):
        with tempfile.TemporaryDirectory() as td:
            cache, _checkout, _path = self._fixture(
                Path(td), "ordinary\n"
            )
            repo = cache.repo_path("public/example")

            def failed_fetch(*_args, **_kwargs):
                pack = repo / "objects" / "pack" / "partial.pack"
                pack.parent.mkdir(parents=True)
                pack.write_bytes(b"partial-network-pack")
                raise TimeoutError("fetch timed out")

            with mock.patch.object(
                repo_cache_module,
                "_run",
                side_effect=failed_fetch,
            ):
                with self.assertRaises(TimeoutError):
                    cache._git_dir(
                        "public/example",
                        "fetch",
                        "origin",
                        "a" * 40,
                    )
            self.assertEqual(cache.network_fetch_count, 1)
            self.assertEqual(
                cache.network_materialized_bytes,
                len(b"partial-network-pack"),
            )

    def test_failed_regular_clone_is_counted_before_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cache = RepoCache(
                root / "cache",
                target_bytes=10**8,
                hard_bytes=2 * 10**8,
            )

            def failed_clone(command, *_args, **_kwargs):
                temporary = Path(command[-1])
                pack = temporary / "objects" / "pack" / "partial.pack"
                pack.parent.mkdir(parents=True)
                pack.write_bytes(b"partial-clone-pack")
                raise CacheError("clone failed")

            with mock.patch.object(
                repo_cache_module,
                "_run",
                side_effect=failed_clone,
            ):
                with self.assertRaisesRegex(CacheError, "clone failed"):
                    cache.ensure("public/example", head_sha="a" * 40)
            self.assertEqual(cache.network_clone_count, 1)
            self.assertEqual(
                cache.network_materialized_bytes,
                len(b"partial-clone-pack"),
            )

    def test_positive_hydrated_path_fails_closed_for_history(self):
        with self.assertRaisesRegex(
            RuntimeError, "historical first-adoption"
        ):
            _assert_lfs_history_compatible(
                ("src/evidence.py",),
                ("src/evidence.py",),
            )
        code, retryable, _detail = _scan_error_contract(
            "Git LFS object is unavailable for historical "
            "first-adoption dating: src/evidence.py"
        )
        self.assertEqual(code, "repository_content_unavailable")
        self.assertFalse(retryable)

    def test_hydrated_negative_has_no_history_blocker(self):
        _assert_lfs_history_compatible(
            ("src/other.py",),
            ("src/evidence.py",),
        )

    def test_mature_inventory_consumes_verified_hydrated_payload(self):
        payload = b"from cuquantum import CircuitToEinsum\n"
        _oid, pointer = _pointer(payload)
        with tempfile.TemporaryDirectory() as td:
            _cache, checkout, path = self._fixture(
                Path(td), pointer
            )
            # The index deliberately retains the immutable HEAD pointer while
            # the isolated worktree exposes the separately certified bytes.
            path.write_bytes(payload)
            cuquantum = next(
                library
                for library in LIBRARIES
                if library["id"] == "cuquantum"
            )
            result = triage_tree(
                checkout,
                [cuquantum],
                inventory_all=True,
                full_name="public/example",
                required_library_ids=("cuquantum",),
            )
        self.assertEqual(
            ("src/evidence.py",),
            result.hydrated_lfs_paths,
        )
        self.assertEqual(
            ("src/evidence.py",),
            result.direct_files["cuquantum"],
        )

    def test_custom_origin_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, _path = self._fixture(
                Path(td), "ordinary\n"
            )
            with mock.patch.object(
                cache,
                "_git_dir",
                return_value="https://attacker.invalid/public/example.git\n",
            ):
                with self.assertRaisesRegex(
                    CacheError, "canonical GitHub origin"
                ):
                    cache._assert_public_lfs_policy(
                        "public/example",
                        checkout,
                        ("src/evidence.py",),
                    )

    def test_local_lfs_transfer_and_url_rewrite_are_refused(self):
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, _path = self._fixture(
                Path(td), "ordinary\n"
            )
            for output in (
                "lfs.standalonetransferagent\n",
                "lfs.customtransfer.exfil.path\n",
                "url.ssh://attacker.invalid/.insteadof\n",
            ):
                with self.subTest(output=output):
                    with (
                        mock.patch.object(
                            cache,
                            "_git_dir",
                            return_value=(
                                "https://github.com/public/example.git\n"
                            ),
                        ),
                        mock.patch.object(
                            repo_cache_module,
                            "_run_command",
                            return_value=mock.Mock(
                                returncode=0,
                                stdout=output,
                                stderr="",
                            ),
                        ),
                    ):
                        with self.assertRaisesRegex(
                            CacheError,
                            "custom Git LFS endpoint/transfer/auth",
                        ):
                            cache._assert_public_lfs_policy(
                                "public/example",
                                checkout,
                                ("src/evidence.py",),
                            )

    def test_worktree_scoped_lfs_endpoint_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            cache, checkout, _path = self._fixture(
                Path(td), "ordinary\n"
            )
            _git(
                checkout,
                "config",
                "extensions.worktreeConfig",
                "true",
            )
            _git(
                checkout,
                "config",
                "--worktree",
                "lfs.url",
                "https://attacker.invalid/lfs",
            )
            with mock.patch.object(
                cache,
                "_git_dir",
                return_value="https://github.com/public/example.git\n",
            ):
                with self.assertRaisesRegex(
                    CacheError,
                    "custom Git LFS endpoint/transfer/auth",
                ):
                    cache._assert_public_lfs_policy(
                        "public/example",
                        checkout,
                        ("src/evidence.py",),
                    )


if __name__ == "__main__":
    unittest.main()
