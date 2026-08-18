import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from collector.config import LIBRARIES
from collector.evidence_content import (
    NotebookEvidenceError,
    parse_lfs_pointer,
    parse_notebook_surfaces,
)
from collector.scan import _notebook_source_surfaces
from collector.triage import (
    BareTriageRequiresWorktree,
    _embedded_project_roots,
    _notebook_might_affect_verdict,
    _notebook_retention_pattern,
    _notebook_surfaces,
    lfs_evidence_path_relevant,
    triage_tree,
)


def _library(identifier):
    return next(
        library for library in LIBRARIES
        if library["id"] == identifier
    )


def _pointer(oid="a" * 64, size=123):
    return (
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:%s\n"
        "size %d\n" % (oid, size)
    )


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _bare_entries(root):
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    records = _git(
        root, "ls-tree", "-rz", "--full-tree", head
    ).split(b"\0")
    entries = []
    for record in records:
        if not record:
            continue
        metadata, encoded_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode().split()
        entries.append(
            (
                mode,
                object_type,
                object_id,
                encoded_path.decode(),
            )
        )
    return head, tuple(entries)


class NotebookEvidenceContentTests(unittest.TestCase):
    def test_strict_notebook_exposes_only_authored_surfaces(self):
        raw = json.dumps({
            "metadata": {"cudnn": "ignored"},
            "cells": [
                {
                    "cell_type": "markdown",
                    "source": ["targets cuBLAS"],
                    "metadata": {"cudnn": "ignored"},
                },
                {
                    "cell_type": "code",
                    "source": ["import cudf"],
                    "outputs": [{"text": ["import tensorrt"]}],
                },
            ],
        })
        surfaces = parse_notebook_surfaces(raw)
        self.assertEqual(
            "targets cuBLAS\nimport cudf",
            surfaces.search_text,
        )
        self.assertEqual("import cudf", surfaces.code_text)
        self.assertEqual("strict-json", surfaces.recovery)
        self.assertEqual(
            (surfaces.search_text, surfaces.code_text),
            _notebook_source_surfaces(raw),
        )
        self.assertEqual(
            (surfaces.search_text, surfaces.code_text),
            _notebook_surfaces(raw),
        )

    def test_bom_and_misnamed_python_are_bounded_recoveries(self):
        bom = ("\ufeff" + json.dumps({
            "cells": [{
                "cell_type": "code",
                "source": ["import cudf"],
            }],
        })).encode()
        self.assertEqual(
            "import cudf",
            parse_notebook_surfaces(bom).code_text,
        )
        script = "#!/usr/bin/env python3\nimport cudf\n"
        surfaces = parse_notebook_surfaces(script.encode())
        self.assertEqual(script, surfaces.search_text)
        self.assertEqual(script, surfaces.code_text)
        self.assertEqual("python-shebang-source", surfaces.recovery)

    def test_trailing_comma_json_preserves_authored_surfaces(self):
        raw = (
            '{"cells":[{"cell_type":"code",'
            '"source":["value = \\\"comma, before } stays\\\"\\n",'
            '"import cudf"]}],'
            '"metadata":{"vscode":{"name":"example",},'
            '"tags":["one",],}}'
        )
        surfaces = parse_notebook_surfaces(raw)
        self.assertEqual(
            'value = "comma, before } stays"\nimport cudf',
            surfaces.code_text,
        )
        self.assertEqual(
            "trailing-comma-json",
            surfaces.recovery,
        )
        with self.assertRaisesRegex(
            NotebookEvidenceError,
            "^notebook is invalid JSON$",
        ):
            parse_notebook_surfaces(
                '{"cells":[{"cell_type":"code" '
                '"source":["import cudf"]}]}'
            )
        for malformed in (
            '{"cells":[],}',
            '{"cells":[{"cell_type":"code","source":["x"]},]}',
            '{"cells":[{"cell_type":"code","source":["x",]}]}',
            '{"cells":[{"cell_type":"code","source":["x"]}],}',
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(
                    NotebookEvidenceError,
                    "^notebook is invalid JSON$",
                ):
                    parse_notebook_surfaces(malformed)

    def test_strict_json_preserves_literal_authored_controls(self):
        raw = json.dumps({
            "cells": [
                {
                    "cell_type": "markdown",
                    "source": ["text\bcontinues"],
                },
                {
                    "cell_type": "code",
                    "source": ["chars = '\ufffd'\nimport cudf"],
                },
            ],
        }, ensure_ascii=False)
        surfaces = parse_notebook_surfaces(raw)
        self.assertEqual("strict-json", surfaces.recovery)
        self.assertEqual(
            "chars = '\ufffd'\nimport cudf",
            surfaces.code_text,
        )

    def test_output_only_decode_damage_is_recoverable(self):
        raw = (
            b'{"cells":[{"cell_type":"code","source":["import cudf"],'
            b'"outputs":[{"text":["bad \xff \x02"]}]}],'
            b'"metadata":{"bad":"\xff"}}'
        )
        surfaces = parse_notebook_surfaces(raw)
        self.assertEqual("import cudf", surfaces.search_text)
        self.assertEqual("import cudf", surfaces.code_text)
        self.assertEqual(
            "output-metadata-only-json-recovery",
            surfaces.recovery,
        )

    def test_raw_json_controls_are_recoverable_only_when_ignored(self):
        ignored = (
            '{"cells":[{"cell_type":"code","source":["import cudf"],'
            '"outputs":[{"text":["raw\noutput"]}]}],'
            '"metadata":{"raw":"value\tcontinues"}}'
        )
        surfaces = parse_notebook_surfaces(ignored)
        self.assertEqual("import cudf", surfaces.code_text)
        self.assertEqual(
            "output-metadata-only-json-recovery",
            surfaces.recovery,
        )
        for damaged in (
            '{"cells":[{"cell_type":"code",'
            '"source":["import\ncudf"]}]}',
            '{"cells":[{"cell_type":"co\tde",'
            '"source":["import cudf"]}]}',
            '{"ce\nlls":[]}',
        ):
            with self.subTest(damaged=damaged):
                with self.assertRaisesRegex(
                    NotebookEvidenceError,
                    "^notebook is invalid JSON$",
                ):
                    parse_notebook_surfaces(damaged)
        for codepoint in range(32):
            control = chr(codepoint)
            with self.subTest(authored_control=codepoint):
                with self.assertRaisesRegex(
                    NotebookEvidenceError,
                    "^notebook is invalid JSON$",
                ):
                    parse_notebook_surfaces(
                        '{"cells":[{"cell_type":"code",'
                        '"source":["import'
                        + control
                        + 'cudf"]}]}'
                    )
            with self.subTest(ignored_control=codepoint):
                recovered = parse_notebook_surfaces(
                    '{"cells":[{"cell_type":"code",'
                    '"source":["import cudf"],'
                    '"outputs":[{"text":["raw'
                    + control
                    + 'output"]}]}]}'
                )
                self.assertEqual("import cudf", recovered.code_text)
        escaped = parse_notebook_surfaces(
            '{"cells":[{"cell_type":"code",'
            '"source":["import\\ncudf\\t# note\\r\\n"]}]}'
        )
        self.assertEqual(
            "import\ncudf\t# note\r\n",
            escaped.code_text,
        )

    def test_authored_decode_damage_and_arbitrary_json_fail_closed(self):
        with self.assertRaisesRegex(
            NotebookEvidenceError,
            "damage reaches authored",
        ):
            parse_notebook_surfaces(
                b'{"cells":[{"cell_type":"code",'
                b'"source":["import cu\xffdnn"]}]}'
            )
        with self.assertRaisesRegex(
            ValueError, "^notebook is invalid JSON$"
        ):
            _notebook_source_surfaces(b"{broken")
        with self.assertRaisesRegex(
            RuntimeError,
            "^tracked notebook is invalid JSON; scan is incomplete$",
        ):
            _notebook_surfaces(b"{broken")

    def test_escaped_ascii_in_authored_cells_survives_retention(self):
        cuquantum = _library("cuquantum")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            (root / "code.ipynb").write_text(
                r'{"cells":[{"cell_type":"code",'
                r'"source":"import \u0063uquantum"}]}'
            )
            (root / "markdown.ipynb").write_text(
                r'{"cells":[{"cell_type":"markdown",'
                r'"source":"uses \u0063uquantum"}]}'
            )
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "escaped notebook evidence")
            result = triage_tree(
                root,
                [cuquantum],
                required_library_ids=("cuquantum",),
            )
        self.assertIn(
            "code.ipynb", result.direct_files["cuquantum"]
        )
        self.assertTrue(
            _notebook_might_affect_verdict(
                (
                    r'{"cells":[{"cell_type":"markdown",'
                    r'"source":"uses \u0063uquantum"}]}'
                ).encode(),
                _notebook_retention_pattern({"cuquantum"}),
            )
        )


class LFSEvidenceContentTests(unittest.TestCase):
    def test_pointer_parser_requires_the_complete_v1_grammar(self):
        pointer = parse_lfs_pointer(_pointer())
        self.assertEqual("a" * 64, pointer.oid)
        self.assertEqual(123, pointer.size)
        extended = (
            "version https://git-lfs.github.com/spec/v1\n"
            "ext-0-example certificate\n"
            "oid sha256:" + "b" * 64 + "\n"
            "size 9"
        )
        self.assertIsNotNone(parse_lfs_pointer(extended))
        self.assertIsNotNone(
            parse_lfs_pointer(_pointer().replace("\n", "\r\n"))
        )
        malformed = (
            "prefix\n" + _pointer(),
            _pointer() + "unrecognized line\n",
            _pointer().replace("size 123\n", ""),
            _pointer().replace(
                "oid sha256:" + "a" * 64 + "\n",
                "",
            ),
            _pointer().replace(
                "size 123\n",
                "size 123\noid sha256:" + "b" * 64 + "\n",
            ),
            _pointer().replace("\n", "\r", 1),
        )
        for raw in malformed:
            with self.subTest(raw=raw[:50]):
                self.assertIsNone(parse_lfs_pointer(raw))

    def test_relevance_follows_each_detector_contract(self):
        libraries = [
            _library("cutensor"),
            _library("cudf"),
            _library("tensorrt"),
        ]
        self.assertTrue(
            lfs_evidence_path_relevant(
                "src/kernel.cu", ("cutensor",), libraries=libraries
            )
        )
        self.assertTrue(
            lfs_evidence_path_relevant(
                "CMakeLists.txt", ("cutensor",), libraries=libraries
            )
        )
        self.assertFalse(
            lfs_evidence_path_relevant(
                "src/model.py", ("cutensor",), libraries=libraries
            )
        )
        self.assertTrue(
            lfs_evidence_path_relevant(
                "src/model.py", ("cudf",), libraries=libraries
            )
        )
        self.assertFalse(
            lfs_evidence_path_relevant(
                "generated/kernel.cu",
                ("cutensor",),
                libraries=libraries,
            )
        )
        self.assertTrue(
            lfs_evidence_path_relevant(
                "src/reference.py", ("cupqc",)
            )
        )
        for path in (
            "requirements-dev.txt",
            "requirements-cuda.in",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "environment-lock.yml",
            "environment.cuda.yaml",
            "Pipfile",
            "docker/Dockerfile.cuda",
        ):
            with self.subTest(bundled_path=path):
                self.assertTrue(
                    lfs_evidence_path_relevant(
                        path, ("cudf",), libraries=libraries
                    )
                )
                if path not in {
                    "pyproject.toml", "setup.py", "setup.cfg"
                }:
                    self.assertFalse(
                        lfs_evidence_path_relevant(
                            path,
                            ("cutensor",),
                            libraries=libraries,
                        )
                    )
        for path in ("cmake/CUDA.cmake", "CMakeLists.txt"):
            with self.subTest(targeted_path=path):
                self.assertTrue(
                    lfs_evidence_path_relevant(
                        path, ("cutensor",), libraries=libraries
                    )
                )
        for path in (
            "tools/link.py",
            "pyproject.toml",
            "config/link.cfg",
            "scripts/link.sh",
            "build.rs",
            "Makefile",
            "meson.build",
            "BUILD",
        ):
            with self.subTest(nonclassifying_targeted_path=path):
                self.assertFalse(
                    lfs_evidence_path_relevant(
                        path, ("cutensor",), libraries=libraries
                    )
                )
        self.assertFalse(
            lfs_evidence_path_relevant(
                "Dockerfile.png", ("tensorrt",), libraries=libraries
            )
        )

    def test_timestamped_result_clone_root_is_exact_and_scoped(self):
        copied = (
            "bench/results/20260303_122226/clones/qiskit_aer/"
            "src/kernel.cu"
        )
        sibling = "bench/results/host.cu"
        roots = _embedded_project_roots((copied, sibling))
        self.assertIn(
            "bench/results/20260303_122226/clones/qiskit_aer",
            roots,
        )
        self.assertNotIn("bench/results", roots)
        self.assertEqual(
            (),
            _embedded_project_roots((
                "bench/results/latest/clones/qiskit_aer/src/kernel.cu",
                sibling,
            )),
        )

    def test_bare_pointer_fallback_is_required_only_when_relevant(self):
        cutensor = _library("cutensor")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            (root / "requirements.txt").write_text(_pointer())
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "irrelevant pointer")
            head, entries = _bare_entries(root)
            result = triage_tree(
                root,
                [cutensor],
                required_library_ids=("cutensor",),
                bare_git_dir=root / ".git",
                bare_head=head,
                bare_entries=entries,
            )
            self.assertEqual((), result.candidate_library_ids)
            self.assertIn("requirements.txt", result.lfs_pointers)

            (root / "kernel.cu").write_text(_pointer("b" * 64))
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "relevant pointer")
            head, entries = _bare_entries(root)
            with self.assertRaisesRegex(
                BareTriageRequiresWorktree,
                "detector-relevant Git LFS object requires a worktree",
            ):
                triage_tree(
                    root,
                    [cutensor],
                    required_library_ids=("cutensor",),
                    bare_git_dir=root / ".git",
                    bare_head=head,
                    bare_entries=entries,
                )

    def test_direct_only_targeted_lfs_matches_executable_cmake_surface(self):
        cutensor = _library("cutensor")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            (root / "build.rs").write_text(_pointer())
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "nonclassifying pointer")
            head, entries = _bare_entries(root)
            result = triage_tree(
                root,
                [cutensor],
                required_library_ids=("cutensor",),
                bare_git_dir=root / ".git",
                bare_head=head,
                bare_entries=entries,
            )
            self.assertEqual((), result.candidate_library_ids)

            (root / "CMakeLists.txt").write_text(_pointer("b" * 64))
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "classifying pointer")
            head, entries = _bare_entries(root)
            with self.assertRaisesRegex(
                BareTriageRequiresWorktree,
                "detector-relevant Git LFS object requires a worktree",
            ):
                triage_tree(
                    root,
                    [cutensor],
                    required_library_ids=("cutensor",),
                    bare_git_dir=root / ".git",
                    bare_head=head,
                    bare_entries=entries,
                )

    def test_inventory_consumes_a_hydrated_lfs_worktree_payload(self):
        cutensor = _library("cutensor")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _git(root, "init", "-q", "-b", "main")
            _git(root, "config", "user.name", "REQ14 Test")
            _git(root, "config", "user.email", "req14@example.invalid")
            path = root / "kernel.cu"
            path.write_text(_pointer())
            _git(root, "add", ".")
            _git(root, "commit", "-q", "-m", "pointer")
            path.write_text("#include <cutensor.h>\n")
            result = triage_tree(
                root,
                [cutensor],
                inventory_all=True,
                required_library_ids=("cutensor",),
            )
        self.assertEqual(("kernel.cu",), result.direct_files["cutensor"])
        self.assertEqual(("kernel.cu",), result.hydrated_lfs_paths)
        self.assertIn("kernel.cu", result.lfs_pointers)


if __name__ == "__main__":
    unittest.main()
