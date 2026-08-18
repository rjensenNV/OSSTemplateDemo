"""One-pass current-tree triage for the REQ-14 scanner.

This is deliberately a broad candidate stage. Existing mature detectors remain
the classification authority; triage narrows which detectors run and provides
exact own-source files for confirmed-only high-volume libraries.
"""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import io
import os
import re
import stat
import subprocess
import time
import tokenize
import warnings
from pathlib import Path

from . import scan as scan_module
from .config import (
    COPIED_PROJECT_PATH_RE,
    DOC_SKILL_PATH_RE,
    ENV_DUMP_PATH_RE,
    LIBRARIES as ALL_LIBRARIES,
    PY_SIGNALS,
    VENDOR_PATH_RE,
    WARP_API_ANCHORS,
)
from .evidence_content import (
    LFSPointer,
    NotebookEvidenceError,
    parse_lfs_pointer,
    parse_notebook_surfaces,
)
from .scan import (
    _python_import_modules,
    _run_command,
    _run_command_bytes,
)

# Ordinary files stay naturally bounded, while unusually large own-source
# files are still inspected for completeness.  Beyond the hard ceiling the
# task is explicitly incomplete and publication is refused; it is never
# silently converted into a clean reject.
MAX_SOURCE_BYTES = 1_000_000
MAX_OWN_SOURCE_BYTES = 128 * 1024 * 1024
GENERATED_PATH_RE = re.compile(
    # A directory literally named ``build`` is not sufficient evidence that a
    # committed source file is generated. Rust bindgen projects commonly keep
    # authored wrapper headers there (for example ``build/cublasXt_wrapper.h``).
    # The unambiguous generated/output roots remain excluded.
    r"(^|/)(generated|autogen|_generated|_build|dist|"
    r"cmake-build[^/]*)/",
    re.IGNORECASE,
)
TEXT_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".cu", ".cuh", ".h", ".hh",
    ".hpp", ".hxx", ".inc", ".inl", ".ipp", ".tpp", ".cinc",
    ".py", ".pyi", ".ipynb", ".cmake", ".toml", ".cfg",
    ".sh", ".rs", ".mk", ".bazel", ".bzl", ".txt",
}
C_SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".cu", ".cuh", ".h", ".hh",
    ".hpp", ".hxx", ".inc", ".inl", ".ipp", ".tpp", ".cinc",
}
C_HEADER_EXTENSIONS = {
    ".h", ".hh", ".hpp", ".hxx", ".cuh", ".inc", ".inl", ".ipp",
    ".tpp", ".cinc",
}
PYTHON_SOURCE_EXTENSIONS = {".py", ".pyi", ".ipynb"}
SPECIAL_NAMES = {
    "CMakeLists.txt", "Makefile", "Dockerfile", "pyproject.toml",
    "requirements.txt", "environment.yml", "setup.py", "setup.cfg",
    "meson.build", "BUILD", "Pipfile",
}
_SPECIAL_NAMES_FOLDED = frozenset(
    name.casefold() for name in SPECIAL_NAMES
)
PROJECT_MANIFESTS = {"setup.py", "setup.cfg", "pyproject.toml"}
_INVENTORY_BATCH_BYTES = 32 * 1024 * 1024
_INVENTORY_BATCH_OBJECTS = 10_000


@dataclasses.dataclass(frozen=True)
class TriageResult:
    candidate_library_ids: tuple[str, ...]
    direct_files: dict[str, tuple[str, ...]]
    signal_files: dict[str, tuple[str, ...]]
    citation_cff: tuple[str, ...]
    # Raw current-tree text is retained only for the lifetime of one worker
    # task. Mature classifiers query this in-memory index instead of launching
    # dozens of per-library ``git grep`` processes or reopening blobs.
    current_text: dict[str, str]
    files_examined: int
    bytes_examined: int
    skipped_large: int
    # Exact pointer certificates are retained as an audit/fallback sidecar.
    # Their serialized pointer text never enters the detector surface.
    lfs_pointers: dict[str, LFSPointer] = dataclasses.field(
        default_factory=dict
    )
    hydrated_lfs_paths: tuple[str, ...] = ()


class _TextInventory(dict):
    """Path-complete text map with per-object analysis sidecars.

    Paths whose blobs cannot match any configured detector remain present with
    an empty value. This preserves path-based shadow/vendor/CFF semantics while
    avoiding retention and repeated parsing of multi-gigabyte irrelevant
    content.
    """

    def __init__(self):
        super().__init__()
        self.size_by_path = {}
        self.analyzed_bytes_by_path = {}
        self.token_ids_by_path = {}
        self.notebook_code_by_path = {}
        self.lfs_pointer_paths = set()
        self.lfs_pointers_by_path = {}
        self.hydrated_lfs_paths = set()
        self.raw_bytes_by_path = {}


def _is_git_lfs_pointer(content):
    return parse_lfs_pointer(content) is not None


def _is_generated_evidence_path(path):
    """Return whether a tracked path is unambiguous generated output."""
    normalized = str(path).replace("\\", "/").strip("/").casefold()
    return bool(
        GENERATED_PATH_RE.search(normalized)
        or any(part in {"cubin", "cubins"} for part in normalized.split("/"))
    )


def _is_binary_media_path(path):
    return Path(os.path.basename(str(path))).suffix.casefold() in {
        ".apng", ".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg",
        ".pdf", ".png", ".tif", ".tiff", ".webp",
    }


def lfs_evidence_path_relevant(
    path,
    library_ids,
    libraries=ALL_LIBRARIES,
):
    """Return whether a missing LFS object can affect requested detectors.

    This is deliberately detector-shaped rather than extension-only. Mature
    libraries retain their broad targeted/reference surface, while REQ-14
    direct-only libraries require only the source/build surfaces that can
    produce a class they actually evaluate.
    """
    normalized = str(path).replace("\\", "/").strip("/")
    if not _eligible(normalized):
        return False
    requested = {
        str(library_id)
        for library_id in (library_ids or ())
    }
    if not requested:
        return False
    if isinstance(libraries, dict):
        by_id = libraries
    else:
        by_id = {
            library["id"]: library
            for library in libraries
            if isinstance(library, dict) and library.get("id")
        }
    selected = [
        by_id[library_id]
        for library_id in requested
        if library_id in by_id
    ]
    if not selected:
        return False
    if any(not library.get("direct_only") for library in selected):
        return True

    suffix = Path(normalized).suffix.casefold()
    basename = os.path.basename(normalized).casefold()
    is_dependency_manifest = (
        (
            basename.startswith("requirements")
            and suffix in {".txt", ".in"}
        )
        or basename in {
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "pipfile",
        }
        or (
            basename.startswith("environment")
            and suffix in {".yml", ".yaml"}
        )
        or basename.startswith("dockerfile")
    )
    is_c_source = suffix in C_SOURCE_EXTENSIONS
    is_python_source = suffix in PYTHON_SOURCE_EXTENSIONS
    is_targeted_surface = (
        suffix == ".cmake"
        or basename == "cmakelists.txt"
    )
    for library in selected:
        has_cpp_detector = bool(
            library.get("header")
            or library.get("cpp_headers")
            or library.get("header_prefix")
            or library.get("header_prefixes")
        )
        has_python_detector = bool(
            library.get("import_namespace")
            or library.get("import_namespaces")
            or library.get("direct_regexes")
            or PY_SIGNALS.get(library["id"])
        )
        if is_c_source and has_cpp_detector:
            return True
        if is_python_source and has_python_detector:
            return True
        coverage = set(library.get("classification_coverage", ()))
        if (
            is_dependency_manifest
            and "bundled" in coverage
            and library.get("pip_pattern")
        ):
            return True
        if (
            is_targeted_surface
            and "targeted" in coverage
            and library.get("targeted_build_signals")
        ):
            return True
    return False


class BareTriageRequiresWorktree(RuntimeError):
    """A tracked checkout transformation cannot be reproduced safely bare."""


class _PersistentCatFile:
    """One bounded, cleanup-aware object reader for a whole tree.

    Filtered reads use Git's NUL-delimited batch protocol so paths containing
    whitespace or newlines remain unambiguous.  A single process applies every
    standard checkout transform; spawning ``cat-file --filters`` once per path
    turns large copied trees into thousands of serial subprocesses.
    """

    def __init__(
        self,
        git_dir,
        *,
        deadline_monotonic=None,
        filters=False,
        head_sha=None,
    ):
        self.deadline_monotonic = deadline_monotonic
        self.filters = bool(filters)
        self.command = [
            "git",
            "--git-dir",
            str(git_dir),
            "-c",
            "core.commitGraph=false",
            "-c",
            "maintenance.auto=false",
            "cat-file",
            "--batch",
        ]
        if self.filters:
            if not head_sha:
                raise ValueError("filtered batch reader requires a HEAD")
            # Filtered output can differ in size from the raw blob size printed
            # in Git's batch header (for example LF -> CRLF). ``-Z`` gives both
            # input and output an unambiguous NUL delimiter.
            self.command.extend(["--filters", "-Z"])
        environment = os.environ.copy()
        environment["GIT_NO_LAZY_FETCH"] = "1"
        if self.filters:
            environment["GIT_ATTR_SOURCE"] = str(head_sha)
        scan_module._record_git_subprocess(self.command)
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=environment,
        )
        scan_module._register_process_group(self.process)

    def _remaining(self, maximum=30):
        if self.deadline_monotonic is None:
            return maximum
        remaining = self.deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                "repository wall deadline exhausted during bare triage"
            )
        return max(0.1, min(float(maximum), remaining))

    def _read_exact(self, length):
        chunks = []
        remaining = int(length)
        while remaining:
            chunk = self.process.stdout.read(remaining)
            if not chunk:
                raise RuntimeError("truncated bare current-tree blob")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_until(self, terminator):
        chunks = []
        while True:
            chunk = self.process.stdout.read(1)
            if not chunk:
                raise RuntimeError("truncated bare current-tree batch response")
            if chunk == terminator:
                return b"".join(chunks)
            chunks.append(chunk)

    def read(self, object_id, *, path=None):
        self._remaining()
        request = object_id.encode("ascii")
        request_terminator = b"\n"
        if self.filters:
            if path is None:
                raise ValueError("filtered batch read requires a path")
            encoded_path = os.fsencode(path)
            if b"\0" in encoded_path:
                raise RuntimeError("tracked path contains a NUL byte")
            request += b" " + encoded_path
            request_terminator = b"\0"
        self.process.stdin.write(request + request_terminator)
        self.process.stdin.flush()
        header = (
            self._read_until(b"\0")
            if self.filters
            else self.process.stdout.readline().rstrip(b"\n")
        )
        if not header:
            returncode = self.process.poll()
            if returncode is None:
                try:
                    returncode = self.process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
            detail = ""
            if returncode is not None:
                detail = self.process.stderr.read().decode(
                    "utf-8", errors="replace"
                )[:300]
            raise RuntimeError(
                "missing bare current-tree batch header"
                + (
                    " (git exit %s: %s)" % (returncode, detail)
                    if returncode is not None
                    else ""
                )
            )
        fields = header.split()
        if (
            len(fields) != 3
            or fields[0].decode("ascii", errors="replace") != object_id
            or fields[1] != b"blob"
        ):
            raise RuntimeError(
                "current-tree object is unavailable after hydration"
            )
        size = int(fields[2])
        if self.filters:
            # Standard ident/EOL transforms cannot introduce NUL bytes. The
            # caller verifies the raw blob is textual before requesting this
            # filtered form; custom filters and encodings use the worktree
            # fallback instead.
            return self._read_until(b"\0")
        payload = self._read_exact(size)
        if self._read_exact(1) != b"\n":
            raise RuntimeError("invalid bare current-tree batch terminator")
        return payload

    def close(self, exc=None):
        try:
            if exc is not None:
                scan_module._terminate_process_group(self.process)
                return
            self.process.stdin.close()
            self.process.stdin = None
            try:
                _stdout, stderr = self.process.communicate(
                    timeout=self._remaining()
                )
            except subprocess.TimeoutExpired as timeout:
                scan_module._terminate_process_group(self.process)
                raise RuntimeError(
                    "git cat-file timed out during bare triage"
                ) from timeout
            if self.process.returncode:
                raise RuntimeError(
                    "git cat-file failed during bare triage: %s"
                    % stderr.decode("utf-8", errors="replace")[:300]
                )
        finally:
            scan_module._clear_process_group(self.process)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close(value)


def _bare_attribute_rows(git_dir, head_sha, paths):
    if not paths:
        return {}
    environment = os.environ.copy()
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_ATTR_SOURCE"] = str(head_sha)
    payload = b"".join(
        os.fsencode(path) + b"\0" for path in paths
    )
    result = _run_command_bytes(
        [
            "git",
            "--git-dir",
            str(git_dir),
            "check-attr",
            "--source",
            str(head_sha),
            "--stdin",
            "-z",
            "filter",
            "working-tree-encoding",
            "ident",
            "text",
            "eol",
        ],
        120,
        input_bytes=payload,
        env=environment,
    )
    if result.returncode:
        raise RuntimeError(
            "git check-attr failed during bare triage: %s"
            % result.stderr.decode("utf-8", errors="replace")[:300]
        )
    fields = result.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 3:
        raise RuntimeError("malformed bare current-tree attributes")
    rows = {}
    for offset in range(0, len(fields), 3):
        path = os.fsdecode(fields[offset])
        attribute = fields[offset + 1].decode(
            "utf-8", errors="replace"
        )
        value = fields[offset + 2].decode("utf-8", errors="replace")
        rows.setdefault(path, {})[attribute] = value
    return rows


def _bare_config_value(git_dir, key):
    result = _run_command(
        ["git", "--git-dir", str(git_dir), "config", "--get", key],
        30,
    )
    if result.returncode == 1:
        return None
    if result.returncode:
        raise RuntimeError(
            "git config failed during bare triage: %s"
            % result.stderr[:300]
        )
    return result.stdout.strip().casefold()


def _supports_batch_nul_output(git_dir):
    """Return whether Git supports unambiguous ``cat-file -Z`` output."""
    result = _run_command(
        ["git", "--git-dir", str(git_dir), "cat-file", "-h"],
        30,
    )
    help_text = (result.stdout or "") + "\n" + (result.stderr or "")
    return re.search(r"(^|\s)-Z(?:\s|$)", help_text) is not None


def _bare_tracked_text_inventory(
    git_dir,
    head_sha,
    entries,
    *,
    deadline_monotonic=None,
    embedded_project_roots=(),
    required_library_ids=(),
    libraries=ALL_LIBRARIES,
):
    """Read the direct-triage surface from one resolved bare commit."""
    regular = [
        (object_id, path)
        for mode, object_type, object_id, path in entries
        if (
            mode.startswith("100")
            and object_type == "blob"
            and _eligible(path)
        )
    ]
    scanned_regular = [
        (object_id, path)
        for object_id, path in regular
        if not _inside_embedded_project(path, embedded_project_roots)
    ]
    paths = [path for _object_id, path in scanned_regular]
    attributes = _bare_attribute_rows(git_dir, head_sha, paths)
    for path, row in attributes.items():
        if row.get("filter") not in {
            None, "unspecified", "unset", "lfs"
        }:
            raise BareTriageRequiresWorktree(
                "custom checkout filter requires a worktree: %s" % path
            )
        if row.get("working-tree-encoding") not in {
            None, "unspecified", "unset"
        }:
            raise BareTriageRequiresWorktree(
                "working-tree encoding requires a worktree: %s" % path
            )

    autocrlf = (
        _bare_config_value(git_dir, "core.autocrlf") if paths else None
    )
    core_eol = _bare_config_value(git_dir, "core.eol") if paths else None
    by_object = {}
    for object_id, path in scanned_regular:
        by_object.setdefault(object_id, []).append(path)

    texts = _TextInventory()
    # Copied project roots cannot establish host adoption.  Keep their paths
    # represented for shadow/CFF logic, but do not read, transform, or parse
    # their content.  In particular, a malformed notebook in a copied fixture
    # cannot make an otherwise complete host scan fail.
    for _object_id, path in regular:
        if _inside_embedded_project(path, embedded_project_roots):
            texts.size_by_path[path] = 0

    transform_by_path = {}
    for _object_id, path in scanned_regular:
        row = attributes.get(path, {})
        text_attr = row.get("text")
        eol_attr = row.get("eol")
        transform_by_path[path] = (
            row.get("ident") == "set"
            or eol_attr not in {None, "unspecified", "unset"}
            or (
                autocrlf == "true"
                and text_attr != "unset"
            )
            or (
                core_eol == "crlf"
                and text_attr in {"set", "auto"}
            )
        )
    filtered_needed = any(transform_by_path.values())
    if filtered_needed and not _supports_batch_nul_output(git_dir):
        # Older Git has NUL-delimited input only. Its LF-delimited filtered
        # output is ambiguous because the checkout transform can change the
        # payload size. Preserve exact semantics via the existing worktree
        # fallback instead of guessing a boundary.
        raise BareTriageRequiresWorktree(
            "Git lacks unambiguous filtered batch output"
        )
    with contextlib.ExitStack() as stack:
        raw_reader = (
            stack.enter_context(
                _PersistentCatFile(
                    git_dir, deadline_monotonic=deadline_monotonic
                )
            )
            if by_object else None
        )
        filtered_reader = (
            stack.enter_context(
                _PersistentCatFile(
                    git_dir,
                    deadline_monotonic=deadline_monotonic,
                    filters=True,
                    head_sha=head_sha,
                )
            )
            if filtered_needed else None
        )
        for object_id in sorted(by_object):
            raw_content = raw_reader.read(object_id)
            # Match ``git grep -I`` and do not feed binary data into the
            # delimiter-based filtered stream.
            if b"\0" in raw_content[:8192]:
                for path in by_object[object_id]:
                    texts.size_by_path[path] = len(raw_content)
                continue
            for path in by_object[object_id]:
                content = (
                    filtered_reader.read(object_id, path=path)
                    if transform_by_path[path]
                    else raw_content
                )
                texts.size_by_path[path] = len(content)
                own_source = (
                    _own_source(path)
                    and not _inside_embedded_project(
                        path, embedded_project_roots
                    )
                )
                if len(content) > MAX_OWN_SOURCE_BYTES and own_source:
                    continue
                if len(content) > MAX_SOURCE_BYTES and not own_source:
                    continue
                if b"\0" in content[:8192]:
                    continue
                texts.size_by_path[path] = len(content)
                texts.raw_bytes_by_path[path] = content
                pointer = parse_lfs_pointer(content)
                if pointer is not None:
                    texts.lfs_pointer_paths.add(path)
                    texts.lfs_pointers_by_path[path] = pointer
                    texts[path] = ""
                    texts.analyzed_bytes_by_path[path] = 0
                    texts.token_ids_by_path[path] = frozenset()
                    if lfs_evidence_path_relevant(
                        path,
                        required_library_ids,
                        libraries=libraries,
                    ):
                        raise BareTriageRequiresWorktree(
                            "detector-relevant Git LFS object requires a "
                            "worktree: %s" % path
                        )
                    continue
                texts[path] = content.decode("utf-8", errors="ignore")
                texts.analyzed_bytes_by_path[path] = len(
                    texts[path].encode("utf-8", errors="ignore")
                )
    return texts


def _tracked_files(checkout):
    result = _run_command(
        ["git", "-C", str(checkout), "-c", "core.quotePath=false",
         "ls-files", "-z"],
        120,
    )
    if result.returncode:
        raise RuntimeError(
            "git ls-files failed: %s" % result.stderr[:300]
        )
    return [
        item
        for item in result.stdout.split("\0") if item
    ]


def _tracked_text_inventory(
    checkout,
    existing_text=None,
    *,
    token_ids=None,
    token_re=None,
    retention_token_re=None,
    notebook_retention_re=None,
    full_name=None,
):
    """Read each eligible current-tree blob once through one batch process."""
    if existing_text is None:
        existing_text = {}
    existing_raw_by_path = getattr(
        existing_text, "raw_bytes_by_path", {}
    )
    existing_size_by_path = getattr(
        existing_text, "size_by_path", {}
    )
    listing = _run_command_bytes(
        [
            "git", "-C", str(checkout), "-c", "core.quotePath=false",
            "ls-files", "--stage", "-z",
        ],
        120,
    )
    if listing.returncode:
        raise RuntimeError(
            "git ls-files --stage failed: %s"
            % listing.stderr.decode("utf-8", errors="replace")[:300]
        )
    oid_paths = {}
    for record in listing.stdout.split(b"\0"):
        if not record or b"\t" not in record:
            continue
        metadata, encoded_path = record.split(b"\t", 1)
        fields = metadata.split()
        if len(fields) < 3 or not fields[0].startswith(b"100"):
            continue
        oid = fields[1].decode("ascii", errors="strict")
        path = encoded_path.decode("utf-8", errors="replace")
        oid_paths.setdefault(oid, []).append(path)

    if not oid_paths:
        return _TextInventory(), 0
    inventory_embedded_roots = _embedded_project_roots(
        (
            path
            for paths in oid_paths.values()
            for path in paths
        ),
        full_name=full_name,
    )
    ordered_oids = sorted(oid_paths)
    # Hydration and explicit pruning are the sole network boundary. Inventory
    # must consume only the resulting local object set; otherwise one missed
    # sparse/promised path can turn cat-file into an invisible serial fetch.
    object_env = os.environ.copy()
    object_env["GIT_NO_LAZY_FETCH"] = "1"
    sizes = {}
    for offset in range(0, len(ordered_oids), _INVENTORY_BATCH_OBJECTS):
        check_batch = ordered_oids[
            offset : offset + _INVENTORY_BATCH_OBJECTS
        ]
        request = (
            "".join(oid + "\n" for oid in check_batch)
        ).encode("ascii")
        checked = _run_command_bytes(
            [
                "git", "-C", str(checkout), "cat-file",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            ],
            120,
            input_bytes=request,
            env=object_env,
        )
        if checked.returncode:
            raise RuntimeError(
                "git cat-file --batch-check failed at object %d: %s"
                % (
                    offset,
                    checked.stderr.decode(
                        "utf-8", errors="replace"
                    )[:300],
                )
            )
        lines = checked.stdout.decode(
            "ascii", errors="replace"
        ).splitlines()
        if len(lines) != len(check_batch):
            raise RuntimeError(
                "current-tree object size response is incomplete"
            )
        for requested_oid, line in zip(check_batch, lines):
            fields = line.split()
            if (
                len(fields) != 3
                or fields[0] != requested_oid
                or fields[1] != "blob"
            ):
                raise RuntimeError(
                    "current-tree object is unavailable after hydration"
                )
            sizes[fields[0]] = int(fields[2])

    allowed_oids = []
    reused_by_oid = {}
    excluded_paths = []
    skipped_large = 0
    for oid in ordered_oids:
        size = sizes.get(oid)
        if size is None:
            raise RuntimeError("current-tree object size is unavailable")
        allowed_paths = []
        for path in oid_paths[oid]:
            if (
                _is_generated_evidence_path(path)
                or _is_binary_media_path(path)
                or _inside_embedded_project(
                    path, inventory_embedded_roots
                )
            ):
                excluded_paths.append(path)
                continue
            own_source = _eligible(path) and _own_source(path)
            if size > MAX_OWN_SOURCE_BYTES and own_source:
                skipped_large += 1
                continue
            if size > MAX_SOURCE_BYTES and not own_source:
                continue
            allowed_paths.append(path)
        if allowed_paths:
            oid_paths[oid] = allowed_paths
            reused_path = next(
                (path for path in allowed_paths if path in existing_text),
                None,
            )
            if reused_path is None:
                reused = None
            else:
                reused = existing_raw_by_path.get(reused_path)
                if reused is None:
                    reused = existing_text[reused_path].encode(
                        "utf-8", errors="ignore"
                    )
            if reused is None:
                allowed_oids.append(oid)
            else:
                reused_by_oid[oid] = (
                    reused,
                    existing_size_by_path.get(
                        reused_path, len(reused)
                    ),
                )

    texts = _TextInventory()
    for path in excluded_paths:
        # Retain path identity for local-shadow / embedded-project policy, but
        # never hydrate or search a path outside the evidence surface.
        texts[path] = ""
        texts.size_by_path[path] = 0
        texts.analyzed_bytes_by_path[path] = 0
        texts.token_ids_by_path[path] = frozenset()

    def retain(
        oid,
        text,
        *,
        selected_paths=None,
        content_size=None,
        allow_worktree_hydration=True,
    ):
        nonlocal skipped_large
        if b"\0" in text[:8192]:
            return
        paths = (
            tuple(selected_paths)
            if selected_paths is not None
            else tuple(oid_paths[oid])
        )
        evidence_size = (
            len(text) if content_size is None else int(content_size)
        )
        decoded = text.decode("utf-8", errors="ignore")
        lfs_pointer = parse_lfs_pointer(text)

        def match_ids(value):
            matched = set()
            if token_re is not None:
                for match in token_re.finditer(value.lower()):
                    matched.update(
                        token_ids.get(match.group(0), ())
                    )
            return frozenset(matched)

        decoded_bytes = len(
            decoded.encode("utf-8", errors="ignore")
        )
        raw_matched_ids = match_ids(decoded)
        if lfs_pointer is not None:
            for path in paths:
                hydrated = None
                hydrated_size = None
                if allow_worktree_hydration:
                    worktree_path = Path(checkout) / path
                    try:
                        metadata = worktree_path.lstat()
                    except OSError:
                        metadata = None
                    if metadata is not None and stat.S_ISREG(
                        metadata.st_mode
                    ):
                        hydrated_size = metadata.st_size
                        own_source = (
                            _eligible(path) and _own_source(path)
                        )
                        if (
                            hydrated_size > MAX_OWN_SOURCE_BYTES
                            and own_source
                        ):
                            skipped_large += 1
                            continue
                        if (
                            hydrated_size > MAX_SOURCE_BYTES
                            and not own_source
                        ):
                            continue
                        try:
                            candidate = worktree_path.read_bytes()
                        except OSError:
                            candidate = None
                        if (
                            candidate is not None
                            and parse_lfs_pointer(candidate) is None
                        ):
                            hydrated = candidate
                if hydrated is not None:
                    texts.lfs_pointers_by_path[path] = lfs_pointer
                    texts.hydrated_lfs_paths.add(path)
                    retain(
                        oid,
                        hydrated,
                        selected_paths=(path,),
                        content_size=hydrated_size,
                        allow_worktree_hydration=False,
                    )
                    continue
                texts[path] = ""
                texts.size_by_path[path] = evidence_size
                texts.analyzed_bytes_by_path[path] = 0
                texts.token_ids_by_path[path] = frozenset()
                texts.lfs_pointer_paths.add(path)
                texts.lfs_pointers_by_path[path] = lfs_pointer
                texts.raw_bytes_by_path[path] = text
            return
        raw_retained = (
            retention_token_re is None
            or retention_token_re.search(decoded.lower()) is not None
            # CFF publication is a separate consumer of this inventory. Its
            # body must survive even when it names no configured library.
            or any(
                os.path.basename(path).lower() == "citation.cff"
                for path in paths
            )
        )
        notebook_search = notebook_code = None
        notebook_retained = False
        notebook_bytes = None
        if any(path.endswith(".ipynb") for path in paths):
            notebook_relevant = (
                notebook_retention_re is None
                or _notebook_might_affect_verdict(
                    text, notebook_retention_re
                )
            )
            if not notebook_relevant:
                # No detector literal occurs anywhere in the serialized
                # notebook, so neither code nor markdown can contribute
                # evidence. Avoid parsing irrelevant (occasionally malformed)
                # notebooks while retaining fail-closed behavior for every
                # notebook that could affect a verdict.
                notebook_search = notebook_code = ""
                notebook_matched_ids = frozenset()
                notebook_bytes = 0
            else:
                try:
                    notebook_search, notebook_code = _notebook_surfaces(
                        text
                    )
                except RuntimeError as exc:
                    notebook_paths = [
                        path for path in paths if path.endswith(".ipynb")
                    ]
                    raise RuntimeError(
                        "%s: %s"
                        % (exc, ", ".join(notebook_paths[:3]))
                    ) from exc
                # Candidate/targeted evidence includes authored markdown;
                # direct confirmation below remains code-only.
                notebook_matched_ids = match_ids(notebook_search)
                notebook_retained = (
                    retention_token_re is None
                    or retention_token_re.search(
                        notebook_search.lower()
                    ) is not None
                )
                notebook_bytes = min(
                    evidence_size,
                    len(
                        notebook_search.encode(
                            "utf-8", errors="ignore"
                        )
                    ),
                )
        for path in paths:
            searchable = (
                notebook_search
                if path.endswith(".ipynb")
                else decoded
            )
            keep_text = (
                notebook_retained
                if path.endswith(".ipynb")
                else raw_retained
            )
            texts[path] = searchable if keep_text else ""
            texts.size_by_path[path] = evidence_size
            texts.analyzed_bytes_by_path[path] = (
                notebook_bytes
                if path.endswith(".ipynb")
                else min(evidence_size, decoded_bytes)
            )
            texts.token_ids_by_path[path] = (
                notebook_matched_ids
                if path.endswith(".ipynb")
                else raw_matched_ids
            )
            if keep_text and path.endswith(".ipynb"):
                texts.notebook_code_by_path[path] = notebook_code
            if path.endswith(".ipynb"):
                texts.raw_bytes_by_path[path] = text

    for oid, (text, content_size) in reused_by_oid.items():
        retain(oid, text, content_size=content_size)

    # `subprocess.communicate()` buffers stdout, so requesting a very large
    # website tree in one `cat-file --batch` call temporarily held three full
    # copies (batch bytes, per-object slices, decoded text). Chapel's 579 MB
    # textual tree peaked around 3 GB. Bounded batches preserve the exact same
    # blob inventory while limiting transient memory to one chunk.
    batches = []
    batch = []
    batch_bytes = 0
    for oid in allowed_oids:
        size = sizes[oid]
        if batch and (
            batch_bytes + size > _INVENTORY_BATCH_BYTES
            or len(batch) >= _INVENTORY_BATCH_OBJECTS
        ):
            batches.append(batch)
            batch = []
            batch_bytes = 0
        batch.append(oid)
        batch_bytes += size
    if batch:
        batches.append(batch)

    for batch in batches:
        content_request = (
            "".join(oid + "\n" for oid in batch)
        ).encode("ascii")
        objects = _run_command_bytes(
            ["git", "-C", str(checkout), "cat-file", "--batch"],
            120,
            input_bytes=content_request,
            env=object_env,
        )
        if objects.returncode:
            raise RuntimeError(
                "git cat-file --batch failed: %s"
                % objects.stderr.decode(
                    "utf-8", errors="replace"
                )[:300]
            )
        cursor = 0
        payload = objects.stdout
        for requested_oid in batch:
            newline = payload.find(b"\n", cursor)
            if newline < 0:
                raise RuntimeError("truncated current-tree batch header")
            header = payload[cursor:newline].split()
            cursor = newline + 1
            if (
                len(header) != 3
                or header[0].decode(
                    "ascii", errors="replace"
                ) != requested_oid
                or header[1] != b"blob"
            ):
                raise RuntimeError("invalid current-tree batch response")
            size = int(header[2])
            end = cursor + size
            if end >= len(payload) or payload[end:end + 1] != b"\n":
                raise RuntimeError("truncated current-tree blob")
            encoded = payload[cursor:end]
            cursor = end + 1
            retain(requested_oid, encoded)
    return texts, skipped_large


def _eligible(path):
    if ENV_DUMP_PATH_RE.search(path):
        return False
    if _is_generated_evidence_path(path):
        return False
    name = os.path.basename(path)
    lowered = name.casefold()
    if _is_binary_media_path(path):
        # Dockerfile screenshots and other binary/prose assets must not become
        # executable manifests merely because their basename starts with
        # ``Dockerfile``.
        return False
    authored_manifest = (
        lowered in _SPECIAL_NAMES_FOLDED
        or (
            lowered.startswith("requirements")
            and Path(lowered).suffix in {".txt", ".in"}
        )
        or (
            lowered.startswith("environment")
            and Path(lowered).suffix in {".yml", ".yaml"}
        )
        or lowered.startswith("dockerfile")
    )
    if authored_manifest:
        # DOC_SKILL_PATH_RE treats every .txt as prose. Dependency/build
        # manifests are executable project configuration, except when copied
        # into an agent-skill tree.
        return not re.search(
            r"(^|/)(\.claude|\.codex|\.agent|\.agents|"
            r"skills?|skillhub)/",
            str(path),
            re.IGNORECASE,
        )
    if DOC_SKILL_PATH_RE.search(path):
        return False
    return (
        name.lower() == "citation.cff"
        or Path(name).suffix.lower() in TEXT_EXTENSIONS
    )


def _own_source(path):
    return (
        not VENDOR_PATH_RE.search(path)
        and not COPIED_PROJECT_PATH_RE.search(path)
        and not ENV_DUMP_PATH_RE.search(path)
        and not _is_generated_evidence_path(path)
    )


def _library_definition_path(path, library):
    """Reject SDK header trees that include themselves inside a host repo."""
    lowered = str(path).strip("/").lower()
    for raw_prefix in library.get("header_prefixes", ()):
        prefix = str(raw_prefix).strip("/").lower()
        if not prefix:
            continue
        if (
            lowered.startswith(prefix + "/include/")
            or lowered.startswith("include/" + prefix + "/")
            or ("/" + prefix + "/include/") in ("/" + lowered)
        ):
            return True
    return False


_COPY_CONTAINER_PARTS = frozenset({
    "deployment", "deployments", "fixture", "fixtures", "corpus",
    "corpora", "testdata", "test-data",
})
_CANONICAL_CMAKE_REPOS = frozenset({"kitware/cmake"})
_CANONICAL_PYTORCH_REPOS = frozenset({
    "pytorch/pytorch", "msft-mirror-aosp/platform.external.pytorch",
})
_COPIED_REPOSITORY_UNITS = frozenset({
    # Explicitly identifies itself as a continuously-following upstream fork;
    # the tracked LAMMPS/KOKKOS code is not an independent integration.
    "cz007297/mliap-fork-follows-main",
    # A hardware-free, locally modified NCCL source distribution. Its test
    # programs exercise the copied NCCL implementation; they are not an
    # independent consumer integrating NCCL.
    "paperg/nccl_gp",
})


def _embedded_project_roots(tracked_files, full_name=None):
    """Return copied-project roots that cannot prove host adoption.

    A nested Python manifest is not, by itself, ownership evidence: ordinary
    monorepos, ROS workspaces and in-repository CUDA extensions all package
    first-party subprojects.  We exclude manifest roots only inside explicit
    deployment/fixture/corpus containers, plus a small set of unmistakable
    non-Python upstream tree signatures.
    """
    tracked_files = tuple(
        str(path).strip("/").replace("\\", "/")
        for path in tracked_files
    )
    tracked_set = {path.casefold() for path in tracked_files}
    roots = set()
    for path in tracked_files:
        normalized = path
        path_parts = normalized.split("/")
        folded_parts = [part.casefold() for part in path_parts]
        for index, part in enumerate(folded_parts[:-4]):
            if (
                part == "results"
                and re.fullmatch(
                    r"[0-9]{8}_[0-9]{6}",
                    folded_parts[index + 1],
                )
                and folded_parts[index + 2] == "clones"
                and folded_parts[index + 3]
            ):
                # Generated scanner/evaluation artifacts sometimes commit a
                # complete checkout below this exact timestamped layout.
                # Scope the exclusion to the copied project, preserving any
                # first-party source elsewhere under ``results``.
                roots.add("/".join(path_parts[:index + 4]))
        for index, part in enumerate(folded_parts[:-2]):
            if (
                part in _COPY_CONTAINER_PARTS
                and folded_parts[index + 2] == "source"
            ):
                # Corpus layouts such as
                # ``psi4/deployment/psi4/source/...`` contain a complete
                # upstream checkout even when that project has no Python
                # package manifest. The explicit container/project/source
                # shape is ownership evidence for the copy, not for the host.
                roots.add("/".join(path_parts[:index + 3]))
        if os.path.basename(normalized).lower() not in PROJECT_MANIFESTS:
            continue
        directory = os.path.dirname(normalized)
        parts = {part.casefold() for part in directory.split("/") if part}
        if parts.intersection(_COPY_CONTAINER_PARTS):
            roots.add(directory)

    repository = (full_name or "").casefold()
    if repository == "sammydev395/yahboomcar_ros2_ws_software":
        # Hand-verified 2026-07-30: this repository is a distribution bundle
        # of wholesale ORB-SLAM2, OpenCV, dlib, g2o, YDLidar-SDK, and other
        # upstream trees. Their CUDA-X use is not host-authored adoption.
        roots.add("")
    if repository in _COPIED_REPOSITORY_UNITS:
        roots.add("")
    if (
        {"source/cmakeversion.cmake", "modules/cmakecudainformation.cmake"}
        <= tracked_set
        and repository
        and repository not in _CANONICAL_CMAKE_REPOS
    ):
        roots.add("")
    copied_pytorch = (
        {
            "aten/src/aten/aten.h",
            "torch/cmakelists.txt",
            "caffe2/cmakelists.txt",
        }
        <= tracked_set
        and repository
        and repository not in _CANONICAL_PYTORCH_REPOS
    )
    if copied_pytorch:
        roots.update({
            "aten", "c10", "caffe2", "torch", "cmake", "tools",
            "CMakeLists.txt", "build_variables.bzl",
        })
        # Some wholesale PyTorch derivatives mechanically rename the top-level
        # ``torch`` Python package. Recognize the copied symmetric-memory /
        # extension surface by several independent, highly specific paths
        # instead of treating an arbitrary host package as vendored.
        for path in tracked_set:
            suffix = (
                "/distributed/_symmetric_memory/_nvshmem_triton.py"
            )
            if not path.endswith(suffix):
                continue
            package = path.split("/", 1)[0]
            if {
                package + "/_c/_distributed_c10d.pyi",
                package + "/utils/cpp_extension.py",
            } <= tracked_set:
                roots.add(package)
    if (
        {
            "src/bootstrap.cc",
            "src/channel.cc",
            "src/collectives/all_reduce.cc",
            "src/include/core.h",
        }
        <= tracked_set
        and repository
        and repository != "nvidia/nccl"
    ):
        roots.add("src")
    # A few adopters copy the complete nvCOMP source distribution below an
    # otherwise generic directory such as ``misc/``.  Header self-shadowing
    # rejects the copied public headers themselves, but examples and
    # benchmarks elsewhere in that copied tree also include those headers and
    # must not be counted as an independent direct integration.  Require the
    # upstream layout signature so an ordinary host ``include/nvcomp.h`` does
    # not turn an enclosing first-party project into vendor code.
    for path in tracked_set:
        suffix = "/include/nvcomp.h"
        if not path.endswith(suffix):
            continue
        root = path[: -len(suffix)]
        if (
            root
            and {
                root + "/readme.md",
                root + "/cmakelists.txt",
                root + "/src/cmakelists.txt",
                root + "/include/nvcomp.hpp",
                root + "/include/nvcomp/lz4.hpp",
            }
            <= tracked_set
        ):
            roots.add(root)
    for path in tracked_set:
        suffix = "/libbsc/libbsc.h"
        if not path.endswith(suffix):
            continue
        root = path[: -len(suffix)]
        if (
            root
            and {
                root + "/authors",
                root + "/cmakelists.txt",
                root + "/license",
                root + "/readme",
                root + "/version",
            }
            <= tracked_set
        ):
            roots.add(root)
    # ORB-SLAM2 is commonly copied wholesale into ROS/robotics workspaces.
    # Its generic top-level name is not enough to prove a copy, so require a
    # distinctive upstream layout spanning headers, implementation, examples,
    # and its DBoW2 dependency. Preserve the canonical upstream repository as
    # its own project unit.
    orb_slam2_suffix = "/include/system.h"
    for path in tracked_set:
        if not ("/" + path).endswith(orb_slam2_suffix):
            continue
        root = path[: -len(orb_slam2_suffix.lstrip("/"))].rstrip("/")
        prefix = (root + "/") if root else ""
        if {
            prefix + "license",
            prefix + "readme.md",
            prefix + "examples/monocular/mono_tum.cc",
            prefix + "include/tracking.h",
            prefix + "src/system.cc",
            prefix + "thirdparty/dbow2/dbow2/bowvector.cpp",
        } <= tracked_set and (
            root or repository != "raulmur/orb_slam2"
        ):
            roots.add(root)
    # TransformerEngine derivatives and copied benchmark submissions contain
    # direct cuBLASMp/NCCL/cuDNN integrations authored by the upstream project.
    # They are not independent host adoption. Match several distinctive files
    # so an ordinary host directory named ``transformer_engine`` is preserved,
    # and scope a nested copy to its own root rather than hiding host source.
    transformer_suffix = (
        "/transformer_engine/common/comm_gemm/comm_gemm.cpp"
    )
    for path in tracked_set:
        if not ("/" + path).endswith(transformer_suffix):
            continue
        root = path[: -len(transformer_suffix.lstrip("/"))].rstrip("/")
        prefix = (root + "/") if root else ""
        if {
            prefix + "transformer_engine/common/cmakelists.txt",
            prefix + "transformer_engine/common/common.h",
            prefix + "transformer_engine/common/util/logging.h",
        } <= tracked_set:
            roots.add(prefix + "transformer_engine")
    return tuple(sorted(roots))


def _inside_embedded_project(path, roots):
    normalized = str(path).strip("/").casefold()
    return any(
        not root
        or normalized == str(root).casefold()
        or normalized.startswith(str(root).casefold() + "/")
        for root in roots
    )


def _notebook_surfaces(raw):
    """Return (code+markdown search text, code-only direct-use text).

    Outputs and notebook/cell metadata are intentionally absent. Both nbformat
    v4 (top-level ``cells``) and v3 (``worksheets[].cells``) are supported.
    """
    try:
        surfaces = parse_notebook_surfaces(raw)
    except NotebookEvidenceError as exc:
        legacy_messages = {
            "notebook is invalid JSON": (
                "tracked notebook is invalid JSON; scan is incomplete"
            ),
            "notebook is not an object": (
                "tracked notebook is not an object; scan is incomplete"
            ),
            "notebook worksheets are invalid": (
                "tracked notebook has invalid worksheets; scan is incomplete"
            ),
            "notebook worksheet is invalid": (
                "tracked notebook has invalid worksheet; scan is incomplete"
            ),
            "notebook has no cells": (
                "tracked notebook has no cells; scan is incomplete"
            ),
            "notebook cells are invalid": (
                "tracked notebook has invalid cells; scan is incomplete"
            ),
            "notebook cell is invalid": (
                "tracked notebook has invalid cell; scan is incomplete"
            ),
            "notebook source is invalid": (
                "tracked notebook has invalid source; scan is incomplete"
            ),
            "notebook source is not text": (
                "tracked notebook has non-text source; scan is incomplete"
            ),
        }
        message = legacy_messages.get(
            str(exc),
            "tracked %s; scan is incomplete" % str(exc),
        )
        raise RuntimeError(message) from exc
    return surfaces.search_text, surfaces.code_text


def _notebook_code(raw):
    return _notebook_surfaces(raw)[1]


def _residual_direct_patterns(lib):
    return tuple(
        re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        for pattern in lib.get("direct_regexes", ())
    )


def _python_imports(source):
    """Return imported modules from executable syntax, never prose/comments."""
    return _python_import_modules(source)


def _python_fallback_executable_surface(source):
    """Keep executable token shape while removing comments and strings."""
    cleaned = scan_module._clean_executable_python(source)
    try:
        tokens = list(
            tokenize.generate_tokens(io.StringIO(cleaned).readline)
        )
    except (tokenize.TokenError, IndentationError):
        return ""
    executable = [
        token._replace(string="")
        if token.type in (tokenize.COMMENT, tokenize.STRING)
        else token
        for token in tokens
    ]
    return tokenize.untokenize(executable)


def _fallback_import_aliases(executable, module):
    """Recover static module aliases from token-sanitized Python-2 source."""
    aliases = set()
    for match in re.finditer(
        r"(?m)^[ \t]*import[ \t]+([^;\n]+)",
        executable,
    ):
        for item in match.group(1).split(","):
            imported = re.match(
                r"[ \t]*([A-Za-z_][A-Za-z0-9_.]*)"
                r"(?:[ \t]+as[ \t]+([A-Za-z_][A-Za-z0-9_]*))?",
                item,
            )
            if imported and imported.group(1) == module:
                aliases.add(imported.group(2) or module)
    return aliases


def _attribute_root_and_parts(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return (
        node.id if isinstance(node, ast.Name) else None,
        tuple(reversed(parts)),
    )


def _warp_direct_api_use(source):
    """Require an executable NVIDIA-Warp API anchor, not a generic import."""
    modules = set(_python_imports(source))
    if any(
        module.startswith("warp." + anchor.casefold())
        for module in modules
        for anchor in WARP_API_ANCHORS
    ):
        return True
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except (SyntaxError, ValueError):
        executable = _python_fallback_executable_surface(source)
        aliases = _fallback_import_aliases(executable, "warp")
        if not aliases:
            return False
        return bool(re.search(
            r"(?m)\b(?:"
            + "|".join(re.escape(value) for value in sorted(aliases))
            + r")\s*\.\s*(?:"
            + "|".join(re.escape(value) for value in sorted(WARP_API_ANCHORS))
            + r")\b",
            executable,
        ))
    aliases = set()
    imported_api = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(
                alias.asname or "warp"
                for alias in node.names
                if alias.name == "warp"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "warp":
            imported_api.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in WARP_API_ANCHORS
            )
    if imported_api:
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            root, parts = _attribute_root_and_parts(node)
            if root in aliases and any(
                part in WARP_API_ANCHORS for part in parts
            ):
                return True
    return False


_MORPHEUS_API_ANCHORS = frozenset(
    {"config", "messages", "pipeline", "stages"}
)


def _morpheus_direct_api_use(source):
    """Disambiguate NVIDIA Morpheus from unrelated ``morpheus`` packages."""
    modules = set(_python_imports(source))
    if any(
        module.startswith("morpheus." + anchor)
        for module in modules
        for anchor in _MORPHEUS_API_ANCHORS
    ):
        return True
    cleaned = scan_module._clean_executable_python(source)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(cleaned)
    except (SyntaxError, ValueError):
        executable = _python_fallback_executable_surface(source)
        aliases = _fallback_import_aliases(executable, "morpheus")
        if not aliases:
            return False
        return bool(re.search(
            r"\b(?:"
            + "|".join(re.escape(value) for value in sorted(aliases))
            + r")\s*\.\s*(?:"
            + "|".join(sorted(_MORPHEUS_API_ANCHORS))
            + r")\b",
            executable,
        ))
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(
                alias.asname or "morpheus"
                for alias in node.names
                if alias.name == "morpheus"
            )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        root, parts = _attribute_root_and_parts(node)
        if root in aliases and any(
            part in _MORPHEUS_API_ANCHORS for part in parts
        ):
            return True
    return False


def _python_shadow_paths(tracked_files, libraries):
    own = {
        path.replace("\\", "/").casefold()
        for path in tracked_files
        if _own_source(path)
    }
    shadow_paths = {}
    for library in libraries:
        namespaces = (
            library.get("import_namespaces")
            or (
                (library["import_namespace"],)
                if library.get("import_namespace")
                else ()
            )
        )
        for namespace in namespaces:
            module_path = str(namespace).casefold().replace(".", "/")
            for path in own:
                root_module = path in {
                    module_path + ".py",
                    module_path + "/__init__.py",
                }
                if (
                    root_module
                    or path.endswith("/" + module_path + ".py")
                    or path.endswith(
                        "/" + module_path + "/__init__.py"
                    )
                ):
                    per_library = shadow_paths.setdefault(
                        library["id"], {}
                    )
                    per_library[path] = (
                        per_library.get(path, False) or root_module
                    )
    return shadow_paths


def _shadowed_for_importer(relpath, shadow_paths):
    importer_path = str(relpath).replace("\\", "/").casefold()
    importer_dir = str(Path(relpath).parent).replace("\\", "/").casefold()
    if importer_dir == ".":
        importer_dir = ""
    shadowed = set()
    for library_id, paths in shadow_paths.items():
        for module_file, root_module in paths.items():
            # A package adapter can legitimately share the external product's
            # basename (for example ``pulp/apis/cuopt.py`` importing cuopt).
            # The importer is already executing under its qualified package
            # name; treating the file as a shadow of its own top-level import
            # suppresses genuine integrations. A distinct sibling/root module
            # remains a shadow and is still rejected below.
            if module_file == importer_path:
                continue
            parts = module_file.split("/")
            module_root = "/".join(parts[:-1])
            # Root modules and conventional package roots are importable from
            # the project environment. Nested fixtures shadow only importers
            # within their own subtree.
            conventional = (
                root_module
                or len(parts) == 1
                or (
                    len(parts) == 2
                    and parts[-1] == "__init__.py"
                )
                or parts[0] in {"src", "python", "lib"}
            )
            shared_subtree = bool(
                module_root
                and (
                    importer_dir == module_root
                    or importer_dir.startswith(module_root + "/")
                )
            )
            if conventional or shared_subtree:
                shadowed.add(library_id)
                break
    return shadowed


def _without_c_comments(source):
    # The mature and direct paths must agree on comment syntax. In particular,
    # comment-shaped bytes inside string literals cannot hide a real include.
    return scan_module._without_cpp_comments(source)


def _prefix_include_resolves_inside_definition(
    source_path,
    include_path,
    prefix,
    tracked_paths,
):
    """Whether a prefix include is one header of a tracked SDK header tree.

    Only a source already located below the configured prefix can be the
    library's own implementation. A host source elsewhere in the monorepo
    remains genuine direct evidence even when the repository also carries a
    local SDK tree.
    """
    source = str(source_path).strip("/").replace("\\", "/").casefold()
    include = str(include_path).strip("/").replace("\\", "/").casefold()
    normalized_prefix = (
        str(prefix).strip("/").replace("\\", "/").casefold()
    )
    if (
        not normalized_prefix
        or not include.startswith(normalized_prefix + "/")
    ):
        return False
    marker = normalized_prefix + "/"
    positions = []
    if source.startswith(marker):
        positions.append(0)
    start = 0
    while True:
        index = source.find("/" + marker, start)
        if index < 0:
            break
        positions.append(index + 1)
        start = index + len(marker) + 1
    return any(
        (
            source[:position] + include
        ) in tracked_paths
        for position in positions
    )


_INCLUDE_RE = re.compile(
    r"(?m)^[ \t]*#[ \t]*include[ \t]*([<\"])([^>\"]+)[>\"]",
    re.IGNORECASE,
)


def _suffixes(value):
    parts = [part for part in value.lower().replace("\\", "/").split("/") if part]
    return tuple("/".join(parts[index:]) for index in range(len(parts)))


def _local_exact_header_paths(
    tracked_files,
    header_ids,
    embedded_project_roots,
):
    """Index project-owned headers that can shadow exact SDK headers."""
    ids_by_basename = {}
    for header, library_ids in header_ids.items():
        ids_by_basename.setdefault(Path(header).name.casefold(), set()).update(
            library_ids
        )
    local = {}
    for raw_path in tracked_files:
        path = str(raw_path).strip("/").replace("\\", "/")
        library_ids = ids_by_basename.get(Path(path).name.casefold(), ())
        if (
            not library_ids
            or not _own_source(path)
            or _inside_embedded_project(path, embedded_project_roots)
        ):
            continue
        for library_id in library_ids:
            local.setdefault(library_id, set()).add(path.casefold())
    return local


def _include_resolves_to_local_header(
    source_path,
    include_path,
    library_id,
    local_header_paths,
    *,
    quoted=False,
):
    """Return whether an include resolves to a tracked project-owned header."""
    candidates = local_header_paths.get(library_id, ())
    if not candidates:
        return False
    source = str(source_path).strip("/").replace("\\", "/").casefold()
    include = str(include_path).strip("/").replace("\\", "/").casefold()
    if not include:
        return False
    adjacent = str(Path(source).parent / include).replace("\\", "/")
    if include in candidates or (quoted and adjacent in candidates):
        return True
    if "/" in include and any(path.endswith("/" + include) for path in candidates):
        return True
    basename = Path(include).name.casefold()
    # A wrapper named after the SDK header can itself include the real SDK
    # header. Allow that file to prove adoption, while rejecting other source
    # files whose same-named include resolves to the tracked local API.
    return (
        "/" not in include
        and Path(source).name.casefold() != basename
        and any(Path(path).name.casefold() == basename for path in candidates)
    )


def _literal_trie_pattern(values):
    """Return a factored regex for exact, already-normalized substrings."""
    root = {}
    terminal = None
    for value in values:
        node = root
        for character in value:
            node = node.setdefault(character, {})
        node[terminal] = {}

    def emit(node):
        branches = [
            re.escape(character) + emit(child)
            for character, child in sorted(
                (
                    (character, child)
                    for character, child in node.items()
                    if character is not terminal
                ),
                key=lambda item: item[0],
            )
        ]
        if not branches:
            body = ""
        elif len(branches) == 1:
            body = branches[0]
        else:
            body = "(?:%s)" % "|".join(branches)
        if terminal in node and body:
            return "(?:%s)?" % body
        return body

    return emit(root)


_NOTEBOOK_BASE64_RUN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{256,}={0,2}"
    r"(?![A-Za-z0-9+/=])"
)


def _notebook_retention_pattern(token_ids):
    """Compile conservative notebook anchors without substring collisions."""
    branches = []
    for token in sorted(token_ids, key=lambda value: (-len(value), value)):
        escaped = re.escape(token)
        if re.fullmatch(r"[a-z0-9_]+", token):
            branches.append(
                r"(?<![a-z0-9])%s(?![a-z0-9])" % escaped
            )
        else:
            branches.append(escaped)
    return re.compile("(?:" + "|".join(branches) + ")") if branches else None


def _notebook_might_affect_verdict(raw, retention_re):
    """Search decoded authored cells before applying the retention shortcut."""
    if retention_re is None:
        return True
    try:
        surfaces = parse_notebook_surfaces(raw)
    except NotebookEvidenceError:
        # Preserve the bounded fast-negative behavior for plainly irrelevant
        # malformed notebooks. A literal detector term or a JSON escape that
        # could conceal one forces the ordinary fail-closed parser path.
        rendered = (
            raw.decode("utf-8", errors="replace")
            if isinstance(raw, bytes)
            else str(raw)
        )
        searchable = _NOTEBOOK_BASE64_RUN.sub(
            "", rendered.casefold()
        )
        return (
            retention_re.search(searchable) is not None
            or re.search(
                r"\\u[0-9a-f]{4}|\\/",
                searchable,
                re.IGNORECASE,
            )
            is not None
        )
    return (
        retention_re.search(surfaces.search_text.casefold())
        is not None
    )


def _triage_indexes(libraries):
    token_ids = {}
    header_ids = {}
    header_prefixes = []
    namespace_ids = {}
    residual = {}
    for lib in libraries:
        library_id = lib["id"]
        for token in _broad_tokens(lib):
            token_ids.setdefault(token, set()).add(library_id)
        headers = list(lib.get("cpp_headers") or ())
        if lib.get("header"):
            headers.append(lib["header"])
        for header in headers:
            header_ids.setdefault(str(header).lower().strip("/"), set()).add(
                library_id
            )
        for prefix in lib.get("header_prefixes", ()):
            header_prefixes.append((str(prefix).lower(), library_id))
        namespaces = (
            lib.get("import_namespaces")
            or ((lib["import_namespace"],) if lib.get("import_namespace") else ())
        )
        for namespace in namespaces:
            namespace_ids.setdefault(str(namespace).lower(), set()).add(library_id)
        patterns = _residual_direct_patterns(lib)
        if patterns:
            residual[library_id] = patterns
    token_re = (
        re.compile(
            _literal_trie_pattern(token_ids),
        )
        if token_ids else None
    )
    return token_ids, token_re, header_ids, tuple(header_prefixes), namespace_ids, residual


def _broad_tokens(lib):
    values = []
    for key in ("token", "import_namespace", "pip_pattern"):
        value = lib.get(key)
        if isinstance(value, str):
            values.append(value.lower())
        elif isinstance(value, (list, tuple)):
            values.extend(str(item).lower() for item in value)
    values.extend(str(item).lower() for item in lib.get("cpp_headers", ()))
    values.extend(str(item).lower() for item in lib.get("header_prefixes", ()))
    values.extend(str(item).lower() for item in lib.get("build_signals", ()))
    values.extend(
        str(item).lower()
        for item in (
            lib.get("targeted_build_discovery_anchors")
            or lib.get("targeted_build_signals", ())
        )
    )
    values.extend(str(item).lower() for item in lib.get("discovery_tokens", ()))
    return tuple(sorted({value for value in values if value}, key=len, reverse=True))


def triage_tree(
    checkout,
    libraries,
    *,
    deadline_monotonic=None,
    inventory_all=False,
    existing_text=None,
    full_name=None,
    bare_git_dir=None,
    bare_head=None,
    bare_entries=None,
    required_library_ids=None,
):
    checkout = Path(checkout)
    bare_mode = bare_entries is not None
    if bare_mode and (
        inventory_all
        or existing_text is not None
        or not bare_git_dir
        or not bare_head
    ):
        raise ValueError(
            "bare triage requires git_dir/head and cannot inventory all"
        )
    libraries = list(libraries)
    libraries_by_id = {library["id"]: library for library in libraries}
    required_library_ids = tuple(
        libraries_by_id
        if required_library_ids is None
        else dict.fromkeys(required_library_ids)
    )
    (token_ids, token_re, header_ids, header_prefixes,
     namespace_ids, residual_patterns) = _triage_indexes(libraries)
    candidates = set()
    direct = {lib["id"]: set() for lib in libraries}
    signals = {lib["id"]: set() for lib in libraries}
    cff = []
    current_text = _TextInventory()
    examined = byte_count = skipped_large = 0
    retention_libraries = {
        library["id"]: library for library in ALL_LIBRARIES
    }
    retention_libraries.update({
        library["id"]: library for library in libraries
    })
    retention_ids, retention_token_re, *_unused = _triage_indexes(
        retention_libraries.values()
    )
    notebook_retention_re = _notebook_retention_pattern(retention_ids)

    if bare_mode:
        tracked_files = sorted(
            path for _mode, _object_type, _object_id, path in bare_entries
        )
    elif inventory_all:
        current_text, skipped_large = _tracked_text_inventory(
            checkout,
            existing_text=existing_text,
            token_ids=token_ids,
            token_re=token_re,
            retention_token_re=retention_token_re,
            notebook_retention_re=notebook_retention_re,
            full_name=full_name,
        )
        tracked_files = sorted(current_text)
    else:
        tracked_files = _tracked_files(checkout)
    embedded_project_roots = _embedded_project_roots(
        tracked_files, full_name=full_name
    )
    tracked_paths_folded = {
        str(path).strip("/").replace("\\", "/").casefold()
        for path in tracked_files
    }
    if bare_mode:
        current_text = _bare_tracked_text_inventory(
            bare_git_dir,
            bare_head,
            bare_entries,
            deadline_monotonic=deadline_monotonic,
            embedded_project_roots=embedded_project_roots,
            required_library_ids=required_library_ids,
            libraries=retention_libraries,
        )
    local_header_paths = _local_exact_header_paths(
        tracked_files,
        header_ids,
        embedded_project_roots,
    )
    python_shadow_paths = _python_shadow_paths(
        tracked_files, libraries
    )
    for relpath in tracked_files:
        if (
            deadline_monotonic is not None
            and time.monotonic() >= deadline_monotonic
        ):
            raise RuntimeError("repository wall deadline exhausted during triage")
        if not inventory_all and not _eligible(relpath):
            continue
        path = checkout / relpath
        if inventory_all:
            raw_text = current_text[relpath]
            size = current_text.size_by_path[relpath]
        elif bare_mode:
            if relpath not in current_text.size_by_path:
                # Symlinks, submodules and other non-regular tree entries have
                # no worktree-regular-file equivalent.
                continue
            size = current_text.size_by_path[relpath]
        else:
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            size = metadata.st_size
        if os.path.basename(relpath).lower() == "citation.cff":
            cff.append(relpath)
        inside_embedded = _inside_embedded_project(
            relpath, embedded_project_roots
        )
        own_source = (
            _eligible(relpath)
            and _own_source(relpath)
            and not inside_embedded
        )
        if size > MAX_OWN_SOURCE_BYTES and own_source:
            skipped_large += 1
            continue
        if size > MAX_SOURCE_BYTES and not own_source:
            # Generated/vendor trees cannot establish direct evidence and do
            # not reduce source-coverage completeness.
            continue
        if inside_embedded:
            # The tracked path remains available to copied-project and CFF
            # policy, but copied content cannot establish host adoption and
            # therefore does not need decoding or notebook parsing.
            continue
        if (
            bare_mode
            and relpath in current_text.lfs_pointer_paths
        ):
            # Relevant pointers already requested a worktree while the bare
            # inventory was built. An exact irrelevant pointer contributes no
            # searchable evidence and is intentionally not counted as read.
            continue
        if (
            inventory_all
            and _eligible(relpath)
            and relpath in current_text.lfs_pointer_paths
            and relpath not in current_text.hydrated_lfs_paths
        ):
            if lfs_evidence_path_relevant(
                relpath,
                required_library_ids,
                libraries=retention_libraries,
            ):
                raise RuntimeError(
                    "tracked detector-relevant Git LFS object is "
                    "unavailable: " + relpath
                )
            continue
        if bare_mode:
            if relpath not in current_text:
                # Binary files cannot establish text evidence.
                continue
            raw_text = current_text[relpath]
        elif not inventory_all:
            try:
                encoded = path.read_bytes()
            except OSError:
                continue
            # Match ``git grep -I``: binary blobs cannot establish textual
            # evidence. They are deliberately not retained in the memory index.
            if b"\0" in encoded[:8192]:
                continue
            pointer = parse_lfs_pointer(encoded)
            if pointer is not None:
                current_text.lfs_pointer_paths.add(relpath)
                current_text.lfs_pointers_by_path[relpath] = pointer
                current_text.raw_bytes_by_path[relpath] = encoded
                current_text[relpath] = ""
                if lfs_evidence_path_relevant(
                    relpath,
                    required_library_ids,
                    libraries=retention_libraries,
                ):
                    raise RuntimeError(
                        "tracked detector-relevant Git LFS object is "
                        "unavailable: " + relpath
                    )
                continue
            raw_text = encoded.decode("utf-8", errors="ignore")
            current_text[relpath] = raw_text
            current_text.size_by_path[relpath] = size
            current_text.analyzed_bytes_by_path[relpath] = min(
                size,
                len(raw_text.encode("utf-8", errors="ignore")),
            )
            if relpath.endswith(".ipynb"):
                current_text.raw_bytes_by_path[relpath] = encoded
        if inventory_all and relpath.endswith(".ipynb"):
            raw = current_text.notebook_code_by_path.get(
                relpath, raw_text
            )
        elif relpath.endswith(".ipynb"):
            notebook_payload = current_text.raw_bytes_by_path.get(
                relpath,
                encoded if not bare_mode else raw_text,
            )
            if _notebook_might_affect_verdict(
                notebook_payload, notebook_retention_re
            ):
                try:
                    raw = _notebook_code(notebook_payload)
                except RuntimeError as exc:
                    raise RuntimeError("%s: %s" % (exc, relpath)) from exc
            else:
                raw = ""
        else:
            raw = raw_text
        suffix = Path(relpath).suffix.lower()
        imported = _python_imports(raw) if suffix in PYTHON_SOURCE_EXTENSIONS else ()
        c_source = _without_c_comments(raw) if suffix in C_SOURCE_EXTENSIONS else ""
        examined += 1
        byte_count += (
            current_text.analyzed_bytes_by_path[relpath]
            if inventory_all
            else min(size, len(raw.encode("utf-8", "ignore")))
        )
        if token_re is not None:
            if inventory_all:
                matched_ids = current_text.token_ids_by_path[relpath]
            else:
                low = raw.lower()
                matched_ids = set()
                for match in token_re.finditer(low):
                    matched_ids.update(
                        token_ids.get(match.group(0).lower(), ())
                    )
            for library_id in matched_ids:
                candidates.add(library_id)
                signals[library_id].add(relpath)

        if not own_source:
            continue
        direct_ids = set()
        if c_source:
            for match in _INCLUDE_RE.finditer(c_source):
                include = match.group(2).lower()
                include_ids = set()
                for suffix in _suffixes(include):
                    include_ids.update(header_ids.get(suffix, ()))
                direct_ids.update(
                    library_id
                    for library_id in include_ids
                    if not _include_resolves_to_local_header(
                        relpath,
                        include,
                        library_id,
                        local_header_paths,
                        quoted=(match.group(1) == '"'),
                    )
                )
                for prefix, library_id in header_prefixes:
                    # Prefix detectors model include directories such as
                    # ``cutlass/``.  Requiring a real header suffix prevents
                    # backups/prose artifacts such as ``cutlass.h.backup`` from
                    # becoming confirmed direct integrations.
                    if (
                        include.startswith(prefix)
                        and Path(include).suffix.lower() in C_HEADER_EXTENSIONS
                        and not _prefix_include_resolves_inside_definition(
                            relpath,
                            include,
                            prefix,
                            tracked_paths_folded,
                        )
                    ):
                        direct_ids.add(library_id)
        if imported:
            shadowed_python_ids = _shadowed_for_importer(
                relpath, python_shadow_paths
            )
            python_direct_ids = set()
            for module in imported:
                parts = module.split(".")
                for length in range(1, len(parts) + 1):
                    python_direct_ids.update(
                        namespace_ids.get(".".join(parts[:length]), ())
                    )
            python_direct_ids.difference_update(shadowed_python_ids)
            if (
                "warp" in python_direct_ids
                and not _warp_direct_api_use(raw)
            ):
                python_direct_ids.remove("warp")
            if (
                "morpheus" in python_direct_ids
                and not _morpheus_direct_api_use(raw)
            ):
                python_direct_ids.remove("morpheus")
            direct_ids.update(python_direct_ids)
        for library_id, patterns in residual_patterns.items():
            if any(pattern.search(raw) for pattern in patterns):
                direct_ids.add(library_id)
        for library_id in direct_ids:
            if _library_definition_path(
                relpath, libraries_by_id[library_id]
            ):
                continue
            candidates.add(library_id)
            direct[library_id].add(relpath)

    return TriageResult(
        candidate_library_ids=tuple(sorted(candidates)),
        direct_files={
            lid: tuple(sorted(paths))
            for lid, paths in direct.items() if paths
        },
        signal_files={
            lid: tuple(sorted(paths))
            for lid, paths in signals.items() if paths
        },
        citation_cff=tuple(sorted(cff)),
        current_text=current_text,
        files_examined=examined,
        bytes_examined=byte_count,
        skipped_large=skipped_large,
        lfs_pointers=dict(current_text.lfs_pointers_by_path),
        hydrated_lfs_paths=tuple(
            sorted(current_text.hydrated_lfs_paths)
        ),
    )
