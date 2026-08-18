"""Per-repo deep scan: clone, confirm genuine integration, date it, detect AI.

For each repo we clone once (blobless: small download, history available for
pickaxe on demand) and per library determine:
  - classification: CONFIRMED (own-source #include) / VENDORED_ONLY / REFERENCED
                    (token present but no own #include, e.g. generators) / absent
  - first_integration: author date of the first commit to introduce the
    include in the repo's OWN source (vendored subtree excluded)
  - ai_on_integration: whether that first-integration commit carries an AI signal
Plus repo-wide AI authorship (which agents, commit counts) and AI config files.
"""
import ast
import base64
from contextlib import contextmanager
import fnmatch
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import signal
import shutil
import subprocess
import stat
import sys
import tempfile
import threading
import time
import tokenize
import tomllib
import warnings

from .config import (AI_CONFIG_FILE_RE, AI_SIGNALS, COPIED_PROJECT_PATH_RE,
                     DOC_SKILL_PATH_RE, ENV_DUMP_PATH_RE,
                     PY_DEP_PATHSPECS, PY_SIGNALS, SOURCE_EXTS, VENDOR_PATH_RE,
                     WARP_API_ANCHORS)
from .evidence_content import (
    NotebookEvidenceError,
    parse_notebook_surfaces,
)

_SRC_PATHSPEC = ["*.%s" % e for e in SOURCE_EXTS]
_REC = "\x1e"   # record sep
_UNIT = "\x1f"  # unit sep


def _positive_int_env(name, default):
    try:
        value = int(os.environ.get(name, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


# A single repository used to be able to consume hours: every pickaxe had its own
# 180-second timeout, and a repo may run many pickaxes. These bounds are deliberately
# configurable for smoke tests, but production defaults cap the WHOLE repository at
# ten minutes, each git command at two minutes, and each clone at three minutes.
REPO_TIMEOUT = _positive_int_env("CXIT_REPO_TIMEOUT_SECONDS", 600)
GIT_TIMEOUT = _positive_int_env("CXIT_GIT_TIMEOUT_SECONDS", 120)
CLONE_TIMEOUT = _positive_int_env("CXIT_CLONE_TIMEOUT_SECONDS", 180)
CLONE_ATTEMPTS = _positive_int_env("CXIT_CLONE_ATTEMPTS", 2)
CLONE_RETRY_DELAY = _positive_int_env("CXIT_CLONE_RETRY_DELAY_SECONDS", 5)

_ACTIVE_REPO_DEADLINE = [None]
_ACTIVE_PROCESS_GROUP = [None]
_ACTIVE_PROCESS_GROUP_REGISTRY = [None]
_ACTIVE_PROCESS_GROUPS = set()
_ACTIVE_PROCESS_GROUPS_LOCK = threading.Lock()
_CURRENT_TREE_INVENTORY = [None]
_ACTIVE_REPOSITORY_NAME = [None]
_GIT_SUBPROCESS_COUNT = [0]
_GIT_SUBPROCESS_COUNT_LOCK = threading.Lock()


class _RepoScanFailure(RuntimeError):
    """An operational clone/git failure. Never interpret this as clean non-evidence."""


class _RepoScanTimeout(_RepoScanFailure):
    """The whole-repository wall-clock deadline expired."""


class FirstUseReuseUnavailable(RuntimeError):
    """A prior first-use boundary cannot safely replace complete dating."""


def reset_git_subprocess_count():
    with _GIT_SUBPROCESS_COUNT_LOCK:
        _GIT_SUBPROCESS_COUNT[0] = 0


def git_subprocess_count():
    with _GIT_SUBPROCESS_COUNT_LOCK:
        return int(_GIT_SUBPROCESS_COUNT[0])


def _record_git_subprocess(cmd):
    if cmd and os.path.basename(str(cmd[0])) == "git":
        with _GIT_SUBPROCESS_COUNT_LOCK:
            _GIT_SUBPROCESS_COUNT[0] += 1


@contextmanager
def current_tree_inventory(root, text_by_path):
    """Serve current-tree text operations from one worker-local blob pass."""
    previous = _CURRENT_TREE_INVENTORY[0]
    texts = (
        text_by_path
        if isinstance(text_by_path, dict)
        else dict(text_by_path)
    )
    _CURRENT_TREE_INVENTORY[0] = (
        os.path.abspath(str(root)),
        texts,
        tuple(sorted(path for path, text in texts.items() if text)),
        getattr(texts, "notebook_code_by_path", {}),
    )
    try:
        yield
    finally:
        _CURRENT_TREE_INVENTORY[0] = previous


def _inventory_text(abspath):
    active = _CURRENT_TREE_INVENTORY[0]
    if active is None:
        return None, False
    root, texts, _searchable_paths, _notebook_codes = active
    try:
        relative = os.path.relpath(os.path.abspath(abspath), root)
    except (OSError, ValueError):
        return None, False
    if relative == ".." or relative.startswith(".." + os.sep):
        return None, False
    key = relative.replace(os.sep, "/")
    # An active in-root inventory is authoritative. A missing key represents
    # a binary/pruned/unavailable blob and must never fall back to reopening
    # the worktree behind the one-pass scanner's back.
    return texts.get(key), True


def _inventory_notebook_code(abspath):
    active = _CURRENT_TREE_INVENTORY[0]
    if active is None:
        return None, False
    root, _texts, _searchable_paths, notebook_codes = active
    try:
        relative = os.path.relpath(os.path.abspath(abspath), root)
    except (OSError, ValueError):
        return None, False
    if relative == ".." or relative.startswith(".." + os.sep):
        return None, False
    key = relative.replace(os.sep, "/")
    return notebook_codes.get(key), key in notebook_codes


def _grep_path_matches(path, pathspecs):
    if not pathspecs:
        return True
    for pattern in pathspecs:
        normalized = str(pattern).replace("\\", "/")
        if fnmatch.fnmatchcase(path, normalized):
            return True
        if "/" not in normalized and fnmatch.fnmatchcase(
            os.path.basename(path), normalized
        ):
            return True
    return False


def _python_ere(pattern):
    """Translate the POSIX classes used by the established detector regexes."""
    return (
        pattern.replace("[[:space:]]", r"\s")
        .replace("[[:blank:]]", r"[ \t]")
    )


def _inventory_git_grep(args):
    """Emulate the detector's bounded ``git grep`` surface over cached text.

    Returns ``None`` for non-grep commands so history operations still use Git.
    All grep forms used by this module are covered and regression-tested.
    """
    active = _CURRENT_TREE_INVENTORY[0]
    if active is None or not args or args[0] != "grep":
        return None
    _root, texts, searchable_paths, _notebook_codes = active
    flags = set()
    pattern = None
    pathspecs = []
    after_separator = False
    index = 1
    while index < len(args):
        value = str(args[index])
        if after_separator:
            pathspecs.append(value)
        elif value == "--":
            after_separator = True
        elif value == "-e":
            index += 1
            if index >= len(args):
                raise _RepoScanFailure("git grep -e requires a pattern")
            pattern = str(args[index])
        elif value.startswith("-"):
            if value not in ("--cached",):
                flags.update(value[1:])
        elif pattern is None:
            pattern = value
        else:
            pathspecs.append(value)
        index += 1
    if pattern is None:
        raise _RepoScanFailure("git grep requires a pattern")

    ignore_case = "i" in flags
    literal = "F" in flags
    regex = None
    if not literal:
        if "E" not in flags and re.search(r"[+?(){}|]", pattern):
            raise _RepoScanFailure(
                "in-memory git grep refuses unsupported BRE-special pattern; "
                "declare -F or -E explicitly"
            )
        try:
            regex = re.compile(
                _python_ere(pattern),
                re.IGNORECASE if ignore_case else 0,
            )
        except re.error as exc:
            raise _RepoScanFailure(
                "in-memory git grep regex failed: %s" % exc
            ) from exc
    needle = pattern.casefold() if ignore_case else pattern

    output = []
    matches_by_object = {}
    for path in searchable_paths:
        if not _grep_path_matches(path, pathspecs):
            continue
        text = texts[path]
        object_key = id(text)
        matching_lines = matches_by_object.get(object_key)
        if matching_lines is None:
            matching_lines = []
            for line_number, line in enumerate(text.splitlines(), 1):
                haystack = line.casefold() if ignore_case else line
                matched = (
                    needle in haystack
                    if literal
                    else regex.search(line) is not None
                )
                if matched:
                    matching_lines.append((line_number, line))
            matches_by_object[object_key] = matching_lines
        if not matching_lines:
            continue
        if "l" in flags:
            output.append(path)
            continue
        if "h" in flags:
            output.extend(line for _number, line in matching_lines)
            continue
        if "n" in flags:
            output.extend(
                "%s:%d:%s" % (path, number, line)
                for number, line in matching_lines
            )
            continue
        output.extend(
            "%s:%s" % (path, line)
            for _number, line in matching_lines
        )
    return "\n".join(output) + ("\n" if output else "")


def _remaining_timeout(requested):
    """Clamp a command timeout to the active whole-repository deadline."""
    deadline = _ACTIVE_REPO_DEADLINE[0]
    if deadline is None:
        return requested
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _RepoScanTimeout("repository scan exceeded %ss wall-clock cap" % REPO_TIMEOUT)
    return max(0.1, min(float(requested), remaining))


def _terminate_process_group(proc):
    """Terminate git plus remote helpers/pack workers, not only the parent process."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            proc.terminate()
        except ProcessLookupError:
            return
    try:
        proc.communicate(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    proc.communicate()


def _register_process_group(proc):
    """Expose the active subprocess group to worker and parent cancellation."""
    with _ACTIVE_PROCESS_GROUPS_LOCK:
        _ACTIVE_PROCESS_GROUPS.add(proc)
        _ACTIVE_PROCESS_GROUP[0] = proc
        _write_process_group_registry_locked()


def _clear_process_group(proc):
    with _ACTIVE_PROCESS_GROUPS_LOCK:
        _ACTIVE_PROCESS_GROUPS.discard(proc)
        if _ACTIVE_PROCESS_GROUP[0] is proc:
            _ACTIVE_PROCESS_GROUP[0] = next(
                iter(_ACTIVE_PROCESS_GROUPS), None
            )
        _write_process_group_registry_locked()


def _write_process_group_registry_locked():
    """Atomically advertise every concurrent Git subprocess in this worker."""
    registry = _ACTIVE_PROCESS_GROUP_REGISTRY[0]
    if registry is None:
        return
    path = os.fspath(registry)
    if not _ACTIVE_PROCESS_GROUPS:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    temporary = "%s.tmp-%d" % (path, os.getpid())
    try:
        with open(temporary, "w", encoding="ascii") as stream:
            for process in sorted(
                _ACTIVE_PROCESS_GROUPS, key=lambda value: value.pid
            ):
                stream.write("%d %d\n" % (os.getpid(), process.pid))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass


def _terminate_active_process_group():
    """Best-effort cleanup used by a ProcessPool worker's signal handler."""
    with _ACTIVE_PROCESS_GROUPS_LOCK:
        processes = tuple(_ACTIVE_PROCESS_GROUPS)
    for proc in processes:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                proc.terminate()
            except ProcessLookupError:
                continue


def _git_auth_env():
    """Pass GitHub auth via process environment, never URL/argv/log output."""
    env = os.environ.copy()
    # Repository checkout is an evidence-materialization step, not an LFS
    # download client.  Smudging can fail on public repositories whose owner
    # exhausted an LFS quota, even when every detector-relevant Git blob is
    # available.  Keep pointer blobs local and let triage fail closed only
    # when a detector-relevant path itself is an unavailable LFS object.
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    token = (env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or "").strip()
    # The encoded, Git-scoped header below is the only credential the child
    # needs.  Do not expose reusable raw tokens to Git hooks, helpers, filters,
    # or other child processes.
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    env.pop("OPENALEX_API_KEY", None)
    if not token:
        return env
    try:
        count = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        count = 0
    credential = base64.b64encode(
        ("x-access-token:" + token).encode("utf-8")).decode("ascii")
    env["GIT_CONFIG_COUNT"] = str(count + 1)
    env["GIT_CONFIG_KEY_%d" % count] = "http.extraHeader"
    env["GIT_CONFIG_VALUE_%d" % count] = "Authorization: Basic " + credential
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _command_label(command):
    """Return a useful, credential-safe subprocess label for diagnostics."""
    values = [str(value) for value in command]
    if not values:
        return "command"
    if os.path.basename(values[0]) != "git":
        return " ".join(values[:4])
    index = 1
    options_with_values = {
        "-c",
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--config-env",
    }
    while index < len(values):
        value = values[index]
        if value in options_with_values:
            index += 2
            continue
        if value.startswith((
            "--git-dir=",
            "--work-tree=",
            "--namespace=",
            "--super-prefix=",
            "--config-env=",
        )):
            index += 1
            continue
        if value.startswith("-"):
            index += 1
            continue
        return "git " + " ".join(values[index:index + 3])
    return "git"


def _run_command(cmd, timeout, env=None):
    """Run a subprocess with a hard timeout and process-group cleanup."""
    timeout = _remaining_timeout(timeout)
    _record_git_subprocess(cmd)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
        env=env,
    )
    _register_process_group(proc)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        detail = "%s timed out after %.1fs" % (
            _command_label(cmd), timeout)
        deadline = _ACTIVE_REPO_DEADLINE[0]
        if deadline is not None and time.monotonic() >= deadline:
            raise _RepoScanTimeout(detail)
        # The per-command cap fired while the whole-repository budget still had
        # time. This is retryable with the same fresh-clone policy as other git
        # failures; it must not masquerade as an exhausted repository deadline.
        raise _RepoScanFailure(detail)
    except BaseException:
        _terminate_process_group(proc)
        raise
    finally:
        _clear_process_group(proc)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def _run_command_bytes(cmd, timeout, *, input_bytes=b"", env=None):
    """Binary subprocess variant used by one batched current-tree object read."""
    timeout = _remaining_timeout(timeout)
    _record_git_subprocess(cmd)
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=env,
    )
    _register_process_group(proc)
    try:
        stdout, stderr = proc.communicate(
            input=input_bytes,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        _terminate_process_group(proc)
        detail = "%s timed out after %.1fs" % (
            _command_label(cmd), timeout)
        deadline = _ACTIVE_REPO_DEADLINE[0]
        if deadline is not None and time.monotonic() >= deadline:
            raise _RepoScanTimeout(detail)
        raise _RepoScanFailure(detail)
    except BaseException:
        _terminate_process_group(proc)
        raise
    finally:
        _clear_process_group(proc)
    return subprocess.CompletedProcess(
        cmd,
        proc.returncode,
        stdout,
        stderr,
    )


def _git(dir_, *args, timeout=GIT_TIMEOUT):
    # core.quotePath=false so non-ASCII paths come back as real UTF-8 (not octal
    # escapes); otherwise a `-- <path>` pathspec can't match them and dating fails
    # silently (TD-14: e.g. Choi-kang's Chinese-character path). Disable commit
    # graph reads: a stale commit-graph referencing an absent partial-clone object
    # caused the 2026-07-20 run to emit thousands of errors and never finish.
    inventory_result = _inventory_git_grep(args)
    if inventory_result is not None:
        return inventory_result
    label = "git " + " ".join(str(a) for a in args[:2])
    try:
        out = _run_command(
            ["git", "-c", "core.quotePath=false", "-c", "core.commitGraph=false",
             "-c", "maintenance.auto=false", "-C", dir_] + list(args),
            timeout, env=_git_auth_env())
        # git grep exits 1 with no stderr when there are simply no matches — not an
        # error. Every genuine failure RAISES so the whole repo is re-cloned; returning
        # empty output used to misclassify corrupt/incomplete clones as clean scans.
        if out.returncode not in (0, 1) or (out.returncode == 1 and out.stderr.strip()):
            detail = out.stderr.strip() or "exit %d" % out.returncode
            print("    WARN %s failed: %s" % (label, detail[:240]),
                  file=sys.stderr, flush=True)
            raise _RepoScanFailure("%s failed: %s" % (label, detail[:240]))
        return out.stdout
    except _RepoScanTimeout:
        print("    WARN %s TIMEOUT" % label, file=sys.stderr, flush=True)
        raise
    except _RepoScanFailure:
        raise
    except Exception as e:
        print("    WARN %s errored: %s" % (label, e),
              file=sys.stderr, flush=True)
        raise _RepoScanFailure("%s errored: %s" % (label, e))


def _clone(full_name, dest):
    url = "https://github.com/%s.git" % full_name
    try:
        r = _run_command(
            ["git", "clone", "--filter=blob:none", "--quiet", "--no-tags",
             "--single-branch", "-c", "advice.detachedHead=false",
             "-c", "core.commitGraph=false", "-c", "maintenance.auto=false",
             url, dest],
            CLONE_TIMEOUT, env=_git_auth_env())
        if r.returncode:
            return False, (r.stderr.strip() or "git clone exit %d" % r.returncode)[:240]
        return True, ""
    except _RepoScanTimeout:
        raise
    except Exception as e:
        return False, str(e)[:240]


def _verify_clone(dest):
    """Reject incomplete/corrupt clones before detection or expensive pickaxes."""
    checks = (
        ("HEAD", ["rev-parse", "--verify", "HEAD^{commit}"], 30),
        (
            "connectivity",
            ["fsck", "--connectivity-only", "--no-dangling"],
            GIT_TIMEOUT,
        ),
        ("commit-graph", ["commit-graph", "verify"], GIT_TIMEOUT),
    )
    for name, args, timeout in checks:
        try:
            out = _run_command(
                ["git", "-c", "core.commitGraph=false", "-c", "maintenance.auto=false",
                 "-C", dest] + args,
                timeout, env=_git_auth_env())
        except _RepoScanTimeout:
            raise
        except Exception as e:
            raise _RepoScanFailure("clone %s check errored: %s" % (name, e))
        if out.returncode:
            detail = out.stderr.strip() or out.stdout.strip() or "exit %d" % out.returncode
            raise _RepoScanFailure("clone %s check failed: %s" % (name, detail[:240]))


def _is_vendored(path):
    return bool(
        VENDOR_PATH_RE.search(path)
        or COPIED_PROJECT_PATH_RE.search(path)
    )


def _is_env_dump(path):
    # A checked-in package-manager install dir (virtualenv / node_modules):
    # noise, not a deliberate vendoring. Never counts as evidence.
    return bool(ENV_DUMP_PATH_RE.search(path))


def _is_doc_or_skill(path):
    # A doc / AI-agent-skill file naming the library (e.g. an ovrtx mention inside a copied
    # .claude/skills/…/SKILL.md) is documentation ABOUT the library, not code/build use of it —
    # never a "targeted" adoption signal. (Tracked separately; see DOC_SKILL_PATH_RE.)
    return bool(DOC_SKILL_PATH_RE.search(path))


_AGENT_SKILL_PATH_RE = re.compile(
    r"(^|/)(\.claude|\.codex|\.agent|\.agents|skills?|skillhub)/"
    r"|(^|/)(AGENTS?|CLAUDE|GEMINI)\.mdx?$",
    re.IGNORECASE,
)


def _is_agent_skill(path):
    """Return whether a path is agent instruction/skill content."""
    return bool(_AGENT_SKILL_PATH_RE.search(path))


# A Python manifest alone is not proof of a copied project. Monorepos, ROS
# workspaces and native extensions routinely carry nested setup.py files.
# Explicit deployment/fixture/corpus containers are the evidence boundary.
_PROJ_MANIFESTS = ("setup.py", "pyproject.toml", "setup.cfg")
_COPY_CONTAINER_PARTS = frozenset({
    "deployment", "deployments", "fixture", "fixtures", "corpus",
    "corpora", "testdata", "test-data",
})


def _is_regular_nonsymlink(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _in_embedded_project(dest, path):
    if COPIED_PROJECT_PATH_RE.search(path):
        return True
    repository = (_ACTIVE_REPOSITORY_NAME[0] or "").casefold()
    normalized = path.strip("/").replace("\\", "/")
    if repository in {
        "cz007297/mliap-fork-follows-main",
        "paperg/nccl_gp",
    }:
        return True
    if (
        repository
        and repository != "kitware/cmake"
        and os.path.exists(os.path.join(dest, "Source/CMakeVersion.cmake"))
        and os.path.exists(
            os.path.join(dest, "Modules/CMakeCUDAInformation.cmake")
        )
    ):
        return True
    if (
        repository
        and repository != "nvidia/nccl"
        and normalized.split("/", 1)[0].casefold() == "src"
        and os.path.exists(os.path.join(dest, "src/bootstrap.cc"))
        and os.path.exists(os.path.join(dest, "src/channel.cc"))
        and os.path.exists(
            os.path.join(dest, "src/collectives/all_reduce.cc")
        )
        and os.path.exists(os.path.join(dest, "src/include/core.h"))
    ):
        return True
    copied_pytorch = (
        repository
        and repository not in {
            "pytorch/pytorch",
            "msft-mirror-aosp/platform.external.pytorch",
        }
        and os.path.exists(os.path.join(dest, "aten/src/ATen/ATen.h"))
        and os.path.exists(os.path.join(dest, "torch/CMakeLists.txt"))
        and os.path.exists(os.path.join(dest, "caffe2/CMakeLists.txt"))
    )
    if copied_pytorch:
        first = normalized.split("/", 1)[0].casefold()
        if first in {
            "aten", "c10", "caffe2", "torch", "cmake", "tools",
        } or normalized.casefold() in {
            "cmakelists.txt", "build_variables.bzl",
        }:
            return True
        package = normalized.split("/", 1)[0]
        if (
            normalized.casefold().endswith(
                "/distributed/_symmetric_memory/_nvshmem_triton.py"
            )
            or os.path.exists(
                os.path.join(
                    dest,
                    package,
                    "distributed/_symmetric_memory/"
                    "_nvshmem_triton.py",
                )
            )
        ) and os.path.exists(
            os.path.join(dest, package, "_C/_distributed_c10d.pyi")
        ) and os.path.exists(
            os.path.join(dest, package, "utils/cpp_extension.py")
        ):
            return first == package.casefold()
    parts = normalized.split("/")
    for index, part in enumerate(parts):
        if part.casefold() != "transformer_engine":
            continue
        root = "/".join(parts[:index])
        common = os.path.join(
            dest, root, "transformer_engine", "common"
        )
        if (
            os.path.exists(os.path.join(common, "CMakeLists.txt"))
            and os.path.exists(os.path.join(common, "common.h"))
            and os.path.exists(
                os.path.join(common, "comm_gemm", "comm_gemm.cpp")
            )
            and os.path.exists(os.path.join(common, "util", "logging.h"))
        ):
            return True
    d = os.path.dirname(path)
    while d and d not in (".", "/"):
        for m in _PROJ_MANIFESTS:
            if os.path.exists(os.path.join(dest, d, m)):
                parts = {
                    part.casefold()
                    for part in d.replace("\\", "/").split("/")
                    if part
                }
                return bool(parts.intersection(_COPY_CONTAINER_PARTS))
        d = os.path.dirname(d)
    return False


def _without_cpp_comments(source):
    """Remove C/C++ comments while preserving strings and line boundaries.

    A regex-only ``//`` removal corrupts URLs and comment-shaped text inside
    string literals.  This small lexer keeps those literals intact, replaces
    comment bytes with spaces, and preserves newlines so preprocessor directives
    can still be recognized only at the beginning of a real source line.
    """
    output = []
    index = 0
    state = "code"
    quote = None
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                output.append(char)
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block_comment":
            if char == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if state == "string":
            output.append(char)
            if char == "\\" and following:
                output.append(following)
                index += 2
                continue
            if char == quote:
                state = "code"
                quote = None
            index += 1
            continue
        if char == "/" and following == "/":
            output.extend((" ", " "))
            index += 2
            state = "line_comment"
            continue
        if char == "/" and following == "*":
            output.extend((" ", " "))
            index += 2
            state = "block_comment"
            continue
        output.append(char)
        if char in ("'", '"'):
            state = "string"
            quote = char
        index += 1
    return "".join(output)


def _exact_cpp_header_pattern(headers):
    """Return an exact include-basename regex for configured header names."""
    normalized = [
        str(header).replace("\\", "/").strip("/")
        for header in headers
        if str(header).strip("/")
    ]
    if not normalized:
        return None
    return "(?:%s)" % "|".join(
        re.escape(header) for header in dict.fromkeys(normalized)
    )


def _source_has_cpp_include(source, header_pattern):
    """Whether source contains an uncommented, syntactic matching include."""
    if not source or not header_pattern:
        return False
    pattern = re.compile(
        r"(?m)^[ \t]*#[ \t]*include[ \t]*[<\"]"
        r"(?:[^>\"]*/)?(?:%s)[>\"]" % header_pattern,
        re.IGNORECASE,
    )
    return pattern.search(_without_cpp_comments(source)) is not None


def _cpp_include_files(dest, paths, header_pattern):
    """Filter a broad grep shortlist to exact, uncommented include evidence."""
    return [
        path
        for path in paths
        if _source_has_cpp_include(
            _read_source_text(dest, path), header_pattern
        )
    ]


def _commit_blob_texts(dest, commit, paths):
    """Read named commit blobs in bounded batches without per-path Git calls."""
    ordered_paths = list(dict.fromkeys(paths))
    for index in range(0, len(ordered_paths), 128):
        batch = ordered_paths[index:index + 128]
        listing = _git(
            dest,
            "ls-tree",
            "-z",
            "--full-tree",
            commit,
            "--",
            *batch,
        )
        blobs = {}
        for record in listing.split("\0"):
            if not record or "\t" not in record:
                continue
            metadata, path = record.split("\t", 1)
            fields = metadata.split()
            if (
                len(fields) == 3
                and fields[0].startswith("100")
                and fields[1] == "blob"
            ):
                blobs[path] = fields[2]
        ordered_oids = list(dict.fromkeys(
            blobs[path] for path in batch if path in blobs
        ))
        if not ordered_oids:
            continue
        request = (
            "".join(oid + "\n" for oid in ordered_oids)
        ).encode("ascii")
        response = _run_command_bytes(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "-c",
                "core.commitGraph=false",
                "-c",
                "maintenance.auto=false",
                "-C",
                dest,
                "cat-file",
                "--batch",
            ],
            GIT_TIMEOUT,
            input_bytes=request,
            env=_git_auth_env(),
        )
        if response.returncode:
            detail = response.stderr.decode(
                "utf-8", errors="replace"
            ).strip()
            raise _RepoScanFailure(
                "git cat-file --batch failed: %s"
                % (detail[:240] or "exit %d" % response.returncode)
            )
        cursor = 0
        text_by_oid = {}
        for expected_oid in ordered_oids:
            line_end = response.stdout.find(b"\n", cursor)
            if line_end < 0:
                raise _RepoScanFailure(
                    "git cat-file --batch response is incomplete"
                )
            header = response.stdout[cursor:line_end].decode(
                "ascii", errors="replace"
            ).split()
            if (
                len(header) != 3
                or header[0] != expected_oid
                or header[1] != "blob"
            ):
                raise _RepoScanFailure(
                    "git cat-file --batch returned an unexpected object"
                )
            try:
                size = int(header[2])
            except ValueError as exc:
                raise _RepoScanFailure(
                    "git cat-file --batch returned an invalid size"
                ) from exc
            start = line_end + 1
            end = start + size
            if end >= len(response.stdout) or response.stdout[end:end + 1] != b"\n":
                raise _RepoScanFailure(
                    "git cat-file --batch blob is incomplete"
                )
            text_by_oid[expected_oid] = response.stdout[start:end].decode(
                "utf-8", errors="replace"
            )
            cursor = end + 1
        if cursor != len(response.stdout):
            raise _RepoScanFailure(
                "git cat-file --batch returned trailing data"
            )
        for path in batch:
            oid = blobs.get(path)
            if oid in text_by_oid:
                yield path, text_by_oid[oid]


def _commit_has_cpp_include(dest, commit, paths, header_pattern):
    """Verify matching include syntax in the named paths at one commit."""
    for _path, text in _commit_blob_texts(dest, commit, paths):
        if _source_has_cpp_include(text, header_pattern):
            return True
    return False


def _cpp_header_first_use(dest, paths, header_pattern):
    """Find the first commit whose snapshot has a real matching include.

    Inspect complete path history rather than only header-token pickaxe hits.
    Removing surrounding ``/* ... */`` markers can activate an unchanged include
    line, so a token-only pickaxe cannot prove the adoption boundary.
    """
    commits = {}
    encounter_order = 0
    for index in range(0, len(paths), 128):
        batch = paths[index:index + 128]
        history = _git(
            dest,
            "log",
            "--reverse",
            "--format=%aI" + _UNIT + "%H",
            "--",
            *batch,
        )
        for line in history.splitlines():
            if _UNIT not in line:
                continue
            date, commit = line.split(_UNIT, 1)
            prior = commits.get(commit)
            if prior is None:
                commits[commit] = (date, encounter_order)
                encounter_order += 1
            elif date < prior[0]:
                commits[commit] = (date, prior[1])
    for date, _order, commit in sorted(
        (
            (date, order, commit)
            for commit, (date, order) in commits.items()
        ),
        key=lambda item: (item[0], item[1]),
    ):
        if _commit_has_cpp_include(
            dest, commit, paths, header_pattern
        ):
            return date, commit
    return None


def _notebook_commit_has_term(dest, commit, paths, term, is_confirmed):
    """Test historical notebook source, excluding output and metadata."""
    folded_term = term.casefold()
    for path, raw in _commit_blob_texts(dest, commit, paths):
        # An unrelated malformed notebook cannot affect this detector. Once
        # the serialized blob contains the term, parsing is required to
        # distinguish source from output and metadata.
        if folded_term not in raw.casefold():
            continue
        try:
            search_text, code_text = _notebook_source_surfaces(raw)
        except (TypeError, ValueError) as exc:
            raise _RepoScanFailure(
                "could not parse evidence-bearing historical notebook "
                "%s at %s" % (path, commit[:12])
            ) from exc
        surface = code_text if is_confirmed else search_text
        if folded_term in surface.casefold():
            return True
    return False


def _latest_addition_commits(dest, paths):
    """Map each path to its most recent add commit using bounded Git walks."""
    result = {}
    ordered = list(dict.fromkeys(paths))
    for index in range(0, len(ordered), 128):
        batch = ordered[index:index + 128]
        history = _git(
            dest,
            "log",
            "--no-renames",
            "--diff-filter=A",
            "--raw",
            "-z",
            "--format=%x1e%H%x00",
            "--",
            *batch,
        )
        for record in history.split("\x1e"):
            if not record:
                continue
            tokens = record.split("\0")
            commit = tokens[0].strip()
            if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                continue
            cursor = 1
            while cursor < len(tokens):
                metadata = tokens[cursor].lstrip("\n")
                cursor += 1
                if not metadata:
                    continue
                if not metadata.startswith(":") or cursor >= len(tokens):
                    continue
                path = tokens[cursor]
                cursor += 1
                status = metadata.rsplit(" ", 1)[-1]
                if status == "A" and path in batch:
                    result.setdefault(path, commit)
    return result


def _rename_predecessors(dest, commit, similarity):
    """Return the first rename/copy predecessor for each new path."""
    # A root commit has no predecessor by definition. Asking diff-tree to run
    # similarity detection across a very large initial tree can consume the
    # full per-command budget even though the only correct answer is empty.
    # Prove parentage first; non-root and merge commits retain the exact
    # existing rename/copy analysis.
    parent_row = _git(
        dest,
        "rev-list",
        "--parents",
        "-n",
        "1",
        commit,
    ).split()
    if (
        len(parent_row) == 1
        and parent_row[0].casefold() == str(commit).casefold()
    ):
        return {}
    changes = _git(
        dest,
        "diff-tree",
        "--root",
        "-r",
        "-m",
        "--no-commit-id",
        "--name-status",
        "-z",
        "--find-renames=%s" % similarity,
        commit,
        # Edited-rename similarity can legitimately hydrate historical blobs
        # from a partial clone. A production case completed in 357 seconds:
        # longer than the generic Git cap, but within the reviewed 540-second
        # repository wall. Keep only that correctness-sensitive operation
        # bounded at 420 seconds; _remaining_timeout still makes the enclosing
        # repository deadline authoritative.
        timeout=(420 if similarity == "50%" else GIT_TIMEOUT),
    ).split("\0")
    result = {}
    cursor = 0
    while cursor < len(changes):
        status = changes[cursor]
        cursor += 1
        if not status:
            continue
        if status[0] in ("R", "C"):
            if cursor + 1 >= len(changes):
                break
            old_path = changes[cursor]
            new_path = changes[cursor + 1]
            cursor += 2
            result.setdefault(new_path, old_path)
        else:
            cursor += 1
    return result


def _notebook_first_use(dest, term, paths, is_confirmed):
    """Find the earliest source-bearing notebook commit.

    Raw ``git log -S/-G`` cannot distinguish executable/markdown source from
    saved outputs. Use ``-G`` only to shortlist term-related commits, then
    verify each snapshot's sanitized notebook surface. A complete path-history
    fallback protects unusual formatting/diff cases without ever dating from
    output-only content.
    """
    def history_candidates(term_related):
        found = {}
        for index in range(0, len(paths), 128):
            batch = paths[index:index + 128]
            command = [
                "log",
                "--reverse",
                "--format=%aI" + _UNIT + "%H",
            ]
            if term_related:
                command.extend(["-i", "-G", re.escape(term)])
            command.extend(["--", *batch])
            for line in _git(dest, *command).splitlines():
                if _UNIT not in line:
                    continue
                date, commit = line.split(_UNIT, 1)
                prior = found.get(commit)
                if prior is None or date < prior:
                    found[commit] = date
        return sorted(
            ((date, commit) for commit, date in found.items()),
            key=lambda item: (item[0], item[1]),
        )

    inspected = set()
    for term_related in (True, False):
        for date, commit in history_candidates(term_related):
            if commit in inspected:
                continue
            inspected.add(commit)
            if _notebook_commit_has_term(
                dest, commit, paths, term, is_confirmed
            ):
                return date, commit
    return None


def _date_first_use(
    dest,
    term,
    paths,
    is_confirmed,
    confirmed_cpp_header_pattern=None,
):
    """Date the first appearance of `term` across `paths`, and (for confirmed)
    detect AI on that commit. Falls back to the first commit that ADDED the
    matched files (then any commit touching them) when the `-S` pickaxe finds
    nothing — so a confirmed/declared row is NEVER left undated (TD-14): handles
    notebooks, copied/odd histories, and paths the pickaxe can't trace.
    Confirmed C/C++ header evidence instead verifies each historical snapshot's
    uncommented include syntax; a commented include can never establish adoption.
    Pathspec is bounded to avoid ARG_MAX / pathological slowness (TD-4).
    Returns (date|None, hash|None, ai_on_integration:bool, agents:list)."""
    # Keep argv bounded without dropping evidence. High-volume libraries can
    # legitimately have thousands of current evidence paths.
    all_paths = list(dict.fromkeys(paths))
    first_date = first_hash = None

    def _candidate(command):
        output = _git(dest, *command)
        line = next((value for value in output.splitlines() if value.strip()), "")
        if _UNIT not in line:
            return None
        date, commit = line.split(_UNIT, 1)
        return date, commit

    candidates = []
    # Build rename-aware lineage without ``git log --follow``. On a partial
    # clone, --follow performs similarity detection across every commit and can
    # trigger an enormous historical-blob fetch for asset-heavy repositories.
    # Instead, find the commit where each current path most recently appeared
    # as an add, then run Git's normal 50%-similarity rename detection only on
    # that boundary commit. Repeat for the predecessor path. This preserves
    # rename+edit semantics while making work proportional to actual renames,
    # not repository history times evidence-path count.
    lineage = list(all_paths)
    notebook_lineage = {
        path for path in all_paths if path.lower().endswith(".ipynb")
    }
    chains = [
        {
            "current": path,
            "notebook": path.lower().endswith(".ipynb"),
            "seen": {path},
        }
        for path in all_paths
    ]
    rename_cache = {}
    while chains:
        additions = _latest_addition_commits(
            dest, [chain["current"] for chain in chains]
        )
        commits = sorted(set(additions.values()))
        for commit in commits:
            exact = _rename_predecessors(dest, commit, "100%")
            needed = {
                chain["current"]
                for chain in chains
                if additions.get(chain["current"]) == commit
                and chain["current"] not in exact
            }
            edited = (
                _rename_predecessors(dest, commit, "50%")
                if needed
                else {}
            )
            rename_cache[commit] = (exact, edited)
        next_chains = []
        for chain in chains:
            current_path = chain["current"]
            addition_commit = additions.get(current_path)
            if not addition_commit:
                continue
            exact, edited = rename_cache[addition_commit]
            predecessor = (
                exact.get(current_path) or edited.get(current_path)
            )
            if not predecessor or predecessor in chain["seen"]:
                continue
            chain["seen"].add(predecessor)
            if predecessor not in lineage:
                lineage.append(predecessor)
            if chain["notebook"]:
                # A notebook can be renamed from an extensionless/JSON path;
                # its whole lineage still requires notebook-aware dating.
                notebook_lineage.add(predecessor)
            chain["current"] = predecessor
            next_chains.append(chain)
        chains = next_chains
    normal_lineage = [
        path for path in lineage if path not in notebook_lineage
    ]
    normal_batches = [
        normal_lineage[index : index + 128]
        for index in range(0, len(normal_lineage), 128)
    ]
    normal_candidates = []
    if (
        is_confirmed
        and confirmed_cpp_header_pattern
        and normal_lineage
    ):
        value = _cpp_header_first_use(
            dest,
            normal_lineage,
            confirmed_cpp_header_pattern,
        )
        if value is not None:
            normal_candidates.append(value)
    else:
        for batch in normal_batches:
            value = _candidate([
                "log", "-S", term, "--reverse",
                "--format=%aI" + _UNIT + "%H", "--", *batch,
            ])
            if value is None:
                value = _candidate([
                    "log", "-G", re.escape(term), "--reverse",
                    "--format=%aI" + _UNIT + "%H", "--", *batch,
                ])
            if value is not None:
                normal_candidates.append(value)
    if (
        not normal_candidates
        and normal_batches
        and not (is_confirmed and confirmed_cpp_header_pattern)
    ):
        # 3) last resort (history the pickaxes can't trace): first commit that
        #    ADDED the matched file, then any commit touching it.
        for extra in (["--diff-filter=A"], []):
            fallback_candidates = []
            for batch in normal_batches:
                fb = _git(
                    dest,
                    "log",
                    "--reverse",
                    "--format=%aI" + _UNIT + "%H",
                    *extra,
                    "--",
                    *batch,
                )
                fb_line = next(
                    (line for line in fb.splitlines() if line.strip()), ""
                )
                if _UNIT in fb_line:
                    fallback_candidates.append(
                        tuple(fb_line.split(_UNIT, 1))
                    )
            if fallback_candidates:
                normal_candidates.append(min(fallback_candidates))
                break
    candidates.extend(normal_candidates)
    if notebook_lineage:
        notebook_candidate = _notebook_first_use(
            dest,
            term,
            sorted(notebook_lineage),
            is_confirmed,
        )
        if notebook_candidate is not None:
            candidates.append(notebook_candidate)
    if candidates:
        first_date, first_hash = min(
            candidates, key=lambda item: (item[0], item[1])
        )
    ai_on_integ, integ_agents = False, []
    if first_hash and is_confirmed:
        rec = _git(dest, "log", "-1", "--format=%an" + _UNIT + "%ae" + _UNIT + "%B", first_hash)
        parts = (rec.split(_UNIT, 2) + ["", "", ""])[:3]
        integ_agents = sorted(_ai_match_fields(parts[0], parts[1], parts[2]))
        ai_on_integ = bool(integ_agents)
    return (first_date[:10] if first_date else None), (first_hash or None), ai_on_integ, integ_agents


def _dating_branch(term, paths, is_confirmed, cpp_header_pattern=None):
    """Return a canonical, JSON-safe description of one dating traversal."""
    return {
        "term": str(term or ""),
        "paths": sorted({
            str(path) for path in paths
            if isinstance(path, str) and path
        }),
        "confirmed": bool(is_confirmed),
        "cpp_header_pattern": (
            str(cpp_header_pattern)
            if cpp_header_pattern is not None
            else None
        ),
    }


def _dating_plan_signature(branches):
    """Fingerprint every current evidence anchor/path in a first-use plan.

    A prior boundary is reusable only when this whole signature is unchanged.
    Adding or removing an evidence path/anchor therefore forces complete
    historical dating instead of risking an earlier integration undercount.
    """
    canonical = sorted(
        (
            _dating_branch(
                branch.get("term"),
                branch.get("paths", ()),
                branch.get("confirmed"),
                branch.get("cpp_header_pattern"),
            )
            for branch in branches
        ),
        key=lambda item: (
            item["term"],
            item["paths"],
            item["confirmed"],
            item["cpp_header_pattern"] or "",
        ),
    )
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unique_dating_branches(branches):
    unique = []
    seen = set()
    for branch in branches:
        normalized = _dating_branch(
            branch.get("term"),
            branch.get("paths", ()),
            branch.get("confirmed"),
            branch.get("cpp_header_pattern"),
        )
        key = json.dumps(
            normalized, sort_keys=True, separators=(",", ":")
        )
        if key not in seen:
            seen.add(key)
            unique.append(normalized)
    return unique


def _integration_ai(dest, commit, is_confirmed):
    if not commit or not is_confirmed:
        return False, []
    rec = _git(
        dest,
        "log",
        "-1",
        "--format=%an" + _UNIT + "%ae" + _UNIT + "%B",
        commit,
    )
    parts = (rec.split(_UNIT, 2) + ["", "", ""])[:3]
    agents = sorted(_ai_match_fields(parts[0], parts[1], parts[2]))
    return bool(agents), agents


def _boundary_evidence_present(dest, commit, branch, *, exact_path=None):
    """Return an exact current-plan path carrying the anchor at `commit`."""
    paths = list(branch.get("paths") or ())
    if exact_path is not None:
        if exact_path not in paths:
            return None
        paths = [exact_path]
    term = branch.get("term") or ""
    pattern = branch.get("cpp_header_pattern")
    confirmed = bool(branch.get("confirmed"))
    try:
        rows = _commit_blob_texts(dest, commit, paths)
        for path, raw in rows:
            if pattern:
                if _source_has_cpp_include(raw, pattern):
                    return path
                continue
            if path.lower().endswith(".ipynb"):
                if term.casefold() not in raw.casefold():
                    continue
                try:
                    search_text, code_text = _notebook_source_surfaces(raw)
                except (TypeError, ValueError):
                    continue
                surface = code_text if confirmed else search_text
                if term.casefold() in surface.casefold():
                    return path
                continue
            if term in raw:
                return path
    except _RepoScanFailure:
        return None
    return None


def _first_use_boundary(dest, dated, branch, plan_signature):
    """Persist the minimum proof needed to validate append-only reuse."""
    first_date, first_commit, _ai, _agents = dated
    if (
        not isinstance(first_commit, str)
        or not re.fullmatch(r"[0-9a-fA-F]{40}", first_commit)
        or not first_date
    ):
        return None
    evidence_path = _boundary_evidence_present(
        dest, first_commit, branch
    )
    if evidence_path is None:
        # A dated row without a reproducible boundary must remain publishable,
        # but it cannot become an optimization input on the next HEAD.
        return None
    return {
        "version": 1,
        "commit": first_commit.lower(),
        "date": str(first_date)[:10],
        "plan_signature": plan_signature,
        "anchor": branch["term"],
        "evidence_path": evidence_path,
        "confirmed": bool(branch["confirmed"]),
        "cpp_header_pattern": branch.get("cpp_header_pattern"),
    }


def _reuse_first_use_boundary(dest, prior, branches, plan_signature):
    """Validate and return a prior append-only first-use result, or None."""
    if not isinstance(prior, dict) or prior.get("version") != 1:
        return None
    commit = prior.get("commit")
    date = prior.get("date")
    if (
        not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not isinstance(date, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date)
        or prior.get("plan_signature") != plan_signature
    ):
        return None
    matching = _unique_dating_branches([
        branch for branch in branches
        if (
            branch.get("term") == prior.get("anchor")
            and bool(branch.get("confirmed"))
            == bool(prior.get("confirmed"))
            and branch.get("cpp_header_pattern")
            == prior.get("cpp_header_pattern")
            and prior.get("evidence_path") in branch.get("paths", ())
        )
    ])
    if len(matching) != 1:
        return None
    try:
        merge_base = _git(dest, "merge-base", commit, "HEAD").strip()
        if merge_base.lower() != commit:
            return None
        author_date = _git(
            dest, "show", "-s", "--format=%aI", commit
        ).strip()
    except _RepoScanFailure:
        return None
    if not author_date or author_date[:10] != date:
        return None
    if _boundary_evidence_present(
        dest,
        commit,
        matching[0],
        exact_path=prior.get("evidence_path"),
    ) is None:
        return None
    ai, agents = _integration_ai(
        dest, commit, bool(matching[0].get("confirmed"))
    )
    return date, commit, ai, agents


def _ai_match_fields(name, email, body):
    """Field-aware AI match (TD-6): `email` signals check ONLY the author email,
    `author` signals the author name+email, and `trailer`/`body` signals the
    commit body — so an `@anthropic.com` / `(aider)` / `noreply@openai.com` string
    appearing in a commit BODY (quoted log, link, etc.) can't be misattributed as
    authorship. Tightens the AI floor without changing genuine detections."""
    author = (name or "") + " " + (email or "")
    body = body or ""
    hits = set()
    for label, kind, rx in AI_SIGNALS:
        target = email if kind == "email" else (author if kind == "author" else body)
        if rx.search(target or ""):
            hits.add(label)
    return hits


def analyze_repository(dest):
    """Return repository-wide publishable analysis for a positive repository.

    REQ-14 intentionally runs this only after at least one detector has positive
    current-tree evidence.  Clean rejects therefore never pay for a full-history
    AI-attribution traversal.
    """
    tracked = [f for f in _git(dest, "ls-files").splitlines() if f]
    ai_config_files = sorted({f for f in tracked if AI_CONFIG_FILE_RE.search(f)})
    raw = _git(dest, "log", "--format=%an" + _UNIT + "%ae" + _UNIT + "%B" + _REC)
    agent_counts = {}
    total_commits = 0
    for rec in raw.split(_REC):
        rec = rec.strip()
        if not rec:
            continue
        total_commits += 1
        parts = (rec.split(_UNIT, 2) + ["", "", ""])[:3]
        for label in _ai_match_fields(parts[0], parts[1], parts[2]):
            agent_counts[label] = agent_counts.get(label, 0) + 1
    return {
        "total_commits": total_commits,
        "ai_agents": agent_counts,
        "ai_config_files": ai_config_files,
    }


def _warp_api_terms(dest, paths):
    """Return current executable Warp API terms for accurate first-use dating."""
    terms = {}
    fallback = re.compile(
        r"\b(?:warp|wp)\s*\.\s*(?:"
        + "|".join(re.escape(value) for value in sorted(WARP_API_ANCHORS))
        + r")\b"
    )
    for path in paths:
        source = (
            _notebook_code_text(os.path.join(dest, path))
            if path.endswith(".ipynb")
            else _read_source_text(dest, path)
        ) or ""
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            for match in fallback.finditer(source):
                terms.setdefault(
                    re.sub(r"\s+", "", match.group(0)), []
                ).append(path)
            continue
        aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                aliases.update(
                    alias.asname or "warp"
                    for alias in node.names
                    if alias.name == "warp"
                )
            elif isinstance(node, ast.ImportFrom) and node.module == "warp":
                for alias in node.names:
                    if alias.name in WARP_API_ANCHORS:
                        # The imported API and the Warp import enter in the same
                        # statement, so the module-qualified import phrase is a
                        # collision-resistant dating anchor.
                        terms.setdefault("warp import " + alias.name, []).append(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            parts.reverse()
            if not isinstance(current, ast.Name) or current.id not in aliases:
                continue
            anchor = next(
                (part for part in parts if part in WARP_API_ANCHORS),
                None,
            )
            if anchor is not None:
                terms.setdefault(
                    current.id + "." + anchor, []
                ).append(path)
    return {
        term: sorted(set(matched))
        for term, matched in terms.items()
    }


def direct_result_from_files(
    dest,
    lib,
    files,
    *,
    prior_boundaries=None,
    require_reuse=False,
):
    """Build a confirmed-only result from one-pass exact direct evidence."""
    files = sorted(set(files))
    if not files:
        return None
    py_files = []
    if lib.get("language") == "python":
        py_files = [path for path in files if path.lower().endswith((".py", ".ipynb"))]
        language = "Python" if py_files else (
            "CUDA" if any(path.lower().endswith((".cu", ".cuh")) for path in files)
            else "C++"
        )
        namespaces = list(lib.get("import_namespaces") or (lib["import_namespace"],))
        term = namespaces[0] if py_files else _header_stem(
            dest, files, lib.get("cpp_headers") or [lib.get("header") or lib["token"]]
        )
    else:
        language = (
            "CUDA" if any(path.lower().endswith((".cu", ".cuh")) for path in files)
            else "C++"
        )
        term = _header_stem(
            dest, files, lib.get("cpp_headers") or [lib.get("header") or lib["token"]]
        )
    # Multi-anchor libraries must be dated from the earliest anchor actually
    # present, not whichever header/namespace happens to be listed first in
    # configuration.
    anchor_paths = {}
    if lib.get("language") == "python":
        if lib.get("id") == "warp":
            anchor_paths.update(_warp_api_terms(dest, py_files))
        else:
            for namespace in namespaces:
                matched = []
                for path in py_files:
                    imported, _referenced = _python_namespace_evidence(
                        os.path.join(dest, path),
                        (namespace,),
                        allow_qualified_call=False,
                        notebook=path.endswith(".ipynb"),
                    )
                    if imported:
                        matched.append(path)
                if matched:
                    anchor_paths[namespace] = matched
    headers = list(lib.get("cpp_headers") or ())
    if lib.get("header"):
        headers.append(lib["header"])
    for header in dict.fromkeys(value for value in headers if value):
        header_pattern = _exact_cpp_header_pattern((header,))
        matched = []
        for path in files:
            if path in py_files:
                continue
            source = _read_source_text(dest, path)
            if _source_has_cpp_include(source, header_pattern):
                matched.append(path)
        if matched:
            anchor_paths[header] = matched
    branches = [
        _dating_branch(
            anchor,
            matched_paths,
            True,
            (
                _exact_cpp_header_pattern((anchor,))
                if anchor in headers
                else None
            ),
        )
        for anchor, matched_paths in sorted(anchor_paths.items())
    ]
    fallback_branch = _dating_branch(
        term,
        files,
        True,
        (
            _exact_cpp_header_pattern(headers)
            if headers and not py_files
            else None
        ),
    )
    all_branches = _unique_dating_branches(
        [*branches, fallback_branch]
    )
    # Include the fallback in the signature even when current anchors date
    # successfully. A configuration/path change that could alter fallback
    # semantics must invalidate the old proof.
    plan_signature = _dating_plan_signature(all_branches)
    reused = _reuse_first_use_boundary(
        dest,
        (prior_boundaries or {}).get("primary"),
        all_branches,
        plan_signature,
    )
    selected_branch = None
    if reused is not None:
        first_date, first_hash, ai_on_integ, integ_agents = reused
        selected_branch = next(
            branch
            for branch in all_branches
            if (
                branch["term"]
                == (prior_boundaries or {})["primary"]["anchor"]
                and (prior_boundaries or {})["primary"]["evidence_path"]
                in branch["paths"]
            )
        )
    else:
        if require_reuse:
            raise FirstUseReuseUnavailable(
                "direct first-use boundary is not safely reusable"
            )
        dated = [
            (_date_first_use(
                dest,
                branch["term"],
                branch["paths"],
                branch["confirmed"],
                branch["cpp_header_pattern"],
            ), branch)
            for branch in branches
        ]
        dated = [
            (value, branch)
            for value, branch in dated
            if value[0]
        ]
        if dated:
            (
                first_date,
                first_hash,
                ai_on_integ,
                integ_agents,
            ), selected_branch = min(
                dated,
                key=lambda item: (
                    item[0][0], item[0][1] or ""
                ),
            )
        else:
            selected_branch = fallback_branch
            (
                first_date,
                first_hash,
                ai_on_integ,
                integ_agents,
            ) = _date_first_use(
                dest,
                fallback_branch["term"],
                fallback_branch["paths"],
                fallback_branch["confirmed"],
                fallback_branch["cpp_header_pattern"],
            )
    components = lib.get("components")
    if components:
        operators = _extract_components(dest, files, components) or ["SDK (unspecified)"]
    elif lib.get("direct_only"):
        # REQ-14 direct detectors have no reviewed operator vocabulary. The
        # generic MathDx descriptor extractor can collide with ordinary C++
        # template names in unrelated SDK integrations.
        operators = []
    elif lib.get("language") == "python":
        operators = []
    else:
        operators = _extract_cpp_operators(dest, files)
    result = {
        "classification": "confirmed",
        "language": language,
        "first_integration": first_date,
        "first_integration_commit": (first_hash or "")[:12],
        "own_source_files": files[:25],
        "own_source_file_count": len(files),
        "vendored_present": False,
        "ai_on_integration_commit": ai_on_integ,
        "ai_on_integration_agents": integ_agents,
        "operators": operators,
    }
    boundary = _first_use_boundary(
        dest,
        (
            first_date,
            first_hash,
            ai_on_integ,
            integ_agents,
        ),
        selected_branch,
        plan_signature,
    )
    if boundary is not None:
        result["_first_use_boundaries"] = {"primary": boundary}
    return result


def _notebook_source_surfaces(raw):
    """Return notebook (code+markdown, code-only) text without saved outputs.

    Both nbformat v4 and v3 are accepted. Malformed notebooks raise so callers
    that are establishing evidence can fail closed rather than turn serialized
    output or metadata into adoption.
    """
    try:
        surfaces = parse_notebook_surfaces(raw)
    except NotebookEvidenceError as exc:
        # Keep the long-standing public exception type and message contract;
        # the shared parser supplies those legacy structural messages.
        raise ValueError(str(exc)) from exc
    return surfaces.search_text, surfaces.code_text


# Jupyter notebooks (.ipynb) are JSON, not plain source. Direct/confirmed
# evidence is executable code only; mature targeted evidence separately uses
# the code+markdown surface from the one-pass inventory.
def _notebook_code_text(abspath):
    if not _is_regular_nonsymlink(abspath):
        return None
    try:
        inventory_code, code_present = _inventory_notebook_code(
            abspath
        )
        if code_present:
            return inventory_code
        inventory_source, present = _inventory_text(abspath)
        if present:
            if inventory_source is None:
                return None
            return _notebook_source_surfaces(inventory_source)[1]
        else:
            with open(abspath, "rb") as fh:
                return _notebook_source_surfaces(fh.read())[1]
    except (OSError, TypeError, ValueError):
        return None


def _clean_executable_python(source):
    """Remove complete notebook magic/shell lines while preserving line shape."""
    return "\n".join(
        "" if line.lstrip().startswith(("%", "!")) else line
        for line in (source or "").splitlines()
    )


def _python_import_modules(source):
    """Return modules imported by executable Python syntax.

    Static imports and literal ``__import__(...)`` calls use one authority for
    triage and mature classification.  The tokenizer fallback retains
    Python-2-era and partial-but-executable import statements without
    promoting comments, docstrings or ordinary string literals.
    """
    cleaned = _clean_executable_python(source)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(cleaned)
    except (SyntaxError, ValueError):
        tree = None

    modules = set()
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.lower() for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                parent = node.module.lower()
                modules.add(parent)
                modules.update(
                    parent + "." + alias.name.lower()
                    for alias in node.names
                    if alias.name != "*"
                )
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                modules.add(node.args[0].value.lower())
        return tuple(sorted(modules))

    try:
        raw_tokens = list(
            tokenize.generate_tokens(io.StringIO(cleaned).readline)
        )
    except (tokenize.TokenError, IndentationError):
        return ()
    executable_tokens = [
        token._replace(string="")
        if token.type in (tokenize.COMMENT, tokenize.STRING)
        else token
        for token in raw_tokens
    ]
    executable = tokenize.untokenize(executable_tokens)
    for match in re.finditer(
        r"(?m)^[ \t]*import[ \t]+([^;\n]+)", executable
    ):
        for item in match.group(1).split(","):
            value = re.match(
                r"[ \t]*([A-Za-z_][A-Za-z0-9_.]*)", item
            )
            if value:
                modules.add(value.group(1).lower())
    for match in re.finditer(
        r"(?m)^[ \t]*from[ \t]+([A-Za-z_][A-Za-z0-9_.]*)"
        r"[ \t]+import[ \t]+([^;\n]+)",
        executable,
    ):
        parent = match.group(1).lower()
        modules.add(parent)
        for item in match.group(2).split(","):
            value = re.match(
                r"[ \t]*([A-Za-z_][A-Za-z0-9_]*)", item
            )
            if value:
                modules.add(parent + "." + value.group(1).lower())

    # Dynamic imports remain recognizable from token shape even when an
    # unrelated Python-2 statement prevents AST parsing.
    significant = [
        token for token in raw_tokens
        if token.type not in {
            tokenize.COMMENT, tokenize.ENCODING, tokenize.NL,
            tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
        }
    ]
    for index in range(len(significant) - 2):
        first, second, third = significant[index:index + 3]
        if (
            first.type == tokenize.NAME
            and first.string == "__import__"
            and second.type == tokenize.OP
            and second.string == "("
            and third.type == tokenize.STRING
        ):
            try:
                value = ast.literal_eval(third.string)
            except (SyntaxError, ValueError):
                continue
            if isinstance(value, str):
                modules.add(value.lower())
    return tuple(sorted(modules))


def _python_namespace_evidence_from_source(
    source, namespaces, allow_qualified_call=True
):
    namespaces = tuple(value.lower() for value in namespaces)

    def matches(value):
        value = (value or "").lower()
        return any(
            value == namespace or value.startswith(namespace + ".")
            for namespace in namespaces
        )

    imported = any(
        matches(module) for module in _python_import_modules(source)
    )
    if not allow_qualified_call:
        return imported, False
    cleaned = _clean_executable_python(source)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(cleaned)
    except (SyntaxError, ValueError):
        return imported, False
    referenced = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        parts = []
        cursor = node
        while isinstance(cursor, ast.Attribute):
            parts.append(cursor.attr)
            cursor = cursor.value
        if isinstance(cursor, ast.Name):
            parts.append(cursor.id)
            if matches(".".join(reversed(parts))):
                referenced = True
                break
    return imported, referenced


def _python_namespace_evidence(abspath, namespaces, allow_qualified_call=True,
                               notebook=False):
    """Return ``(imports, references)`` from executable Python syntax only.

    Grep cheaply selects candidate files, but comments, strings, and docstrings
    never become adoption evidence. Notebook magics, literal dynamic imports
    and Python-2-era import syntax share the triage parser above.
    """
    try:
        if notebook:
            source = _notebook_code_text(abspath)
        else:
            if not _is_regular_nonsymlink(abspath):
                return False, False
            inventory_source, present = _inventory_text(abspath)
            if present:
                if inventory_source is None:
                    return False, False
                source = inventory_source
            else:
                with open(abspath, encoding="utf-8", errors="ignore") as handle:
                    source = handle.read()
        if source is None:
            return False, False
    except (OSError, ValueError):
        return False, False
    return _python_namespace_evidence_from_source(
        source, namespaces, allow_qualified_call=allow_qualified_call
    )


def _ipynb_confirms_token(dest, relpath, token):
    """Confirm a raw notebook hit only when executable code contains it."""
    code = _notebook_code_text(os.path.join(dest, relpath))
    if code is None:
        raise _RepoScanFailure(
            "could not parse evidence-bearing notebook: %s" % relpath
        )
    return token in code


def _read_source_text(dest, relpath):
    """Text for operator scanning: a notebook's rejoined CODE-cell source (no JSON
    output/markdown noise, and statements split across the `source` array are
    rejoined so the fn.*/ops.* regex matches), or a plain read otherwise. '' on
    failure."""
    abspath = os.path.join(dest, relpath)
    if not _is_regular_nonsymlink(abspath):
        return ""
    if relpath.endswith(".ipynb"):
        code = _notebook_code_text(abspath)
        if code is not None:
            return code
    inventory_source, present = _inventory_text(abspath)
    if present:
        return (inventory_source or "")[:500000]
    try:
        with open(abspath, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(500000)   # cap per-file read
    except OSError:
        return ""


_DISTRIBUTION_SEPARATOR_RE = re.compile(r"[-_.]+")
_REQUIREMENT_NAME_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)
    (?:\s*\[[A-Za-z0-9._,-]+\])?
    \s*
    (?:
        @\s*\S+
        |
        \(?\s*
        (?:
            (?:===|==|~=|!=|<=|>=|<|>)\s*[^,;()\s]+
            (?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)
                \s*[^,;()\s]+)*
        )
        \s*\)?
    )?
    \s*(?:;\s*.+)?$
    """,
    re.VERBOSE,
)
_CONDA_REQUIREMENT_NAME_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\s*(?:={1,3}|~=|!=|<=|>=|<|>)\s*[^;\s]+)?"
    r"\s*(?:;\s*.+)?$"
)
_GENERATED_EVIDENCE_PATH_RE = re.compile(
    r"(^|/)(generated|autogen|_generated|_build|dist|"
    r"cmake-build[^/]*)/",
    re.IGNORECASE,
)


def _is_generated_evidence_path(path):
    normalized = str(path).replace("\\", "/").strip("/").casefold()
    return bool(
        _GENERATED_EVIDENCE_PATH_RE.search(normalized)
        or any(part in {"cubin", "cubins"} for part in normalized.split("/"))
    )


def _classification_evaluated(lib, classification):
    supplied = lib.get("classification_coverage")
    if supplied is None:
        return True
    return classification in supplied


def _normalize_distribution_name(value):
    return _DISTRIBUTION_SEPARATOR_RE.sub(
        "-", str(value).strip().casefold()
    )


def _requirement_name(value, *, conda=False):
    text = str(value).strip().strip("\"'")
    if not text or text.startswith(("-", "#")):
        return None
    pattern = (
        _CONDA_REQUIREMENT_NAME_RE if conda else _REQUIREMENT_NAME_RE
    )
    match = pattern.match(text)
    if not match:
        return None
    return _normalize_distribution_name(match.group("name"))


def _pyproject_dependency_names(source):
    document = tomllib.loads(source)
    names = set()

    def add(values):
        if isinstance(values, str):
            values = (values,)
        if not isinstance(values, (list, tuple)):
            return
        for value in values:
            if isinstance(value, str):
                name = _requirement_name(value)
                if name:
                    names.add(name)

    project = document.get("project")
    if isinstance(project, dict):
        add(project.get("dependencies"))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                add(values)
    groups = document.get("dependency-groups")
    if isinstance(groups, dict):
        for values in groups.values():
            add(values)
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        for key in ("dependencies", "dev-dependencies"):
            dependencies = poetry.get(key)
            if isinstance(dependencies, dict):
                names.update(
                    _normalize_distribution_name(name)
                    for name in dependencies
                    if str(name).casefold() != "python"
                )
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for group in groups.values():
                dependencies = (
                    group.get("dependencies")
                    if isinstance(group, dict)
                    else None
                )
                if isinstance(dependencies, dict):
                    names.update(
                        _normalize_distribution_name(name)
                        for name in dependencies
                        if str(name).casefold() != "python"
                    )
    return names


def _setup_py_dependency_names(source):
    tree = ast.parse(source)
    assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
                assignments[node.target.id] = node.value

    def dependency_strings(node, seen=frozenset()):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
        ):
            return [node.value]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return [
                item
                for child in node.elts
                for item in dependency_strings(child, seen)
            ]
        if isinstance(node, ast.Dict):
            # Dictionary keys are dependency-group labels, never packages.
            # Values include ``**other_dependency_map`` nodes as well as the
            # ordinary list assigned to a group.
            return [
                item
                for child in node.values
                for item in dependency_strings(child, seen)
            ]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return [
                *dependency_strings(node.left, seen),
                *dependency_strings(node.right, seen),
            ]
        if (
            isinstance(node, ast.Name)
            and node.id in assignments
            and node.id not in seen
        ):
            return dependency_strings(
                assignments[node.id], seen | {node.id}
            )
        return []

    def mapping_values(node, seen=frozenset()):
        if (
            isinstance(node, ast.Name)
            and node.id in assignments
            and node.id not in seen
        ):
            return mapping_values(
                assignments[node.id], seen | {node.id}
            )
        if isinstance(node, ast.Dict):
            values = {}
            for key, value in zip(node.keys, node.values):
                if key is None:
                    values.update(mapping_values(value, seen))
                elif (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                ):
                    values[key.value] = value
            return values
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.BitOr)
        ):
            return {
                **mapping_values(node.left, seen),
                **mapping_values(node.right, seen),
            }
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "dict"
        ):
            values = {}
            for keyword in node.keywords:
                if keyword.arg is None:
                    values.update(mapping_values(keyword.value, seen))
                else:
                    values[keyword.arg] = keyword.value
            return values
        return {}

    def is_setup_call(node):
        if not isinstance(node, ast.Call):
            return False
        return (
            isinstance(node.func, ast.Name)
            and node.func.id == "setup"
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "setup"
        )

    names = set()
    for node in ast.walk(tree):
        if not is_setup_call(node):
            continue
        dependency_values = []
        for keyword in node.keywords:
            if keyword.arg in {"install_requires", "extras_require"}:
                dependency_values.append(keyword.value)
            elif keyword.arg is None:
                mapping = mapping_values(keyword.value)
                dependency_values.extend(
                    mapping[key]
                    for key in ("install_requires", "extras_require")
                    if key in mapping
                )
        for dependency_value in dependency_values:
            for value in dependency_strings(dependency_value):
                name = _requirement_name(value)
                if name:
                    names.add(name)
    return names


def _dependency_names_for_file(path, source):
    """Return exact declared distributions from supported authored manifests."""
    normalized = str(path).replace("\\", "/")
    basename = os.path.basename(normalized).casefold()
    if basename == "pyproject.toml":
        return _pyproject_dependency_names(source)
    if basename == "setup.py":
        return _setup_py_dependency_names(source)
    if basename == "setup.cfg":
        names = set()
        section = ""
        active_key = None
        for raw_line in source.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().casefold()
                active_key = None
                continue
            if section not in {"options", "options.extras_require"}:
                continue
            if "=" in stripped and not raw_line[:1].isspace():
                key, value = stripped.split("=", 1)
                key = key.strip().casefold()
                active_key = (
                    key
                    if (
                        section == "options.extras_require"
                        or key in {
                            "install_requires",
                            "setup_requires",
                            "tests_require",
                        }
                    )
                    else None
                )
                if active_key is None:
                    continue
                stripped = value.strip()
            elif active_key is None:
                continue
            name = _requirement_name(stripped)
            if name:
                names.add(name)
        return names
    if (
        "requirements" in basename
        and basename.endswith((".txt", ".in"))
    ):
        names = set()
        continuation = ""
        for raw_line in source.splitlines():
            line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
            if line.endswith("\\"):
                continuation += line[:-1].rstrip() + " "
                continue
            line = (continuation + line).strip()
            continuation = ""
            # pip-compile hash options pin the same declaration and are not
            # part of its PEP 508 name or version specifier.
            line = re.split(r"\s+--hash(?:=|\s)", line, maxsplit=1)[0]
            name = _requirement_name(line)
            if name:
                names.add(name)
        if continuation.strip():
            name = _requirement_name(continuation.strip())
            if name:
                names.add(name)
        return names
    if (
        "environment" in basename
        and basename.endswith((".yml", ".yaml"))
    ):
        names = set()
        dependency_indent = None
        pip_indent = None
        for raw_line in source.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            indent = len(raw_line) - len(raw_line.lstrip())
            stripped = raw_line.strip()
            if stripped == "dependencies:":
                dependency_indent = indent
                pip_indent = None
                continue
            if dependency_indent is None:
                continue
            if indent <= dependency_indent:
                dependency_indent = None
                pip_indent = None
                continue
            if not stripped.startswith("-"):
                continue
            value = stripped[1:].strip()
            if value == "pip:":
                pip_indent = indent
                continue
            if pip_indent is not None and indent > pip_indent:
                name = _requirement_name(value)
            else:
                pip_indent = None
                name = _requirement_name(value, conda=True)
            if name:
                names.add(name)
        return names
    if basename == "pipfile":
        document = tomllib.loads(source)
        names = set()
        for section in ("packages", "dev-packages"):
            declared = document.get(section)
            if not isinstance(declared, dict):
                continue
            names.update(
                _normalize_distribution_name(name)
                for name in declared
            )
        return names
    if basename.startswith("dockerfile"):
        names = set()
        logical = source.replace("\\\n", " ")
        for match in re.finditer(
            r"(?:python(?:\d+(?:\.\d+)?)?\s+-m\s+pip|pip(?:\d+)?)"
            r"\s+install\s+([^\n;&|]+)",
            logical,
            re.IGNORECASE,
        ):
            try:
                values = shlex.split(match.group(1), comments=True)
            except ValueError:
                values = match.group(1).split()
            skip_next = False
            for value in values:
                if skip_next:
                    skip_next = False
                    continue
                if value in {
                    "-c", "--constraint", "-e", "--editable",
                    "-f", "--find-links", "-i", "--index-url",
                    "--extra-index-url", "--proxy", "-r", "--requirement",
                    "--trusted-host",
                }:
                    skip_next = True
                    continue
                if value.startswith("-"):
                    continue
                name = _requirement_name(value)
                if name:
                    names.add(name)
        return names
    return set()


def _tracked_tree_entry(dest, path):
    """Return one exact HEAD entry without following filesystem aliases."""
    listing = _git(
        dest, "ls-tree", "-z", "--full-tree", "HEAD", "--",
        ":(literal)" + path,
    )
    matches = []
    for record in listing.split("\0"):
        if not record or "\t" not in record:
            continue
        metadata, candidate = record.split("\t", 1)
        fields = metadata.split()
        if candidate == path and len(fields) == 3:
            matches.append((fields[0], fields[1], fields[2]))
    if len(matches) != 1:
        raise _RepoScanFailure(
            "dependency/build evidence tree identity is ambiguous: %s" % path
        )
    return matches[0]


def _resolve_tracked_evidence_symlink(dest, path):
    """Resolve an authored, repository-internal dependency-manifest link.

    Git's exact HEAD tree remains the authority. Absolute, escaping, cyclic,
    non-blob, generated, vendored, or local-shadow targets fail closed; no
    worktree-only file can become dependency evidence through a symlink.
    """
    current = str(path).replace("\\", "/").strip("/")
    if not current or current != path:
        raise _RepoScanFailure(
            "dependency/build evidence path is not canonical: %s" % path
        )
    seen = set()
    for _unused in range(16):
        if current in seen:
            raise _RepoScanFailure(
                "dependency/build evidence symlink is cyclic: %s" % path
            )
        seen.add(current)
        mode, object_type, object_id = _tracked_tree_entry(dest, current)
        if mode.startswith("100") and object_type == "blob":
            if (
                _is_env_dump(current)
                or _is_agent_skill(current)
                or _is_generated_evidence_path(current)
                or _is_vendored(current)
                or _in_embedded_project(dest, current)
            ):
                raise _RepoScanFailure(
                    "dependency/build evidence symlink target is excluded: %s"
                    % path
                )
            return current
        if mode != "120000" or object_type != "blob":
            raise _RepoScanFailure(
                "dependency/build evidence is not a regular file: %s" % path
            )
        target = _git(dest, "cat-file", "blob", object_id)
        if (
            not target
            or "\0" in target
            or "\n" in target
            or "\r" in target
            or "\ufffd" in target
            or "\\" in target
            or target.startswith("/")
        ):
            raise _RepoScanFailure(
                "dependency/build evidence symlink target is unsafe: %s" % path
            )
        joined = posixpath.normpath(
            posixpath.join(posixpath.dirname(current), target)
        )
        if joined in {"", ".", ".."} or joined.startswith("../"):
            raise _RepoScanFailure(
                "dependency/build evidence symlink escapes repository: %s" % path
            )
        current = joined
    raise _RepoScanFailure(
        "dependency/build evidence symlink chain is too deep: %s" % path
    )


def _read_evidence_text(dest, path):
    """Read a shortlisted authored manifest completely or fail closed."""
    abspath = os.path.join(dest, path)
    if not _is_regular_nonsymlink(abspath):
        resolved = _resolve_tracked_evidence_symlink(dest, path)
        abspath = os.path.join(dest, resolved)
    inventory_source, present = _inventory_text(abspath)
    if present and inventory_source:
        return inventory_source
    try:
        with open(
            abspath, "r", encoding="utf-8", errors="strict"
        ) as handle:
            return handle.read()
    except (OSError, UnicodeError) as exc:
        raise _RepoScanFailure(
            "could not read dependency/build evidence file: %s" % path
        ) from exc


def _declared_distribution_matches(
    declared, expected, *, allow_mature_cuda_suffixes=False
):
    """Match an authored distribution without restoring substring evidence.

    The retained mature detectors predate REQ-14 and intentionally recognize
    NVIDIA's CUDA-major wheel families (for example ``nvidia-dali-cuda120`` and
    ``custatevec-cu12``).  New REQ-14 certifications are exact allowlists.
    """
    if declared == expected:
        return True
    if not allow_mature_cuda_suffixes:
        return False
    if expected == "nvidia-dali":
        return re.fullmatch(r"nvidia-dali-cuda[0-9]+", declared) is not None
    if expected.endswith("-cu"):
        return re.fullmatch(re.escape(expected) + r"[0-9]+", declared) is not None
    return False


def _reviewed_dependency_files(
    dest, packages, *, allow_mature_cuda_suffixes=False
):
    expected = {
        _normalize_distribution_name(package) for package in packages
    }
    candidates = set()
    for package in packages:
        candidates.update(
            path
            for path in _git(
                dest,
                "grep",
                "--cached",
                "-I",
                "-l",
                "-i",
                "-F",
                "-e",
                package,
                "--",
                *PY_DEP_PATHSPECS,
            ).splitlines()
            if path
        )
    result = []
    for path in sorted(candidates):
        if (
            _is_vendored(path)
            or _is_env_dump(path)
            or _in_embedded_project(dest, path)
            or _GENERATED_EVIDENCE_PATH_RE.search(path)
        ):
            continue
        source = _read_evidence_text(dest, path)
        try:
            declared = _dependency_names_for_file(path, source)
        except (SyntaxError, ValueError, tomllib.TOMLDecodeError) as exc:
            raise _RepoScanFailure(
                "could not parse dependency evidence file: %s" % path
            ) from exc
        if any(
            _declared_distribution_matches(
                name,
                package,
                allow_mature_cuda_suffixes=allow_mature_cuda_suffixes,
            )
            for name in declared
            for package in expected
        ):
            result.append(path)
    return result


def _cmake_without_comments(source):
    source = re.sub(
        r"#\[(=*)\[.*?\]\1\]", "", source, flags=re.DOTALL
    )
    lines = []
    for raw_line in source.splitlines():
        quote = None
        kept = []
        escaped = False
        for character in raw_line:
            if escaped:
                kept.append(character)
                escaped = False
                continue
            if character == "\\":
                kept.append(character)
                escaped = True
                continue
            if character in {"'", '"'}:
                if quote == character:
                    quote = None
                elif quote is None:
                    quote = character
                kept.append(character)
                continue
            if character == "#" and quote is None:
                break
            kept.append(character)
        lines.append("".join(kept))
    return "\n".join(lines)


_CMAKE_COMMAND_RE = re.compile(
    r"(?P<command>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<arguments>.*?)\)",
    re.DOTALL,
)
_CMAKE_LINK_VARIABLE_RE = re.compile(
    r"(?:lib(?:rary|raries|s)?|targets?|cuda|cublas|cufft|curand|"
    r"cusolver|cusparse|cufile|npp|tensorrt|trt|nvinfer)",
    re.IGNORECASE,
)


def _cmake_signal_is_classifying(source, signal_value):
    escaped = re.escape(signal_value)
    boundary = (
        r"(?<![A-Za-z0-9_:])%s(?![A-Za-z0-9_:])"
        if "::" in signal_value
        else r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])"
    ) % escaped
    signal_pattern = re.compile(boundary)
    for match in _CMAKE_COMMAND_RE.finditer(source):
        command = match.group("command").casefold()
        arguments = match.group("arguments")
        if signal_pattern.search(arguments) is None:
            continue
        if command in {
            "target_link_libraries", "link_libraries", "find_library",
        }:
            return True
        tokens = arguments.split()
        if (
            command == "if"
            and tokens
            and tokens[0].casefold() == "target"
        ):
            return True
        if (
            command == "list"
            and len(tokens) >= 2
            and tokens[0].casefold() in {
                "append", "prepend", "insert",
            }
            and _CMAKE_LINK_VARIABLE_RE.search(tokens[1])
        ):
            return True
        if (
            command == "set"
            and tokens
            and _CMAKE_LINK_VARIABLE_RE.search(tokens[0])
        ):
            return True
    return False


def _reviewed_targeted_build_files(dest, lib):
    signals = tuple(lib.get("targeted_build_signals") or ())
    if not signals:
        return [], None
    discovery_anchors = tuple(
        lib.get("targeted_build_discovery_anchors") or signals
    )
    candidates = set()
    for anchor in discovery_anchors:
        candidates.update(
            path
            for path in _git(
                dest,
                "grep",
                "--cached",
                "-I",
                "-l",
                "-F",
                "-e",
                anchor,
                "--",
                "*CMakeLists.txt",
                "*.cmake",
            ).splitlines()
            if path
        )
    matches = []
    first_signal = None
    for path in sorted(candidates):
        if (
            _is_vendored(path)
            or _is_env_dump(path)
            or _in_embedded_project(dest, path)
            or _GENERATED_EVIDENCE_PATH_RE.search(path)
        ):
            continue
        source = _cmake_without_comments(
            _read_evidence_text(dest, path)
        )
        for signal_value in signals:
            if _cmake_signal_is_classifying(source, signal_value):
                matches.append(path)
                first_signal = first_signal or signal_value
                break
    return matches, first_signal


def _has_token_reference(dest, relpath, token):
    """Require a lexical token start for generic mature references.

    CUDA APIs commonly extend a library token with an underscore
    (``nvshmem_malloc``), so the right boundary permits that shape.  The left
    boundary rejects base64/identifier substrings such as ``...UpQc...`` while
    retaining plain prose/config names and API identifiers.
    """
    if (
        not relpath
        or _is_env_dump(relpath)
        or _is_agent_skill(relpath)
        or _is_generated_evidence_path(relpath)
        or _in_embedded_project(dest, relpath)
    ):
        return False
    abspath = os.path.join(dest, relpath)
    inventory_source, present = _inventory_text(abspath)
    if present:
        source = inventory_source or ""
    else:
        if _is_regular_nonsymlink(abspath):
            try:
                with open(
                    abspath, "r", encoding="utf-8", errors="ignore"
                ) as handle:
                    source = handle.read()
            except OSError:
                return False
        else:
            # A sparse checkout can retain the blob in the index/object store
            # without materializing the path in the worktree.
            source = _git(dest, "show", "HEAD:" + relpath)
            if not source:
                return False
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])"
        + re.escape(token)
        + r"(?=$|[^A-Za-z0-9]|_)",
        re.IGNORECASE,
    )
    return pattern.search(source) is not None


# Operator/function usage for Python libraries (REQ-04). Heuristic: in a file
# that imports the library, `fn.<op>` / `ops.<op>` refer to it (DALI convention
# `import nvidia.dali.fn as fn`). Also catches the fully-qualified tail of
# `nvidia.dali.fn.resize`. A string match, not an AST parse — see CAVEATS.
_PY_OP_RE = re.compile(r"\b(?:fn|ops)\.([A-Za-z_][A-Za-z0-9_.]*)")


def _extract_py_operators(dest, files, cap_files=25, cap_ops=40):
    ops = set()
    for f in files[:cap_files]:
        text = _read_source_text(dest, f)
        if not text:
            continue
        for m in _PY_OP_RE.finditer(text):
            ops.add(m.group(0).rstrip("."))   # e.g. "fn.decoders.image"
            if len(ops) >= cap_ops:
                break
    return sorted(ops)


# C++ Dx descriptor vocabulary (REQ-04): the MathDx device libraries are
# configured with template "operator descriptors" — cublasdx::Function<...>,
# Size<...>, Precision<...>, SM<...>, etc. Extracting these from a repo's own
# confirmed source shows WHICH functionality it uses. Heuristic string match
# (not a C++ parse) over files that already #include the Dx header — same
# caveat class as the Python fn.*/ops.* extractor.
_CPP_DESC_RE = re.compile(
    r"\b(Function|Size|Precision|SM|BlockDim|Block|Type|Arrangement|Alignment|"
    r"FFTDirection|Direction|RealFFTOptions|TransposeMode|LeadingDimension|"
    r"MaxAlignment|ElementsPerThread|FunctionId|StaticBlockDim)\s*<([^<>;{}()\n]{0,48})")


def _extract_cpp_operators(dest, files, cap_files=25, cap_ops=40):
    ops = set()
    for f in files[:cap_files]:
        text = _read_source_text(dest, f)
        if not text:
            continue
        for m in _CPP_DESC_RE.finditer(text):
            name, arg = m.group(1), re.sub(r"\s+", "", m.group(2).strip())  # collapse ws so Size<M, N> == Size<M,N>
            ops.add("%s<%s>" % (name, arg) if arg else name)
            if len(ops) >= cap_ops:
                break
    return sorted(ops)


# Component breakdown (cuQuantum, NVPL): which sub-component(s) a repo uses, from
# a signal-substring -> label map in config. A string match over the confirmed
# files' text (C++ header names, Python submodule paths, API prefixes), NOT an AST
# parse — same caveat class as the operator extractors. Distinct from
# _extract_py_operators (DALI fn./ops.) — do not conflate.
def _extract_components(dest, files, comp_map, cap_files=40):
    if not comp_map:
        return []
    found = set()
    keys = sorted(comp_map.keys(), key=len, reverse=True)
    for f in files[:cap_files]:
        low = _read_source_text(dest, f).lower()
        if not low:
            continue
        for k in keys:
            if k.lower() in low:
                found.add(comp_map[k])
    return sorted(found)


# A file that is a framework's optional-backend shim (e.g. ggml's `ggml-blas.cpp`)
# includes the library header only behind a build-vendor switch — its presence is
# NOT evidence the repo uses the library (the backend is usually unselected). Such
# a file never counts as a confirmed own-source integration (NVPL precision guard).
def _is_optional_backend(path, names):
    base = os.path.basename(path).lower()
    return any(n.lower() in base for n in names)


def _header_stem(dest, files, headers):
    """The component-header stem present in `files` (e.g. custatevec.h -> custatevec),
    used to date the C++ side of a dual-surface lib. Falls back to the first header."""
    txt = _git(dest, "grep", "--cached", "-h", "-iE",
               "(" + "|".join(re.escape(h) for h in headers) + ")", "--", *files).lower()
    for h in headers:
        if h.lower() in txt:
            return h.split(".")[0]
    return headers[0].split(".")[0]


def _scan_python_lib(dest, lib, *, include_history=True):
    """Detect a pip-distributed library (DALI, etc.) in a cloned repo.

    confirmed (Integration) = own .py/.ipynb source imports the library namespace.
    "bundled" (shown as "Declared" for Python libs) = a dependency manifest /
    Dockerfile names the pip package but no import was found. targeted = the name
    appears elsewhere. Vendored / env-dump copies never count. Returns the same
    result shape as the C++ path, plus `operators` (REQ-04), or None if absent.
    """
    namespaces = list(lib.get("import_namespaces") or (lib["import_namespace"],))
    ns = namespaces[0]             # primary namespace used for display/dating fallback
    pips = lib["pip_pattern"]      # str (nvidia-dali) or list (cuQuantum component wheels)
    pips = pips if isinstance(pips, list) else [pips]
    cpp_headers = lib.get("cpp_headers", [])   # dual-surface libs (cuQuantum); empty for DALI
    comp_map = lib.get("components")           # component-breakdown map, or None (DALI)

    def _grep(pattern, pathspecs):
        out = _git(
            dest, "grep", "--cached", "-I", "-l", "-F", "-e", pattern,
            "--", *pathspecs
        ).splitlines()
        res = []
        for f in out:
            if not f or _is_vendored(f) or _is_env_dump(f) or _in_embedded_project(dest, f):
                continue
            # For notebooks, require the token in a CODE cell (not output/markdown).
            if f.endswith(".ipynb") and not _ipynb_confirms_token(dest, f, pattern):
                continue
            res.append(f)
        return res

    def _grep_dep_noncomment(patterns):
        # Parse supported dependency manifests and compare normalized
        # distribution names. Substrings, comments, requirements directives,
        # prose, and environment/vendor copies are not declarations.
        return _reviewed_dependency_files(
            dest,
            patterns,
            allow_mature_cuda_suffixes=not lib.get("direct_only"),
        )

    if lib.get("strict_import"):
        # Precision guard (opt-in): confirm only on an IMPORT-SHAPED match — `import <ns>`,
        # `from <ns>`, or `<ns>.<attr>` with a word boundary before <ns> — not a bare
        # substring. Kills the nvpro/nvtt C++ "nvmath" collision (libnvmath.so / nvmath.lib /
        # -lenvmath / "nvmath" in a libs list). DALI/cuQuantum don't set this (no collision).
        escaped = [re.escape(value) for value in namespaces]
        alternatives = "|".join(escaped)
        shapes_g = [
            r"import[[:space:]]+(%s)" % alternatives,
            r"from[[:space:]]+(%s)" % alternatives,
            r"__import__[[:space:]]*\([[:space:]]*['\"](%s)"
            % alternatives,
        ]
        if lib.get("allow_qualified_call", True):
            shapes_g.append(r"(%s)\.[A-Za-z_]" % alternatives)
        imp_g = r"(^|[^A-Za-z0-9_.])(%s)" % "|".join(shapes_g)
        import_files = []
        executable_ref_files = []
        for f in _git(dest, "grep", "--cached", "-I", "-l", "-iE", imp_g, "--", "*.py", "*.ipynb").splitlines():
            if not f or _is_vendored(f) or _is_env_dump(f) or _in_embedded_project(dest, f):
                continue
            imported, referenced = _python_namespace_evidence(
                os.path.join(dest, f),
                namespaces,
                allow_qualified_call=lib.get("allow_qualified_call", True),
                notebook=f.endswith(".ipynb"),
            )
            if imported:
                import_files.append(f)
            elif referenced:
                executable_ref_files.append(f)
    else:
        import_files = sorted({
            path
            for namespace in namespaces
            for path in _grep(namespace, ["*.py", "*.ipynb"])
        })
    # Dual-surface (cuQuantum): own C/C++ source that #includes any component header
    # is ALSO a confirmed integration. Component headers are distinctive (no token
    # collision). Guarded on `cpp_headers` so pure-Python libs (DALI) are untouched.
    cpp_header_files = []
    cpp_header_pattern = _exact_cpp_header_pattern(cpp_headers)
    if cpp_headers:
        hdr_re = (
            r"include[[:space:]]*[<\"]([^>\"]*/)?("
            + "|".join(re.escape(h) for h in cpp_headers)
            + r")[>\"]"
        )
        cpp_header_candidates = [
            f for f in _git(
                dest,
                "grep",
                "--cached",
                "-I",
                "-l",
                "-iE",
                hdr_re,
                "--",
                *_SRC_PATHSPEC,
            ).splitlines()
            if f and not _is_vendored(f) and not _is_env_dump(f)
            and not _in_embedded_project(dest, f)
        ]
        cpp_header_files = _cpp_include_files(
            dest, cpp_header_candidates, cpp_header_pattern
        )
    dep_files = _grep_dep_noncomment(pips)
    targeted_build_files, targeted_build_term = (
        _reviewed_targeted_build_files(dest, lib)
    )
    # Targeted fallback = a code/build reference. Drop doc / AI-agent-skill mentions (an ovrtx skill
    # copied into .claude/skills/…/SKILL.md is documentation ABOUT ovrtx, not use of it) — aligns
    # the Python path with the C++ targeted rule, which already searches only code/build files.
    any_ref = [
        f for f in (
            _grep(pips[0], [])
            + [path for namespace in namespaces for path in _grep(namespace, [])]
        )
        if (
            not _is_doc_or_skill(f)
            and (
                not lib.get("strict_import")
                or not f.lower().endswith((".py", ".ipynb"))
                or f in executable_ref_files
            )
        )
    ]
    if (
        not import_files
        and not cpp_header_files
        and not dep_files
        and not any_ref
        and not targeted_build_files
    ):
        return None

    confirmed_src = import_files + cpp_header_files
    if confirmed_src and _classification_evaluated(lib, "confirmed"):
        if import_files:
            language, pick_term = "Python", ns
        else:
            language = "CUDA" if any(f.lower().endswith((".cu", ".cuh")) for f in cpp_header_files) else "C++"
            pick_term = _header_stem(dest, cpp_header_files, cpp_headers)
        klass, pick_paths = "confirmed", confirmed_src
    elif dep_files and _classification_evaluated(lib, "bundled"):
        # "Declared": a dependency manifest names the package but no import/include
        # was found. Stored under the shared 'bundled' band; relabeled in the UI.
        klass, language, pick_term, pick_paths = "bundled", "Python", pips[0], dep_files
    elif _classification_evaluated(lib, "targeted") and (
        targeted_build_files or (any_ref and not lib.get("direct_only"))
    ):
        pick_paths = (
            targeted_build_files
            if targeted_build_files
            else sorted(set(any_ref))
        )
        klass, language, pick_term = (
            "targeted",
            None,
            targeted_build_term or pips[0],
        )
    else:
        return None

    # Operators vs components: component-aware libs (cuQuantum) record the per-repo
    # component breakdown in the operators field; DALI keeps fn.*/ops.* operators.
    if comp_map:
        operators = _extract_components(dest, confirmed_src or pick_paths, comp_map)
        if klass == "confirmed" and not operators:
            operators = ["SDK (unspecified)"]
    elif (
        klass == "confirmed"
        and import_files
        and lib.get("operator_namespaces")
    ):
        operators = _extract_py_operators(dest, import_files)
    else:
        operators = []

    first_date, first_hash, ai_on_integ, integ_agents = (None, None, False, [])
    dating_cpp_header_pattern = (
        cpp_header_pattern
        if klass == "confirmed" and cpp_header_files and not import_files
        else None
    )
    if pick_paths and include_history:
        first_date, first_hash, ai_on_integ, integ_agents = _date_first_use(
            dest,
            pick_term,
            pick_paths,
            klass == "confirmed",
            dating_cpp_header_pattern,
        )
    confirmed_files = pick_paths if klass == "confirmed" else []

    result = {
        "classification": klass,
        "language": language,
        "first_integration": first_date,
        "first_integration_commit": (first_hash or "")[:12],
        "own_source_files": confirmed_files[:25],
        "own_source_file_count": len(confirmed_files),
        "vendored_present": False,
        "ai_on_integration_commit": ai_on_integ,
        "ai_on_integration_agents": integ_agents,
        "operators": operators,
    }
    if not include_history:
        result["_dating_term"] = pick_term
        result["_dating_paths"] = list(pick_paths)
        result["_dating_cpp_header_pattern"] = dating_cpp_header_pattern
    return result


# A build-signal match inside CMake's GENERIC multi-vendor BLAS/LAPACK finder, or a
# vendored cmake install, is NOT adoption: CMake's own FindBLAS.cmake (4.1+) knows
# NVPL as a BLAS vendor, so it literally contains `find_package(nvpl...)` + `nvpl::`
# targets — any repo that committed a cmake install / toolchain matches. A repo's OWN
# CMakeLists.txt or its own FindNVPL.cmake (NVPL-specific, author-written) is genuine
# and NOT matched here. Also excludes a verbatim copy of PyTorch's manywheel CI
# Dockerfile (a pytorch-fork tell). Narrowed per the 2026-06-26 certification (a
# blanket /Modules/Find would wrongly drop repos that author their own finder).
_NVPL_FALSEPOS_BUILDFILE = re.compile(
    r"find(blas|lapack)\.cmake$"
    r"|(^|/)cmake-\d+\.\d+"
    r"|/share/cmake-"
    r"|\.ci/docker/manywheel/dockerfile_cuda_aarch64",
    re.IGNORECASE)
# Deliberate-selection signals (NVPL named specifically) => "strong"; a bare optional
# find_package(nvpl) => "weak" (capability, not a committed choice).
_NVPL_STRONG_SIGNALS = ("nvpl::", "-lnvpl_", "bla_vendor=nvpl", "ggml_blas_vendor=nvpl")


def _scan_nvpl(dest, lib, *, include_history=True):
    """NVPL CPU-family detector (Arm/Grace; NOT CUDA).
      confirmed = own-source #include <nvpl_*.h> / <nvpl_compat/*.h> (direct API).
      bundled   = a build-integration token (find_package(nvpl, nvpl::, -lnvpl_*,
                  BLA_VENDOR=NVPL) in own build files — they link/select NVPL, often
                  via the FFTW/CBLAS compat API — OR a nvpl-* pip wheel / conda
                  blas=*=nvpl in a manifest. A secondary "Build-integrated / Declared"
                  signal, NEVER summed into the confirmed headline (REQ-05/§3.0).
      targeted  = a bare, shape-guarded nvpl mention only.
    Precision guards: never confirm on a bare compat token (cblas_/fftw3.h/LAPACKE_)
    alone; a conditional include inside an optional-backend file (ggml-blas) is not
    use; vendored / env-dump / embedded-project copies excluded."""
    prefix = lib["header_prefix"]                       # "nvpl_"
    comp_map = lib.get("components", {})
    build_signals = [s.lower() for s in lib.get("build_signals", [])]
    backend_files = lib.get("optional_backend_files", [])
    # NVPL is a C library too — SOURCE_EXTS omits plain .c, so add it here.
    nvpl_src = list(_SRC_PATHSPEC) + ["*.c"]
    build_pathspecs = ["CMakeLists.txt", "*.cmake", "*.cmake.in", "Makefile", "*.mk",
                       "meson.build", "meson.options", "*.bazel", "BUILD", "*.bzl"] + list(PY_DEP_PATHSPECS)

    def _clean(files):
        return [f for f in files if f and not _is_vendored(f) and not _is_env_dump(f)
                and not _in_embedded_project(dest, f)]

    # 1) own-source #include of a COMPONENT-QUALIFIED NVPL header => confirmed
    #    (direct API use). Component-qualified (nvpl_blas/_fftw/_lapack/...) not bare
    #    `nvpl_`, so a path like `InvPl.h` (substring "nvpl") can't false-confirm and
    #    every confirm carries a real component.
    conf_re = (r"include[[:space:]]*[<\"][^>\"]*"
               r"nvpl_(blas|fft|fftw|lapack|scalapack|blacs|sparse|rand|tensor)")
    nvpl_header_pattern = (
        r"nvpl_(?:blas|fft|fftw|lapack|scalapack|blacs|sparse|rand|tensor)"
        r"[^>\"]*"
    )
    inc = _cpp_include_files(
        dest,
        _clean(
            _git(
                dest,
                "grep",
                "--cached",
                "-I",
                "-l",
                "-iE",
                conf_re,
                "--",
                *nvpl_src,
            ).splitlines()
        ),
        nvpl_header_pattern,
    )
    own_inc = [f for f in inc if not _is_optional_backend(f, backend_files)]

    # 2) build-integration token in own build files => bundled (Build-integrated).
    # Capture the PRECISE matched signal (cased) to date on — pickaxing the bare
    # "nvpl" substring mis-dates (e.g. it matched an unrelated 2016 commit in
    # PyTorch's CMake history when NVPL was added ~2024). Date on "find_package(nvpl"
    # / "BLA_VENDOR=NVPL" / "nvpl::" etc. instead.
    build_files = []
    build_term = None
    build_strong = False
    for f in _clean(_git(dest, "grep", "--cached", "-I", "-l", "-iF", "nvpl", "--", *build_pathspecs).splitlines()):
        if _NVPL_FALSEPOS_BUILDFILE.search(f):
            continue   # vendored CMake finder / cmake install / pytorch CI copy — not adoption
        txt = _read_source_text(dest, f)
        low = txt.lower()
        hit = next((sig for sig in build_signals if sig in low), None)
        if hit:
            build_files.append(f)
            if any(s in low for s in _NVPL_STRONG_SIGNALS):
                build_strong = True
            if build_term is None:
                i = low.find(hit)
                build_term = txt[i:i + len(hit)]   # precise cased signal for dating

    # 3) Declared: a nvpl-* pip wheel / conda blas=*=nvpl in a manifest (non-comment).
    dep_files = set()
    dep_re = r"nvpl-(blas|fft|lapack|scalapack|sparse|rand|tensor)|blas=\*=nvpl"
    for ln in _git(dest, "grep", "--cached", "-I", "-n", "-iE", dep_re, "--", *PY_DEP_PATHSPECS).splitlines():
        parts = ln.split(":", 2)
        if len(parts) < 3:
            continue
        path, _lineno, content = parts
        if (_is_vendored(path) or _is_env_dump(path) or _in_embedded_project(dest, path)
                or content.lstrip().startswith("#")):
            continue
        dep_files.add(path)
    dep_files = sorted(dep_files)

    # 4) component-qualified nvpl mention => targeted fallback. Require a real NVPL
    #    shape (component-qualified header/wheel/target/API or an explicit vendor
    #    selection) — never a bare 'nvpl' / 'nvpl-' substring, which over-matches
    #    unrelated tokens (a quantum repo must not pick up a spurious NVPL mention).
    #    Optional-backend files (vendored ggml-blas.cpp etc.) are excluded: a copied
    #    framework shim that conditionally names NVPL is not the repo's own use.
    any_ref = [f for f in _clean(_git(dest, "grep", "--cached", "-I", "-l", "-iE",
                          r"nvpl_(blas|fft|fftw|lapack|scalapack|blacs|sparse|rand|tensor)"
                          r"|nvpl::|libnvpl_|nvpltensor"
                          r"|nvpl-(blas|fft|lapack|scalapack|sparse|rand|tensor)"
                          r"|bla_vendor=nvpl|ggml_blas_vendor=nvpl",
                          "--").splitlines())
               if not _is_optional_backend(f, backend_files)]

    if not own_inc and not build_files and not dep_files and not any_ref:
        return None

    basis = own_inc + build_files + dep_files
    operators = _extract_components(dest, basis or any_ref, comp_map) if comp_map else []

    signal_strength = None   # only meaningful for the build-integrated ("Backend") band
    if own_inc:
        klass = "confirmed"
        language = "CUDA" if any(f.lower().endswith((".cu", ".cuh")) for f in own_inc) else "C++"
        pick_term, pick_paths = prefix, own_inc
    elif build_files:
        klass, language, pick_term, pick_paths = "bundled", None, (build_term or "nvpl"), build_files
        signal_strength = "strong" if build_strong else "weak"   # deliberate selection vs optional capability
    elif dep_files:
        klass, language, pick_term, pick_paths = "bundled", None, "nvpl", dep_files
        signal_strength = "declared"
    else:
        klass, language, pick_term, pick_paths = "targeted", None, "nvpl", any_ref

    first_date, first_hash, ai_on_integ, integ_agents = (None, None, False, [])
    dating_cpp_header_pattern = (
        nvpl_header_pattern if klass == "confirmed" else None
    )
    if pick_paths and include_history:
        first_date, first_hash, ai_on_integ, integ_agents = _date_first_use(
            dest,
            pick_term,
            pick_paths,
            klass == "confirmed",
            dating_cpp_header_pattern,
        )
    confirmed_files = pick_paths if klass == "confirmed" else []

    # Per-component confirmed detail (parent->children split): date each confirmed component's
    # first own-source #include separately, so each child graph's x-axis anchor is honest. Same
    # clone; a few extra pickaxe calls over own_inc only. Backend/targeted bands stay parent-level
    # (build signals like find_package(nvpl) rarely name a component); children derive those bands
    # from the operators labels in aggregate(). {} unless this repo confirms a component.
    component_detail = {}
    component_dating = {}
    if klass == "confirmed" and comp_map:
        keys = sorted(comp_map.keys(), key=len, reverse=True)
        label_files, label_key = {}, {}
        for f in own_inc:
            low = _read_source_text(dest, f).lower()
            for k in keys:
                if k.lower() in low:
                    lab = comp_map[k]
                    label_files.setdefault(lab, []).append(f)
                    label_key.setdefault(lab, k)   # a component header token to pickaxe on
        if include_history:
            for lab, files in label_files.items():
                d, h, ai, ags = _date_first_use(
                    dest,
                    label_key[lab],
                    files,
                    True,
                    re.escape(label_key[lab]) + r"[^>\"]*",
                )
                component_detail[lab] = {
                    "first_integration": d,
                    "first_integration_commit": (h or "")[:12],
                    "ai_on_integration_commit": ai,
                    "ai_on_integration_agents": ags,
                }
        else:
            component_dating = {
                lab: {
                    "term": label_key[lab],
                    "paths": list(files),
                    "cpp_header_pattern": (
                        re.escape(label_key[lab]) + r"[^>\"]*"
                    ),
                }
                for lab, files in label_files.items()
            }

    result = {
        "classification": klass,
        "language": language,
        "first_integration": first_date,
        "first_integration_commit": (first_hash or "")[:12],
        "own_source_files": confirmed_files[:25],
        "own_source_file_count": len(confirmed_files),
        "vendored_present": bool([f for f in inc if _is_vendored(f)]),
        "ai_on_integration_commit": ai_on_integ,
        "ai_on_integration_agents": integ_agents,
        "operators": operators,
        "signal_strength": signal_strength,   # strong|weak|declared (Backend band) or None
        "component_detail": component_detail,  # {label: {first_integration, commit, ai...}} — confirmed only
    }
    if not include_history:
        result["_dating_term"] = pick_term
        result["_dating_paths"] = list(pick_paths)
        result["_dating_cpp_header_pattern"] = dating_cpp_header_pattern
        result["_component_dating"] = component_dating
    return result


def finalize_classified_results(
    dest,
    classified,
    libraries,
    *,
    prior_boundaries_by_library=None,
    require_reuse=False,
):
    """Date a current-tree probe without re-running current-tree detection."""
    library_by_id = {library["id"]: library for library in libraries}
    finalized = {}
    for library_id, source in classified.items():
        if library_id not in library_by_id:
            continue
        row = dict(source)
        term = row.pop("_dating_term", None)
        paths = list(row.pop("_dating_paths", ()))
        cpp_header_pattern = row.pop(
            "_dating_cpp_header_pattern", None
        )
        component_dating = row.pop("_component_dating", {})
        prior_boundaries = (
            (prior_boundaries_by_library or {}).get(library_id) or {}
        )
        stored_boundaries = {}
        first_date = first_hash = None
        ai_on_integration = False
        integration_agents = []
        if term and paths:
            primary_branch = _dating_branch(
                term,
                paths,
                row.get("classification") == "confirmed",
                cpp_header_pattern,
            )
            primary_signature = _dating_plan_signature([primary_branch])
            reused = _reuse_first_use_boundary(
                dest,
                prior_boundaries.get("primary"),
                [primary_branch],
                primary_signature,
            )
            if reused is not None:
                (
                    first_date,
                    first_hash,
                    ai_on_integration,
                    integration_agents,
                ) = reused
            else:
                if require_reuse:
                    raise FirstUseReuseUnavailable(
                        "%s primary first-use boundary is not safely reusable"
                        % library_id
                    )
                (
                    first_date,
                    first_hash,
                    ai_on_integration,
                    integration_agents,
                ) = _date_first_use(
                    dest,
                    primary_branch["term"],
                    primary_branch["paths"],
                    primary_branch["confirmed"],
                    primary_branch["cpp_header_pattern"],
                )
            boundary = _first_use_boundary(
                dest,
                (
                    first_date,
                    first_hash,
                    ai_on_integration,
                    integration_agents,
                ),
                primary_branch,
                primary_signature,
            )
            if boundary is not None:
                stored_boundaries["primary"] = boundary
        row["first_integration"] = first_date
        row["first_integration_commit"] = (first_hash or "")[:12]
        row["ai_on_integration_commit"] = ai_on_integration
        row["ai_on_integration_agents"] = integration_agents
        if component_dating:
            details = {}
            for label, detail in sorted(component_dating.items()):
                component_branch = _dating_branch(
                    detail["term"],
                    detail["paths"],
                    True,
                    detail.get("cpp_header_pattern"),
                )
                component_signature = _dating_plan_signature(
                    [component_branch]
                )
                key = "component:" + label
                reused = _reuse_first_use_boundary(
                    dest,
                    prior_boundaries.get(key),
                    [component_branch],
                    component_signature,
                )
                if reused is not None:
                    date, commit, ai, agents = reused
                else:
                    if require_reuse:
                        raise FirstUseReuseUnavailable(
                            "%s %s first-use boundary is not safely reusable"
                            % (library_id, label)
                        )
                    date, commit, ai, agents = _date_first_use(
                        dest,
                        component_branch["term"],
                        component_branch["paths"],
                        component_branch["confirmed"],
                        component_branch["cpp_header_pattern"],
                    )
                details[label] = {
                    "first_integration": date,
                    "first_integration_commit": (commit or "")[:12],
                    "ai_on_integration_commit": ai,
                    "ai_on_integration_agents": agents,
                }
                boundary = _first_use_boundary(
                    dest,
                    (date, commit, ai, agents),
                    component_branch,
                    component_signature,
                )
                if boundary is not None:
                    stored_boundaries[key] = boundary
            row["component_detail"] = details
        if stored_boundaries:
            row["_first_use_boundaries"] = stored_boundaries
        finalized[library_id] = row
    return finalized


def _scan_repo_once(
    full_name, libs, log, checkout=None, *, include_history=True
):
    """Scan one existing checkout or create a disposable clone.

    ``checkout`` is the V2 persistent-cache integration point. It preserves the
    proven detector semantics while allowing a caller to materialize a temporary
    worktree from a bounded bare cache. The legacy path remains a fresh clone.
    """
    tmp = None
    dest = checkout
    if dest is None:
        tmp = tempfile.mkdtemp(prefix="cxit_")
        dest = os.path.join(tmp, "repo")
    try:
        if checkout is None:
            cloned, reason = _clone(full_name, dest)
            if not cloned:
                raise _RepoScanFailure("clone failed: %s" % reason)
        _verify_clone(dest)

        results = {}
        for lib in libs:
            # NVPL CPU family (Arm/Grace) uses its own multi-signal detector.
            if lib.get("family") == "nvpl":
                r = _scan_nvpl(
                    dest, lib, include_history=include_history
                )
                if r is not None:
                    results[lib["id"]] = r
                continue
            # Pip-distributed Python libraries (DALI, cuQuantum) use the import/dep
            # detector; the C++ include path below is left untouched.
            if lib.get("language") == "python":
                r = _scan_python_lib(
                    dest, lib, include_history=include_history
                )
                if r is not None:
                    results[lib["id"]] = r
                continue
            token = lib["token"]
            py_sigs = PY_SIGNALS.get(lib["id"], [])
            # Multi-header C++ libs (cuPQC): confirm on any of `cpp_headers`, and record a
            # `components` breakdown (like cuQuantum/NVPL) instead of Dx operators. Single-token
            # libs (the Dx family) leave both None and behave exactly as before.
            cpp_headers = lib.get("cpp_headers")
            comp_map = lib.get("components")

            # Env-dump paths (a checked-in virtualenv / node_modules) are stripped
            # from every evidence list below: a committed package install is not an
            # integration. A repo whose ONLY hits are env-dump copies falls through
            # the `continue` and, if that holds for all libs, scan_repo returns None
            # upstream so the repo is dropped entirely.
            # C/C++/CUDA path: files that #include the header (vendored split out). For
            # multi-header libs match ANY of cpp_headers (distinctive, re.escaped); else the
            # single token. (A cuhash-only cuPQC repo has no "cupqc" substring, so token alone
            # would miss it — hence the header list.)
            exact_headers = list(cpp_headers or ())
            if not exact_headers and lib.get("header"):
                exact_headers.append(lib["header"])
            cpp_header_pattern = _exact_cpp_header_pattern(exact_headers)
            if exact_headers:
                inc_re = (
                    r"include[[:space:]]*[<\"]([^>\"]*/)?("
                    + "|".join(re.escape(h) for h in exact_headers)
                    + r")[>\"]"
                )
            else:
                inc_re = r"include[[:space:]]*[<\"][^>\"]*" + token
            inc_candidates = [
                f for f in _git(
                    dest,
                    "grep",
                    "--cached",
                    "-I",
                    "-l",
                    "-iE",
                    inc_re,
                    "--",
                    *_SRC_PATHSPEC,
                ).splitlines()
                if (
                    f
                    and not _is_env_dump(f)
                    and not _is_generated_evidence_path(f)
                    and not _in_embedded_project(dest, f)
                )
            ]
            inc = (
                _cpp_include_files(
                    dest, inc_candidates, cpp_header_pattern
                )
                if cpp_header_pattern
                else inc_candidates
            )
            own_inc = [f for f in inc if not _is_vendored(f)]

            # Python path: own .py source calling nvmath.device.{fft,matmul,random}.
            py_own, matched_sig = [], None
            for sig in py_sigs:
                hits = [f for f in _git(
                    dest, "grep", "--cached", "-I", "-l", "-F", "-e", sig,
                    "--", "*.py"
                ).splitlines()
                        if (f and not _is_vendored(f) and not _is_env_dump(f)
                            and not _is_generated_evidence_path(f)
                            and not _in_embedded_project(dest, f))]
                if hits:
                    py_own += hits
                    matched_sig = matched_sig or sig

            # Token presence (for bundled/targeted fallback on the C++ side).
            ref = [
                f
                for f in _git(
                    dest,
                    "grep",
                    "--cached",
                    "-I",
                    "-l",
                    "-i",
                    "-e",
                    token,
                    "--",
                    *_SRC_PATHSPEC,
                ).splitlines()
                if _has_token_reference(dest, f, token)
            ]
            any_ref = [
                f
                for f in _git(
                    dest,
                    "grep",
                    "--cached",
                    "-I",
                    "-l",
                    "-i",
                    "-e",
                    token,
                ).splitlines()
                if _has_token_reference(dest, f, token)
            ]
            targeted_build_files, targeted_build_term = (
                _reviewed_targeted_build_files(dest, lib)
            )
            if (
                not own_inc
                and not py_own
                and not ref
                and not any_ref
                and not inc
                and not targeted_build_files
            ):
                continue  # library genuinely absent (or only an env-dump copy)

            vend_files = [f for f in ref if _is_vendored(f) or os.path.basename(f).lower() == lib["header"].lower()]
            if cpp_headers:   # multi-header libs: a vendored component header (e.g. cuhash.hpp) is a
                # bundled copy even when the token ("cupqc") never appears in `ref`/`any_ref`.
                vend_files = sorted(set(vend_files) | {f for f in inc if _is_vendored(f)})
            # Default: targeted (named in code/build, no include/bundle). language
            # left None for non-confirmed rows so the dashboard shows the repo's
            # own primary language rather than a guessed one.
            klass, language, pick_term, pick_paths = (
                "targeted",
                None,
                targeted_build_term or token,
                (
                    targeted_build_files
                    if lib.get("direct_only")
                    else [f for f in any_ref if f]
                ),
            )
            if own_inc and _classification_evaluated(lib, "confirmed"):
                klass = "confirmed"
                language = "CUDA" if any(f.lower().endswith((".cu", ".cuh")) for f in own_inc) else "C++"
                # date on the header stem actually present (cupqc / cuhash) for multi-header libs,
                # so a cuhash-only repo dates on "cuhash" rather than a "cupqc" that isn't there.
                pick_term = _header_stem(dest, own_inc, cpp_headers) if cpp_headers else token
                pick_paths = own_inc
            elif py_own and _classification_evaluated(lib, "confirmed"):
                klass, language = "confirmed", "Python"
                pick_term, pick_paths = matched_sig, py_own
            elif (
                (inc or vend_files)
                and _classification_evaluated(lib, "bundled")
            ):
                klass = "bundled"
                pick_paths = vend_files or inc
            elif (
                not _classification_evaluated(lib, "targeted")
                or not pick_paths
            ):
                continue

            # Date the first appearance for every class: confirmed = first real use;
            # bundled = first shipped a copy; targeted = first referenced in code/build.
            first_date, first_hash, ai_on_integ, integ_agents = (None, None, False, [])
            dating_term = pick_term
            dating_cpp_header_pattern = (
                cpp_header_pattern
                if klass == "confirmed" and own_inc
                else None
            )
            if pick_paths:
                # Detect the token's ACTUAL casing in the matched files, then pickaxe with
                # a fast LITERAL -S on that exact string. (A regex/-i pickaxe is correct but
                # far too slow over large histories; this stays fast and case-correct, so a
                # repo that writes "cuBLASDx" still gets a date.)
                m = re.search(
                    re.escape(pick_term),
                    _git(
                        dest, "grep", "--cached", "-h", "-i", "-F",
                        "-e", pick_term, "--", *pick_paths
                    ),
                    re.IGNORECASE,
                )
                if m:
                    dating_term = m.group(0)
            if pick_paths and include_history:
                first_date, first_hash, ai_on_integ, integ_agents = _date_first_use(
                    dest,
                    dating_term,
                    pick_paths,
                    klass == "confirmed",
                    dating_cpp_header_pattern,
                )
            confirmed_files = pick_paths if klass == "confirmed" else []

            row = {
                "classification": klass,
                "language": language,
                "first_integration": first_date,
                "first_integration_commit": (first_hash or "")[:12],
                "own_source_files": confirmed_files[:25],
                "own_source_file_count": len(confirmed_files),
                "vendored_present": bool([f for f in ref if _is_vendored(f)]),
                "ai_on_integration_commit": ai_on_integ,
                "ai_on_integration_agents": integ_agents,
                # component breakdown for multi-component C++ libs (cuPQC), else Dx operators.
                "operators": (
                    (_extract_components(dest, confirmed_files, comp_map) or ["SDK (unspecified)"])
                    if comp_map else _extract_cpp_operators(dest, confirmed_files)
                ) if klass == "confirmed" else [],
            }
            if not include_history:
                row["_dating_term"] = dating_term
                row["_dating_paths"] = list(pick_paths)
                row[
                    "_dating_cpp_header_pattern"
                ] = dating_cpp_header_pattern
            results[lib["id"]] = row

        if not results:
            return {}       # clean reject; distinct from None = operational failure
        if not include_history:
            # The persistent-cache caller deepens only after this proves
            # publishable evidence, then dates these stored evidence paths
            # without re-running current-tree classification.
            return {"libraries": results}
        analysis = analyze_repository(dest)
        analysis["libraries"] = results
        return analysis
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def scan_repo(full_name, libs, log, repo_timeout=None, clone_attempts=None,
              retry_delay=None, checkout=None, include_history=True):
    """Scan one repository with a whole-repo deadline and clean re-clone retries.

    Returns:
      * detection mapping — successful scan with tracked evidence;
      * {}                — successful clean scan with no tracked evidence;
      * None              — every clone/scan attempt failed (caller retains cached
                            data when available and retries on the next refresh).

    A retry always receives a brand-new temporary clone. This is intentional:
    repairing a partial clone in place after commit-graph/object-database errors
    can preserve the corrupt state that caused the incident.
    """
    timeout = repo_timeout if repo_timeout is not None else REPO_TIMEOUT
    attempts = clone_attempts if clone_attempts is not None else CLONE_ATTEMPTS
    delay = retry_delay if retry_delay is not None else CLONE_RETRY_DELAY
    attempts = max(1, int(attempts))
    previous_deadline = _ACTIVE_REPO_DEADLINE[0]
    previous_repository_name = _ACTIVE_REPOSITORY_NAME[0]
    requested_deadline = time.monotonic() + max(0.1, float(timeout))
    # V2 starts the repository deadline before cache materialization and
    # triage.  Preserve that outer budget instead of resetting it when the
    # mature detector is invoked with an existing checkout.
    _ACTIVE_REPO_DEADLINE[0] = (
        min(previous_deadline, requested_deadline)
        if previous_deadline is not None
        else requested_deadline
    )
    _ACTIVE_REPOSITORY_NAME[0] = full_name
    try:
        for attempt in range(1, attempts + 1):
            try:
                result = _scan_repo_once(
                    full_name,
                    libs,
                    log,
                    checkout=checkout,
                    include_history=include_history,
                )
                if attempt > 1:
                    log("    recovered after fresh re-clone: %s" % full_name)
                return result
            except _RepoScanTimeout as e:
                log("    repo timeout: %s (%s)" % (full_name, e))
                return None       # total deadline is exhausted; another retry cannot help
            except _RepoScanFailure as e:
                log("    scan attempt %d/%d failed: %s (%s)"
                    % (attempt, attempts, full_name, e))
                if attempt < attempts and checkout is None:
                    log("    retrying with a fresh clone: %s" % full_name)
                    remaining = _ACTIVE_REPO_DEADLINE[0] - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(float(delay), remaining))
                    continue
                log("    skipping after %d failed attempts: %s" % (attempts, full_name))
                return None
    finally:
        _ACTIVE_REPO_DEADLINE[0] = previous_deadline
        _ACTIVE_REPOSITORY_NAME[0] = previous_repository_name
