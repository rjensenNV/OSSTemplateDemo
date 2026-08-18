"""Fail-closed parsers for authored notebook and Git LFS evidence.

These helpers are shared by bare triage, worktree classification, and history
dating.  Keeping one implementation prevents current-tree recovery from
silently using semantics that historical first-adoption dating cannot repeat.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import re
from typing import Any


_PYTHON_SHEBANG_RE = re.compile(
    r"\A#![^\r\n]*\bpython(?:[0-9]+(?:\.[0-9]+)*)?\b",
    re.IGNORECASE,
)
_LFS_OID_RE = re.compile(r"\Aoid sha256:([0-9a-f]{64})\Z")
_LFS_SIZE_RE = re.compile(r"\Asize ([0-9]+)\Z")
_LFS_EXTENSION_RE = re.compile(r"\Aext-[A-Za-z0-9.-]+ [^\r\n]+\Z")
_DISALLOWED_AUTHORED_TEXT_RE = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffd]"
)
_MAX_LFS_POINTER_BYTES = 4096


class NotebookEvidenceError(ValueError):
    """A tracked notebook cannot be interpreted without inventing evidence."""


@dataclasses.dataclass(frozen=True)
class NotebookSurfaces:
    search_text: str
    code_text: str
    recovery: str


@dataclasses.dataclass(frozen=True)
class LFSPointer:
    oid: str
    size: int


def parse_lfs_pointer(raw: bytes | str) -> LFSPointer | None:
    """Return an exact SHA-256 Git LFS pointer certificate, if present."""
    if isinstance(raw, str):
        try:
            payload = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return None
    else:
        payload = bytes(raw)
    if len(payload) > _MAX_LFS_POINTER_BYTES:
        return None
    if b"\r" in payload:
        payload = payload.replace(b"\r\n", b"\n")
        if b"\r" in payload:
            return None
    if not payload.startswith(
        b"version https://git-lfs.github.com/spec/v1\n"
    ):
        return None
    try:
        lines = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        return None
    if not lines or lines[0] != (
        "version https://git-lfs.github.com/spec/v1"
    ):
        return None
    oid = None
    size = None
    saw_oid = False
    saw_size = False
    for line in lines[1:]:
        oid_match = _LFS_OID_RE.fullmatch(line)
        size_match = _LFS_SIZE_RE.fullmatch(line)
        if oid_match:
            # The v1 grammar is version, zero or more extensions, oid, size.
            if saw_oid or saw_size:
                return None
            oid = oid_match.group(1)
            saw_oid = True
        elif size_match:
            if not saw_oid or saw_size:
                return None
            try:
                size = int(size_match.group(1))
            except ValueError:
                return None
            saw_size = True
        elif saw_oid or saw_size or not _LFS_EXTENSION_RE.fullmatch(line):
            return None
    if oid is None or size is None:
        return None
    return LFSPointer(oid=oid, size=size)


def _contains_authored_damage(value: str) -> bool:
    return _DISALLOWED_AUTHORED_TEXT_RE.search(value) is not None


def _bounded_json_recovery(
    value: str,
    *,
    allow_ignored_raw_controls: bool,
    repair_ignored_trailing_commas: bool,
) -> tuple[str, bool] | None:
    """Validate one bounded relaxation of the strict JSON grammar.

    This is deliberately a small JSON parser rather than a regex or JSON5
    decoder. Accepted trailing commas are replaced with a length-preserving
    space. Raw control characters are accepted only inside ignored
    metadata/output descendants. Strings, escapes, keys, and authored values
    otherwise retain the strict JSON grammar.
    """
    repaired = list(value)
    whitespace = " \t\r\n"
    changed = False

    def skip_space(index):
        while index < len(value) and value[index] in whitespace:
            index += 1
        return index

    def parse_string(index, ignored):
        if index >= len(value) or value[index] != '"':
            raise ValueError("expected JSON string")
        cursor = index + 1
        escaped = False
        while cursor < len(value):
            character = value[cursor]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                token = value[index:cursor + 1]
                decoded = json.loads(
                    token,
                    strict=not (
                        allow_ignored_raw_controls and ignored
                    ),
                )
                if not isinstance(decoded, str):
                    raise ValueError("invalid JSON string")
                return cursor + 1, decoded
            cursor += 1
        raise ValueError("unterminated JSON string")

    def parse_value(index, ignored):
        index = skip_space(index)
        if index >= len(value):
            raise ValueError("missing JSON value")
        if value[index] == "{":
            return parse_object(index, ignored)
        if value[index] == "[":
            return parse_array(index, ignored)
        if value[index] == '"':
            return parse_string(index, ignored)[0]
        cursor = index
        while (
            cursor < len(value)
            and value[cursor] not in ",]}"
        ):
            cursor += 1
        token = value[index:cursor].strip()
        if not token:
            raise ValueError("missing JSON scalar")
        parsed = json.loads(token)
        if isinstance(parsed, (dict, list, str)):
            raise ValueError("invalid JSON scalar")
        return cursor

    def parse_object(index, ignored):
        nonlocal changed
        cursor = skip_space(index + 1)
        if cursor < len(value) and value[cursor] == "}":
            return cursor + 1
        while True:
            cursor, key = parse_string(cursor, ignored)
            cursor = skip_space(cursor)
            if cursor >= len(value) or value[cursor] != ":":
                raise ValueError("missing JSON object colon")
            child_ignored = ignored or key in {"metadata", "outputs"}
            cursor = parse_value(cursor + 1, child_ignored)
            cursor = skip_space(cursor)
            if cursor >= len(value):
                raise ValueError("unterminated JSON object")
            if value[cursor] == "}":
                return cursor + 1
            if value[cursor] != ",":
                raise ValueError("missing JSON object comma")
            comma = cursor
            cursor = skip_space(cursor + 1)
            if cursor < len(value) and value[cursor] == "}":
                if (
                    not ignored
                    or not repair_ignored_trailing_commas
                ):
                    raise ValueError(
                        "trailing comma outside ignored JSON"
                    )
                repaired[comma] = " "
                changed = True
                return cursor + 1

    def parse_array(index, ignored):
        nonlocal changed
        cursor = skip_space(index + 1)
        if cursor < len(value) and value[cursor] == "]":
            return cursor + 1
        while True:
            cursor = parse_value(cursor, ignored)
            cursor = skip_space(cursor)
            if cursor >= len(value):
                raise ValueError("unterminated JSON array")
            if value[cursor] == "]":
                return cursor + 1
            if value[cursor] != ",":
                raise ValueError("missing JSON array comma")
            comma = cursor
            cursor = skip_space(cursor + 1)
            if cursor < len(value) and value[cursor] == "]":
                if (
                    not ignored
                    or not repair_ignored_trailing_commas
                ):
                    raise ValueError(
                        "trailing comma outside ignored JSON"
                    )
                repaired[comma] = " "
                changed = True
                return cursor + 1

    try:
        end = skip_space(parse_value(0, False))
        if end != len(value):
            raise ValueError("extra JSON content")
    except (TypeError, ValueError):
        return None
    return "".join(repaired), changed


def _validate_damage_location(
    value: Any,
    *,
    ignored: bool = False,
) -> None:
    """Reject tolerant-parse damage outside outputs and metadata."""
    if ignored:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or _contains_authored_damage(key):
                raise NotebookEvidenceError(
                    "notebook has damaged structural keys"
                )
            _validate_damage_location(
                item,
                ignored=key in {"metadata", "outputs"},
            )
    elif isinstance(value, list):
        for item in value:
            _validate_damage_location(item)
    elif isinstance(value, str) and _contains_authored_damage(value):
        raise NotebookEvidenceError(
            "notebook damage reaches authored or structural text"
        )


def _cells(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        raise NotebookEvidenceError("notebook is not an object")
    if "cells" in document:
        cells = document["cells"]
    elif "worksheets" in document:
        worksheets = document["worksheets"]
        if not isinstance(worksheets, list):
            raise NotebookEvidenceError("notebook worksheets are invalid")
        cells = []
        for worksheet in worksheets:
            if (
                not isinstance(worksheet, dict)
                or not isinstance(worksheet.get("cells", []), list)
            ):
                raise NotebookEvidenceError(
                    "notebook worksheet is invalid"
                )
            cells.extend(worksheet.get("cells", []))
    else:
        raise NotebookEvidenceError("notebook has no cells")
    if not isinstance(cells, list):
        raise NotebookEvidenceError("notebook cells are invalid")
    if not all(isinstance(cell, dict) for cell in cells):
        raise NotebookEvidenceError("notebook cell is invalid")
    return cells


def _surface_document(
    document: Any,
    *,
    recovery: str,
    tolerant: bool,
) -> NotebookSurfaces:
    if tolerant:
        _validate_damage_location(document)
    cells = _cells(document)
    search_parts: list[str] = []
    code_parts: list[str] = []
    for cell in cells:
        cell_type = cell.get("cell_type")
        if (
            ("cell_type" in cell and not isinstance(cell_type, str))
            or (
                isinstance(cell_type, str)
                and _contains_authored_damage(cell_type)
            )
        ):
            raise NotebookEvidenceError("notebook cell is invalid")
        if cell_type not in {"code", "markdown"}:
            continue
        source = cell.get(
            "source",
            cell.get("input", "") if cell_type == "code" else "",
        )
        if isinstance(source, list):
            if not all(isinstance(part, str) for part in source):
                raise NotebookEvidenceError(
                    "notebook source is not text"
                )
            text = "".join(source)
        elif isinstance(source, str):
            text = source
        else:
            raise NotebookEvidenceError("notebook source is invalid")
        # A replacement glyph or escaped control character that was present
        # in strict UTF-8 JSON is authored content, not decoder damage. Keep
        # it verbatim so it cannot bridge two detector tokens. Only tolerant
        # decoding needs the fail-closed damage-location proof.
        if tolerant and _contains_authored_damage(text):
            raise NotebookEvidenceError(
                "notebook damage reaches authored source"
            )
        search_parts.append(text)
        if cell_type == "code":
            code_parts.append(text)
    return NotebookSurfaces(
        search_text="\n".join(search_parts),
        code_text="\n".join(code_parts),
        recovery=recovery,
    )


def parse_notebook_surfaces(raw: bytes | str) -> NotebookSurfaces:
    """Parse notebook authored surfaces without searching outputs/metadata.

    Strict nbformat JSON is authoritative.  Three bounded recovery forms are
    accepted because each preserves the exact authored source:

    * a strict UTF-8 Python script stored under an ``.ipynb`` name; and
    * strict UTF-8 JSON with only trailing container commas; and
    * relaxed JSON whose decoding/control damage is confined to ignored
      notebook outputs or metadata.
    """
    strict_text = None
    if isinstance(raw, bytes):
        try:
            strict_text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        tolerant_text = raw.decode("utf-8", errors="replace")
    elif isinstance(raw, str):
        strict_text = raw
        tolerant_text = raw
    else:
        raise NotebookEvidenceError("notebook input is not text")

    if strict_text is not None:
        normalized = strict_text.removeprefix("\ufeff")
        try:
            document = json.loads(normalized)
        except (TypeError, ValueError):
            document = None
        if document is not None:
            return _surface_document(
                document,
                recovery="strict-json",
                tolerant=False,
            )
        trailing_recovery = _bounded_json_recovery(
            normalized,
            allow_ignored_raw_controls=False,
            repair_ignored_trailing_commas=True,
        )
        if trailing_recovery is not None and trailing_recovery[1]:
            trailing_comma_text, _removed_trailing_comma = (
                trailing_recovery
            )
            try:
                document = json.loads(trailing_comma_text)
            except (TypeError, ValueError):
                document = None
            if document is not None:
                return _surface_document(
                    document,
                    recovery="trailing-comma-json",
                    tolerant=False,
                )
        if _PYTHON_SHEBANG_RE.match(normalized):
            try:
                ast.parse(normalized)
            except (SyntaxError, ValueError):
                # A shebang prefix alone is not permission to reinterpret
                # arbitrary malformed JSON as source. Fall through to the
                # ordinary fail-closed invalid-JSON result.
                pass
            else:
                if _contains_authored_damage(normalized):
                    raise NotebookEvidenceError(
                        "misnamed Python notebook source is damaged"
                    )
                return NotebookSurfaces(
                    search_text=normalized,
                    code_text=normalized,
                    recovery="python-shebang-source",
                )

    if _bounded_json_recovery(
        tolerant_text.removeprefix("\ufeff"),
        allow_ignored_raw_controls=True,
        repair_ignored_trailing_commas=False,
    ) is None:
        raise NotebookEvidenceError("notebook is invalid JSON")
    try:
        document = json.loads(
            tolerant_text.removeprefix("\ufeff"),
            strict=False,
        )
    except (TypeError, ValueError) as exc:
        raise NotebookEvidenceError(
            "notebook is invalid JSON"
        ) from exc
    return _surface_document(
        document,
        recovery="output-metadata-only-json-recovery",
        tolerant=True,
    )
