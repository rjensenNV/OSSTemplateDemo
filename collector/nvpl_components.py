"""Audited NVPL component projection helpers.

These helpers operate after current-tree classification. They never promote a
repository into NVPL or change its adoption band; they only preserve or attach
component labels to an already-positive NVPL row.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping


NVPL_COMPONENT_LABELS = frozenset(
    {"BLAS", "FFT", "LAPACK", "ScaLAPACK", "Sparse", "RAND", "Tensor"}
)
_OVERRIDES_PATH = Path(__file__).with_name("nvpl_component_bucket_overrides.json")


@lru_cache(maxsize=1)
def _document() -> dict[str, Any]:
    document = json.loads(_OVERRIDES_PATH.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ValueError("unsupported NVPL component override schema")
    seen = set()
    for row in document.get("overrides", ()):
        key = (row.get("repository", "").casefold(), row.get("head_sha"))
        if (
            not key[0]
            or key in seen
            or len(str(key[1] or "")) != 40
            or not isinstance(row.get("evidence_path"), str)
            or not row["evidence_path"]
            or not row.get("components")
            or not set(row["components"]).issubset(NVPL_COMPONENT_LABELS)
        ):
            raise ValueError("invalid NVPL component override")
        seen.add(key)
    return document


def override_policy_sha256() -> str:
    return hashlib.sha256(_OVERRIDES_PATH.read_bytes()).hexdigest()


def reviewed_components(
    repository: str,
    head_sha: str,
    evidence: Mapping[str, Any],
) -> tuple[str, ...]:
    boundary = (
        ((evidence.get("_first_use_boundaries") or {}).get("primary") or {})
        if isinstance(evidence, Mapping)
        else {}
    )
    evidence_path = boundary.get("evidence_path")
    for row in _document().get("overrides", ()):
        if (
            row["repository"].casefold() == repository.casefold()
            and row["head_sha"] == head_sha
            and row["evidence_path"] == evidence_path
        ):
            return tuple(row["components"])
    return ()


def effective_components(entry: Mapping[str, Any]) -> set[str]:
    """Return the component membership used by V1/V2 NVPL projection."""
    if entry.get("classification") == "confirmed" and entry.get("component_detail"):
        values = set(entry["component_detail"])
    else:
        values = set(entry.get("operators") or ())
    return values & NVPL_COMPONENT_LABELS


def preserve_v1_components(
    current_entry: dict[str, Any], prior_entry: Mapping[str, Any]
) -> None:
    """Preserve exact V1 component membership without changing the V2 band."""
    prior = effective_components(prior_entry)
    if current_entry.get("classification") == "confirmed":
        prior_detail = prior_entry.get("component_detail") or {}
        current_entry["component_detail"] = {
            label: dict(prior_detail.get(label) or {})
            for label in sorted(prior)
        }
    else:
        current_entry["operators"] = sorted(prior)
