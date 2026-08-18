"""Deterministic, library-scoped discovery query packing.

The current-tree scanner remains authoritative.  Discovery queries are broad
candidate generators, but their coverage still has to be explicit and
auditable.  A pack therefore records every detector signal it represents and
uses an OR query whose result set is the union of those signal queries.  This
reduces network lanes without turning a broad token into an undocumented
substitute for an exact header/import declaration.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .. import config


# GitHub search accepts at most five boolean operators in one query.  Six
# alternatives also leaves headroom below the endpoint's query-length limit
# for extension and recursive size qualifiers appended by the adapter.
MAX_PACK_MEMBERS = 6
MAX_PACK_QUERY_CHARS = 180
GITHUB_MAX_FILE_SIZE = 384 * 1024 - 1
GITHUB_RESULT_CAP = 1_000
SOURCEGRAPH_RESULT_LIMIT = 50_000
QUERY_PLAN_VERSION = 5


@dataclass(frozen=True)
class SignalSpec:
    """One reviewed detector signal before compatible lanes are consolidated."""

    library_id: str
    signal_id: str
    anchor: str
    github_query: str
    sourcegraph_query: str
    extensions: tuple[str, ...]


@dataclass(frozen=True)
class DiscoveryQueryPack:
    """One source query covering one or more compatible detector signals."""

    library_id: str
    signal_id: str
    kind: str
    member_signal_ids: tuple[str, ...]
    anchors: tuple[str, ...]
    github_query: str
    sourcegraph_query: str
    extensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.library_id or not self.signal_id or not self.kind:
            raise ValueError("query-pack identity fields must not be empty")
        if not self.member_signal_ids or not self.anchors:
            raise ValueError("query pack must contain at least one signal")
        if len(self.member_signal_ids) != len(self.anchors):
            raise ValueError("query-pack signals and anchors must align")
        if len(set(self.member_signal_ids)) != len(self.member_signal_ids):
            raise ValueError("query-pack signal IDs must be unique")


def _quoted(value: object) -> str:
    return '"%s"' % str(value).replace('"', "")


def _sourcegraph_file_filter(extensions: Iterable[str]) -> str:
    normalized = tuple(
        sorted(
            {
                item.strip().lower().removeprefix(".")
                for item in extensions
                if isinstance(item, str) and item.strip()
            }
        )
    )
    if not normalized:
        return ""
    return r" file:\.(%s)$" % "|".join(re.escape(item) for item in normalized)


def signal_specs(lib: Mapping[str, Any]) -> tuple[SignalSpec, ...]:
    """Build reviewed broad-candidate signals; exact scan evidence is authoritative."""
    specs: list[SignalSpec] = []
    source_exts = tuple(sorted(set(config.SOURCE_EXTS) | {"c"}))
    python_exts = tuple(config.PY_SOURCE_EXTS)
    headers = list(lib.get("cpp_headers") or ())
    if lib.get("header"):
        headers.append(lib["header"])
    header_prefixes = list(lib.get("header_prefixes") or ())
    if lib.get("header_prefix"):
        header_prefixes.append(lib["header_prefix"])
    namespaces = list(lib.get("import_namespaces") or ())
    if not namespaces and lib.get("import_namespace"):
        namespaces.append(lib["import_namespace"])

    for ordinal, header in enumerate(dict.fromkeys(headers)):
        quoted = _quoted(header)
        specs.append(SignalSpec(
            library_id=lib["id"],
            signal_id="header-%02d" % ordinal,
            anchor=str(header),
            github_query=quoted,
            sourcegraph_query=quoted + _sourcegraph_file_filter(source_exts),
            extensions=source_exts,
        ))
    for ordinal, prefix in enumerate(dict.fromkeys(header_prefixes)):
        quoted = _quoted(prefix)
        specs.append(SignalSpec(
            library_id=lib["id"],
            signal_id="header-prefix-%02d" % ordinal,
            anchor=str(prefix),
            github_query=quoted,
            sourcegraph_query=quoted + _sourcegraph_file_filter(source_exts),
            extensions=source_exts,
        ))
    for ordinal, namespace in enumerate(dict.fromkeys(namespaces)):
        for shape, phrase in (
            ("import", "import %s" % namespace),
            ("from", "from %s" % namespace),
        ):
            quoted = _quoted(phrase)
            specs.append(SignalSpec(
                library_id=lib["id"],
                signal_id="import-%02d-%s" % (ordinal, shape),
                anchor=str(namespace),
                github_query=quoted,
                sourcegraph_query=quoted + _sourcegraph_file_filter(python_exts),
                extensions=python_exts,
            ))

    # Declaration/build/reference lanes exist only for classifications that the
    # library actually evaluates. A direct-lane detector may therefore add an
    # exact declared-package or reviewed build-target lane without enabling a
    # broad product-token fallback.
    evaluated = set(
        lib.get(
            "classification_coverage",
            ("confirmed", "bundled", "targeted"),
        )
    )
    if not lib.get("direct_only") or evaluated.intersection(
        {"bundled", "targeted"}
    ):
        broad: list[object] = []
        if "targeted" in evaluated:
            broad.extend(
                lib.get("targeted_build_discovery_anchors")
                or lib.get("targeted_build_signals")
                or ()
            )
            broad.extend(lib.get("build_signals") or ())
        if "bundled" in evaluated:
            packages = lib.get("pip_pattern") or ()
            broad.extend(
                (packages,) if isinstance(packages, str) else packages
            )
        if (
            not lib.get("direct_only")
            and not broad
            and not specs
            and lib.get("token")
        ):
            broad.append(lib["token"])
        for ordinal, value in enumerate(dict.fromkeys(x for x in broad if x)):
            quoted = _quoted(value)
            specs.append(SignalSpec(
                library_id=lib["id"],
                signal_id="broad-%02d" % ordinal,
                anchor=str(value),
                github_query=quoted,
                sourcegraph_query=quoted,
                extensions=(),
            ))
    if not specs:
        anchor = str(lib["token"])
        quoted = _quoted(anchor)
        specs.append(SignalSpec(
            library_id=lib["id"],
            signal_id="token",
            anchor=anchor,
            github_query=quoted,
            sourcegraph_query=quoted,
            extensions=tuple(
                sorted(set(source_exts) | set(config.TARGETED_EXTS))
            ),
        ))
    return tuple(specs)


def _kind(spec: SignalSpec) -> str:
    if spec.signal_id.startswith(("header-", "header-prefix-")):
        return "header"
    if spec.signal_id.startswith("import-"):
        return "import"
    return "broad"


def _chunks(specs: Iterable[SignalSpec]) -> tuple[tuple[SignalSpec, ...], ...]:
    """Pack OR-compatible signals without exceeding GitHub query constraints."""
    groups: list[tuple[SignalSpec, ...]] = []
    current: list[SignalSpec] = []
    for spec in specs:
        proposal = current + [spec]
        query = " OR ".join(item.github_query for item in proposal)
        if current and (
            len(proposal) > MAX_PACK_MEMBERS
            or len(query) > MAX_PACK_QUERY_CHARS
        ):
            groups.append(tuple(current))
            current = [spec]
        else:
            current = proposal
    if current:
        groups.append(tuple(current))
    return tuple(groups)


def query_packs(lib: Mapping[str, Any]) -> tuple[DiscoveryQueryPack, ...]:
    """Return deterministic header/import packs plus unmodified broad lanes."""
    specs = signal_specs(lib)
    compatible: dict[tuple[str, tuple[str, ...]], list[SignalSpec]] = {}
    broad: list[SignalSpec] = []
    for spec in specs:
        kind = _kind(spec)
        if kind == "broad":
            broad.append(spec)
            continue
        compatible.setdefault((kind, spec.extensions), []).append(spec)

    packs: list[DiscoveryQueryPack] = []
    ordinals: dict[str, int] = {"header": 0, "import": 0}
    for (kind, extensions), members in compatible.items():
        for chunk in _chunks(members):
            if len(chunk) == 1:
                signal_id = chunk[0].signal_id
                github_query = chunk[0].github_query
                sourcegraph_query = chunk[0].sourcegraph_query
            else:
                signal_id = "%s-pack-%02d" % (kind, ordinals[kind])
                github_query = " OR ".join(
                    member.github_query for member in chunk
                )
                sourcegraph_query = (
                    "("
                    + " OR ".join(member.github_query for member in chunk)
                    + ")"
                    + _sourcegraph_file_filter(extensions)
                )
            ordinals[kind] += 1
            packs.append(DiscoveryQueryPack(
                library_id=lib["id"],
                signal_id=signal_id,
                kind=kind,
                member_signal_ids=tuple(
                    member.signal_id for member in chunk
                ),
                anchors=tuple(member.anchor for member in chunk),
                github_query=github_query,
                sourcegraph_query=sourcegraph_query,
                extensions=extensions,
            ))

    for spec in broad:
        packs.append(DiscoveryQueryPack(
            library_id=lib["id"],
            signal_id=spec.signal_id,
            kind="broad",
            member_signal_ids=(spec.signal_id,),
            anchors=(spec.anchor,),
            github_query=spec.github_query,
            sourcegraph_query=spec.sourcegraph_query,
            extensions=spec.extensions,
        ))
    return tuple(packs)


def _fingerprint(pack: DiscoveryQueryPack, source: str) -> str:
    payload: dict[str, object] = {
        "query_plan_version": QUERY_PLAN_VERSION,
        "source": source,
        "library_id": pack.library_id,
        "signal_id": pack.signal_id,
        "member_signal_ids": pack.member_signal_ids,
        "anchors": pack.anchors,
    }
    if source == "github-code-search":
        payload.update({
            "query": pack.github_query.strip(),
            "extensions": tuple(
                sorted(
                    ext.strip().lower().removeprefix(".")
                    for ext in pack.extensions
                )
            ),
            "max_file_size": GITHUB_MAX_FILE_SIZE,
            "result_cap": GITHUB_RESULT_CAP,
            "coverage_policy": (
                "single-empty-page-bounded-retry-repository-membership-v5"
            ),
        })
    elif source == "sourcegraph":
        payload.update({
            "query": pack.sourcegraph_query.strip(),
            "coverage_policy": (
                "patternType:keyword",
                "repo:^github\\.com/",
                "visibility:public",
                "select:file",
                "count:%d" % SOURCEGRAPH_RESULT_LIMIT,
                "timeout:1m",
                "fork:no",
                "archived:no",
            ),
        })
    else:
        raise ValueError("unsupported discovery source %r" % source)
    return hashlib.sha256(json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def github_query_fingerprint(pack: DiscoveryQueryPack) -> str:
    return _fingerprint(pack, "github-code-search")


def sourcegraph_query_fingerprint(pack: DiscoveryQueryPack) -> str:
    return _fingerprint(pack, "sourcegraph")
