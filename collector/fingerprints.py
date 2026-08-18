"""Canonical, granular fingerprints and REQ-14 invalidation planning.

The old collector bound every decision to one source-code hash.  These helpers
make the semantic dependency explicit: presentation changes republish, release
dates reaggregate, and detector changes rescan only the affected library.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


FINGERPRINT_FORMAT_VERSION = 1


def _canonical(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        value = dataclasses.asdict(value)
    if isinstance(value, Mapping):
        return {
            str(key): _canonical(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        normalized = [_canonical(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
        )
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    if isinstance(value, bytes):
        return {"__bytes_hex__": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "pattern") and hasattr(value, "flags"):
        return {"pattern": value.pattern, "flags": value.flags}
    raise TypeError(f"unsupported fingerprint value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return the single canonical JSON representation used by all hashes."""
    return json.dumps(
        _canonical(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

def fingerprint(domain: str, value: Any, *, version: int = FINGERPRINT_FORMAT_VERSION) -> str:
    """Hash a declaration in a namespace so equal data cannot cross domains."""
    if not domain or not isinstance(domain, str):
        raise ValueError("fingerprint domain must be a non-empty string")
    envelope = {"domain": domain, "format": version, "value": _canonical(value)}
    return hashlib.sha256(canonical_json(envelope).encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class LibraryFingerprints:
    discovery: str
    detector: str
    citation: str
    presentation: str
    release: str

    def as_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class FingerprintManifest:
    libraries: dict[str, LibraryFingerprints]
    dating: str
    ai: str
    filters: dict[str, str]
    aggregation: str
    publication: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "libraries": {
                library_id: fps.as_dict()
                for library_id, fps in sorted(self.libraries.items())
            },
            "dating": self.dating,
            "ai": self.ai,
            "filters": dict(sorted(self.filters.items())),
            "aggregation": self.aggregation,
            "publication": self.publication,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "FingerprintManifest":
        return cls(
            libraries={
                str(library_id): LibraryFingerprints(**dict(values))
                for library_id, values in dict(raw.get("libraries", {})).items()
            },
            dating=str(raw["dating"]),
            ai=str(raw["ai"]),
            filters={
                str(profile): str(value)
                for profile, value in dict(raw.get("filters", {})).items()
            },
            aggregation=str(raw["aggregation"]),
            publication=str(raw["publication"]),
        )


@dataclasses.dataclass(frozen=True)
class InvalidationPlan:
    discover: frozenset[str] = frozenset()
    scan: frozenset[str] = frozenset()
    cite: frozenset[str] = frozenset()
    republish: frozenset[str] = frozenset()
    reaggregate: frozenset[str] = frozenset()
    redate_all_positives: bool = False
    reanalyze_all_publishable: bool = False
    refilter_profiles: frozenset[str] = frozenset()
    added_libraries: frozenset[str] = frozenset()
    removed_libraries: frozenset[str] = frozenset()

    @property
    def requires_network(self) -> bool:
        return bool(
            self.discover
            or self.scan
            or self.cite
            or self.reanalyze_all_publishable
        )


def build_manifest(
    libraries: Mapping[str, Mapping[str, Any]],
    *,
    dating_semantics: Any,
    ai_semantics: Any,
    filter_profiles: Mapping[str, Any],
    aggregation_semantics: Any,
    publication_semantics: Any,
) -> FingerprintManifest:
    """Build fingerprints from already-separated canonical declarations.

    Each library mapping must provide ``discovery``, ``detector``, ``citation``,
    ``presentation`` and ``release`` declarations.  Shared engine versions
    belong inside the declaration whose behavior they affect.
    """
    required = {"discovery", "detector", "citation", "presentation", "release"}
    built: dict[str, LibraryFingerprints] = {}
    for library_id, declaration in sorted(libraries.items()):
        missing = required.difference(declaration)
        if missing:
            raise ValueError(
                f"{library_id} missing fingerprint declarations: {sorted(missing)}"
            )
        built[library_id] = LibraryFingerprints(
            discovery=fingerprint(f"library:{library_id}:discovery", declaration["discovery"]),
            detector=fingerprint(f"library:{library_id}:detector", declaration["detector"]),
            citation=fingerprint(f"library:{library_id}:citation", declaration["citation"]),
            presentation=fingerprint(
                f"library:{library_id}:presentation", declaration["presentation"]
            ),
            release=fingerprint(f"library:{library_id}:release", declaration["release"]),
        )
    return FingerprintManifest(
        libraries=built,
        dating=fingerprint("shared:dating", dating_semantics),
        ai=fingerprint("shared:ai", ai_semantics),
        filters={
            profile: fingerprint(f"filter:{profile}", declaration)
            for profile, declaration in sorted(filter_profiles.items())
        },
        aggregation=fingerprint("shared:aggregation", aggregation_semantics),
        publication=fingerprint("shared:publication", publication_semantics),
    )


def invalidation_plan(
    previous: FingerprintManifest | None,
    current: FingerprintManifest,
    *,
    profile_libraries: Mapping[str, Sequence[str]] | None = None,
) -> InvalidationPlan:
    """Translate fingerprint changes into the minimal required work.

    A missing prior manifest is an explicit cold reconciliation.  Callers must
    still enforce their run budgets before scheduling the resulting work.
    """
    current_ids = frozenset(current.libraries)
    if previous is None:
        return InvalidationPlan(
            discover=current_ids,
            scan=current_ids,
            cite=current_ids,
            republish=current_ids,
            reaggregate=current_ids,
            redate_all_positives=True,
            reanalyze_all_publishable=True,
            refilter_profiles=frozenset(current.filters),
            added_libraries=current_ids,
        )

    previous_ids = frozenset(previous.libraries)
    added = current_ids - previous_ids
    removed = previous_ids - current_ids
    common = current_ids & previous_ids

    discover = set(added)
    scan = set(added)
    cite = set(added)
    republish = set(added) | set(removed)
    reaggregate = set(added) | set(removed)

    for library_id in common:
        before = previous.libraries[library_id]
        after = current.libraries[library_id]
        if before.discovery != after.discovery:
            discover.add(library_id)
        if before.detector != after.detector:
            scan.add(library_id)
        if before.citation != after.citation:
            cite.add(library_id)
        if before.presentation != after.presentation:
            republish.add(library_id)
        if before.release != after.release:
            reaggregate.add(library_id)

    changed_profiles = {
        profile
        for profile in set(previous.filters) | set(current.filters)
        if previous.filters.get(profile) != current.filters.get(profile)
    }
    profile_libraries = profile_libraries or {}
    for profile in changed_profiles:
        scan.update(profile_libraries.get(profile, ()))

    aggregation_changed = previous.aggregation != current.aggregation
    publication_changed = previous.publication != current.publication
    dating_changed = previous.dating != current.dating
    ai_changed = previous.ai != current.ai

    if aggregation_changed:
        reaggregate.update(current_ids)
    if publication_changed:
        republish.update(current_ids)
    if dating_changed:
        reaggregate.update(current_ids)
    if ai_changed:
        republish.update(current_ids)

    # A detector/discovery/citation result changes the affected library output.
    republish.update(discover)
    republish.update(scan)
    republish.update(cite)
    reaggregate.update(scan)

    return InvalidationPlan(
        discover=frozenset(discover),
        scan=frozenset(scan),
        cite=frozenset(cite),
        republish=frozenset(republish),
        reaggregate=frozenset(reaggregate),
        redate_all_positives=dating_changed,
        reanalyze_all_publishable=ai_changed,
        refilter_profiles=frozenset(changed_profiles),
        added_libraries=added,
        removed_libraries=removed,
    )
