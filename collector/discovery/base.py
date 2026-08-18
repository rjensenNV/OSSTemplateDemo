"""Shared, side-effect-free discovery contracts for the REQ-14 pipeline.

Discovery sources emit evidence observations and a coverage certificate.  The
certificate is deliberately separate from the observations: an interrupted or
truncated source can yield syntactically valid matches, but those matches must
remain quarantined until the source proves that its search completed.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping, Sequence


PUBLIC = "PUBLIC"


class IncompleteCoverageError(RuntimeError):
    """Raised when callers try to consume a quarantined discovery result."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | datetime | None) -> datetime | None:
    """Parse an ISO-8601 timestamp and always return a timezone-aware value."""
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class DiscoveryObservation:
    """One repository/library signal seen by one discovery source."""

    repo_full_name: str
    library_id: str
    signal_id: str
    source: str
    query_fingerprint: str
    observed_at: datetime
    visibility: str
    repo_node_id: str | None = None
    matched_path: str | None = None
    matched_blob: str | None = None
    matched_commit: str | None = None
    source_fetched_at: datetime | None = None
    source_lag_seconds: int | None = None
    partition: str | None = None

    def __post_init__(self) -> None:
        if (
            self.repo_full_name.count("/") != 1
            or any(not part for part in self.repo_full_name.split("/", 1))
        ):
            raise ValueError("repo_full_name must be OWNER/REPO")
        if self.repo_node_id is not None and not self.repo_node_id:
            raise ValueError("repo_node_id cannot be empty")
        for name in ("library_id", "signal_id", "source", "query_fingerprint"):
            if not getattr(self, name):
                raise ValueError("%s must not be empty" % name)
        if self.visibility != PUBLIC:
            raise ValueError("publishable observations require explicit PUBLIC visibility")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.source_fetched_at is not None and self.source_fetched_at.tzinfo is None:
            raise ValueError("source_fetched_at must be timezone-aware")
        if self.source_lag_seconds is not None and self.source_lag_seconds < 0:
            raise ValueError("source_lag_seconds cannot be negative")

    @property
    def repository_identity(self) -> str:
        if self.repo_node_id:
            return "node:" + self.repo_node_id
        return "name:" + self.repo_full_name.casefold()

    def to_dict(self) -> dict:
        return {
            "repo_node_id": self.repo_node_id,
            "repo_full_name": self.repo_full_name,
            "library_id": self.library_id,
            "signal_id": self.signal_id,
            "matched_path": self.matched_path,
            "matched_blob": self.matched_blob,
            "matched_commit": self.matched_commit,
            "source": self.source,
            "query_fingerprint": self.query_fingerprint,
            "observed_at": format_timestamp(self.observed_at),
            "source_fetched_at": format_timestamp(self.source_fetched_at),
            "source_lag_seconds": self.source_lag_seconds,
            "partition": self.partition,
            "visibility": self.visibility,
        }


@dataclass(frozen=True)
class CoverageGap:
    code: str
    detail: str
    partition: str | None = None
    retryable: bool = False

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "detail": self.detail,
            "partition": self.partition,
            "retryable": self.retryable,
        }


@dataclass(frozen=True)
class CoveragePartition:
    key: str
    query: str
    total_count: int | None
    fetched_count: int
    page_count: int
    complete: bool
    capped: bool = False
    subdivided: bool = False
    incomplete_results: bool = False
    extension: str | None = None
    size_min: int | None = None
    size_max: int | None = None
    gaps: tuple[CoverageGap, ...] = ()

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "query": self.query,
            "total_count": self.total_count,
            "fetched_count": self.fetched_count,
            "page_count": self.page_count,
            "complete": self.complete,
            "capped": self.capped,
            "subdivided": self.subdivided,
            "incomplete_results": self.incomplete_results,
            "extension": self.extension,
            "size_min": self.size_min,
            "size_max": self.size_max,
            "gaps": [gap.to_dict() for gap in self.gaps],
        }


@dataclass(frozen=True)
class CoverageCertificate:
    """Machine-readable proof of what one discovery invocation completed."""

    source: str
    library_id: str
    query_fingerprint: str
    epoch_started_at: datetime
    epoch_completed_at: datetime | None
    complete: bool
    terminal: bool
    observations_count: int
    quarantined_count: int = 0
    partitions: tuple[CoveragePartition, ...] = ()
    intentional_skips: tuple[str, ...] = ()
    gaps: tuple[CoverageGap, ...] = ()
    source_lag_max_seconds: int | None = None
    metrics: Mapping[str, int | float | str | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.complete:
            if not self.terminal or self.epoch_completed_at is None:
                raise ValueError("complete coverage requires a terminal completion")
            if self.gaps or any(not part.complete for part in self.partitions):
                raise ValueError("complete coverage cannot contain gaps")
        if self.epoch_started_at.tzinfo is None:
            raise ValueError("epoch_started_at must be timezone-aware")
        if self.epoch_completed_at is not None and self.epoch_completed_at.tzinfo is None:
            raise ValueError("epoch_completed_at must be timezone-aware")

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "library_id": self.library_id,
            "query_fingerprint": self.query_fingerprint,
            "epoch_started_at": format_timestamp(self.epoch_started_at),
            "epoch_completed_at": format_timestamp(self.epoch_completed_at),
            "complete": self.complete,
            "terminal": self.terminal,
            "observations_count": self.observations_count,
            "quarantined_count": self.quarantined_count,
            "partitions": [part.to_dict() for part in self.partitions],
            "intentional_skips": list(self.intentional_skips),
            "gaps": [gap.to_dict() for gap in self.gaps],
            "source_lag_max_seconds": self.source_lag_max_seconds,
            "metrics": dict(self.metrics),
        }


@dataclass(frozen=True)
class DiscoveryResult:
    observations: tuple[DiscoveryObservation, ...]
    quarantined_observations: tuple[DiscoveryObservation, ...]
    certificate: CoverageCertificate

    def require_complete(self) -> tuple[DiscoveryObservation, ...]:
        if not self.certificate.complete:
            codes = ",".join(gap.code for gap in self.certificate.gaps) or "incomplete"
            raise IncompleteCoverageError(
                "%s discovery coverage is incomplete: %s"
                % (self.certificate.source, codes)
            )
        return self.observations


@dataclass(frozen=True)
class CompositeDiscoveryResult:
    """Union of independently certified source/query results."""

    observations: tuple[DiscoveryObservation, ...]
    quarantined_observations: tuple[DiscoveryObservation, ...]
    certificates: tuple[CoverageCertificate, ...]
    complete: bool
    reasons: tuple[str, ...] = ()

    def require_complete(self) -> tuple[DiscoveryObservation, ...]:
        if not self.complete:
            raise IncompleteCoverageError(
                "composite discovery coverage is incomplete: %s"
                % (",".join(self.reasons) or "incomplete")
            )
        return self.observations

    def to_dict(self) -> dict:
        return {
            "complete": self.complete,
            "reasons": list(self.reasons),
            "observations_count": len(self.observations),
            "quarantined_count": len(self.quarantined_observations),
            "certificates": [certificate.to_dict() for certificate in self.certificates],
        }


def _observation_lane(observation: DiscoveryObservation) -> tuple[str, ...]:
    """Identity for one durable evidence lane.

    Commit and repository name are intentionally not part of the key.  A newer
    observation updates those values after a branch advance or repository
    rename, while evidence from different sources, signals, and paths remains
    independently auditable.
    """
    return (
        observation.library_id,
        observation.signal_id,
        observation.source,
        observation.matched_path or "",
    )


def _merge_observation(
    old: DiscoveryObservation, new: DiscoveryObservation
) -> DiscoveryObservation:
    newest, older = (new, old) if new.observed_at >= old.observed_at else (old, new)
    return replace(
        newest,
        repo_node_id=newest.repo_node_id or older.repo_node_id,
        matched_path=newest.matched_path or older.matched_path,
        matched_blob=newest.matched_blob or older.matched_blob,
        matched_commit=newest.matched_commit or older.matched_commit,
        source_fetched_at=newest.source_fetched_at or older.source_fetched_at,
        source_lag_seconds=(
            newest.source_lag_seconds
            if newest.source_lag_seconds is not None
            else older.source_lag_seconds
        ),
        partition=newest.partition or older.partition,
    )


def durable_union(
    previous: Iterable[DiscoveryObservation],
    current: Iterable[DiscoveryObservation],
) -> tuple[DiscoveryObservation, ...]:
    """Return a deterministic, additive union of discovery evidence.

    Absence from a later search never deletes an earlier observation.  The
    function is pure so state/migration tests can prove this property without a
    database or network.
    """
    records: list[DiscoveryObservation | None] = []
    by_node: dict[tuple[str, tuple[str, ...]], int] = {}
    by_name: dict[tuple[str, tuple[str, ...]], int] = {}
    for observation in tuple(previous) + tuple(current):
        lane = _observation_lane(observation)
        indexes: set[int] = set()
        if observation.repo_node_id:
            index = by_node.get((observation.repo_node_id, lane))
            if index is not None:
                indexes.add(index)
        index = by_name.get((observation.repo_full_name.casefold(), lane))
        if index is not None:
            indexes.add(index)
        if not indexes:
            target = len(records)
            records.append(observation)
        else:
            target = min(indexes)
            current_record = records[target]
            assert current_record is not None
            current_record = _merge_observation(current_record, observation)
            for duplicate in sorted(indexes - {target}):
                duplicate_record = records[duplicate]
                if duplicate_record is not None:
                    current_record = _merge_observation(current_record, duplicate_record)
                    records[duplicate] = None
                    for mapping in (by_node, by_name):
                        for key, value in tuple(mapping.items()):
                            if value == duplicate:
                                mapping[key] = target
            records[target] = current_record
        merged = records[target]
        assert merged is not None
        # Retain both old and new names as aliases so a node-ID enrichment and a
        # later rename coalesce rather than creating parallel candidate rows.
        by_name[(observation.repo_full_name.casefold(), lane)] = target
        by_name[(merged.repo_full_name.casefold(), lane)] = target
        if observation.repo_node_id:
            by_node[(observation.repo_node_id, lane)] = target
        if merged.repo_node_id:
            by_node[(merged.repo_node_id, lane)] = target
    compact = [record for record in records if record is not None]
    return tuple(
        sorted(
            compact,
            key=lambda item: (
                item.library_id.casefold(),
                item.repo_full_name.casefold(),
                item.signal_id.casefold(),
                item.source.casefold(),
                (item.matched_path or "").casefold(),
            ),
        )
    )


def combine_discovery_results(
    previous: Iterable[DiscoveryObservation],
    results: Iterable[DiscoveryResult],
    *,
    required_sources: Iterable[str] = (),
    advisory_sources: Iterable[str] = (),
) -> CompositeDiscoveryResult:
    """Combine required lanes without consuming incomplete advisory evidence.

    Complete lanes are still represented in the quarantine when a sibling lane
    fails. A caller may explicitly name sources whose complete observations
    add recall but whose incomplete public-service response is non-authoritative;
    those partial observations remain quarantined and do not invalidate an
    independently complete required source.
    """
    materialized = tuple(results)
    certificates = tuple(result.certificate for result in materialized)
    present = {certificate.source for certificate in certificates}
    missing = sorted(set(required_sources) - present)
    advisory = set(advisory_sources)
    incomplete = sorted(
        {
            "%s:%s" % (certificate.source, certificate.query_fingerprint)
            for certificate in certificates
            if not certificate.complete
            and certificate.source not in advisory
        }
    )
    reasons = tuple(
        ["missing_source:%s" % source for source in missing]
        + ["incomplete_lane:%s" % lane for lane in incomplete]
    )
    accepted: tuple[DiscoveryObservation, ...] = tuple(previous)
    partial: list[DiscoveryObservation] = []
    for result in materialized:
        if result.certificate.complete:
            accepted = durable_union(accepted, result.observations)
        else:
            partial.extend(result.quarantined_observations)
    complete = not reasons
    if complete:
        return CompositeDiscoveryResult(
            observations=accepted,
            quarantined_observations=(),
            certificates=certificates,
            complete=True,
        )
    quarantine = durable_union(accepted, partial)
    return CompositeDiscoveryResult(
        observations=(),
        quarantined_observations=quarantine,
        certificates=certificates,
        complete=False,
        reasons=reasons,
    )


@dataclass(frozen=True)
class CoverageEpochRule:
    source: str
    max_age: timedelta
    require_terminal: bool = True


DEFAULT_COVERAGE_RULES = (
    CoverageEpochRule("github-code-search", timedelta(days=28)),
)


@dataclass(frozen=True)
class CoverageEpochAssessment:
    complete: bool
    missing_sources: tuple[str, ...]
    stale_sources: tuple[str, ...]
    incomplete_sources: tuple[str, ...]
    certificate_times: Mapping[str, str]

    def to_dict(self) -> dict:
        return {
            "complete": self.complete,
            "missing_sources": list(self.missing_sources),
            "stale_sources": list(self.stale_sources),
            "incomplete_sources": list(self.incomplete_sources),
            "certificate_times": dict(self.certificate_times),
        }


def assess_coverage_epoch(
    certificates: Sequence[CoverageCertificate],
    *,
    library_id: str,
    now: datetime,
    rules: Sequence[CoverageEpochRule] = DEFAULT_COVERAGE_RULES,
) -> CoverageEpochAssessment:
    """Assess whether every required source has a fresh, complete certificate."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    matching = [c for c in certificates if c.library_id == library_id]
    missing: list[str] = []
    stale: list[str] = []
    incomplete: list[str] = []
    times: dict[str, str] = {}
    for rule in rules:
        source_certs = [c for c in matching if c.source == rule.source]
        if not source_certs:
            missing.append(rule.source)
            continue
        cert = max(
            source_certs,
            key=lambda c: c.epoch_completed_at or c.epoch_started_at,
        )
        completed = cert.epoch_completed_at
        if not cert.complete or (rule.require_terminal and not cert.terminal):
            incomplete.append(rule.source)
            continue
        assert completed is not None  # guaranteed by CoverageCertificate
        times[rule.source] = format_timestamp(completed) or ""
        if completed > now or now - completed > rule.max_age:
            stale.append(rule.source)
    return CoverageEpochAssessment(
        complete=not (missing or stale or incomplete),
        missing_sources=tuple(sorted(missing)),
        stale_sources=tuple(sorted(stale)),
        incomplete_sources=tuple(sorted(incomplete)),
        certificate_times=times,
    )


def can_retire_candidate(
    epoch: CoverageEpochAssessment,
    *,
    metadata_resolved: bool,
    current_tree_resolved: bool,
    current_tree_has_evidence: bool,
) -> bool:
    """Absence alone is insufficient; retirement needs coverage and verification."""
    return (
        epoch.complete
        and metadata_resolved
        and current_tree_resolved
        and not current_tree_has_evidence
    )
