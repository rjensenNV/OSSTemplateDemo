"""Strict Sourcegraph streaming discovery adapter.

The public stream is valuable only when it supplies both a ``progress`` event
with ``done=true`` and Sourcegraph's required final ``event: done`` SSE marker.
Valid matches from a malformed, truncated, capped, timed-out, or unexpectedly
skipped stream are returned as quarantined evidence and cannot be consumed
through :meth:`DiscoveryResult.require_complete`.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, Iterator

from .base import (
    PUBLIC,
    CoverageCertificate,
    CoverageGap,
    CoveragePartition,
    DiscoveryObservation,
    DiscoveryResult,
    parse_timestamp,
    utc_now,
)
from .query_plan import SOURCEGRAPH_RESULT_LIMIT


SOURCE = "sourcegraph"
SOURCEGRAPH_TIMEOUT_BOUNDARY_MS = 59_000
DEFAULT_INTENTIONAL_SKIPS = frozenset(
    {
        "excluded-archive",
        "excluded-archives",
        "excluded-fork",
        "excluded-forks",
        "repository-archive",
        "repository-fork",
    }
)


class SourcegraphStreamError(ValueError):
    """The SSE framing or payload is malformed."""


@dataclass(frozen=True)
class SSEEvent:
    name: str
    data: str


def _iter_lines(payload: str | bytes | Iterable[str | bytes]) -> Iterator[str]:
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise SourcegraphStreamError("SSE stream is not valid UTF-8") from exc
    if isinstance(payload, str):
        for line in payload.splitlines():
            yield line
        return
    for raw in payload:
        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise SourcegraphStreamError("SSE stream is not valid UTF-8") from exc
        if not isinstance(raw, str):
            raise SourcegraphStreamError("SSE transport yielded a non-text line")
        # Streaming transports vary: some retain and some remove newlines.
        for line in raw.splitlines() or [""]:
            yield line


def parse_sse(payload: str | bytes | Iterable[str | bytes]) -> tuple[SSEEvent, ...]:
    """Parse enough of the SSE standard for Sourcegraph's stream endpoint."""
    events: list[SSEEvent] = []
    name: str | None = None
    data_lines: list[str] = []

    def flush() -> None:
        nonlocal name, data_lines
        if name is None and not data_lines:
            return
        if not name:
            raise SourcegraphStreamError("SSE event is missing its event name")
        if not data_lines:
            raise SourcegraphStreamError("SSE event %r is missing data" % name)
        events.append(SSEEvent(name=name, data="\n".join(data_lines)))
        name = None
        data_lines = []

    for line in _iter_lines(payload):
        line = line.rstrip("\r")
        if not line:
            flush()
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "event":
            if name is not None:
                raise SourcegraphStreamError("SSE event contains duplicate event fields")
            name = value
        elif field == "data":
            data_lines.append(value)
        elif field in ("id", "retry"):
            continue
        else:
            raise SourcegraphStreamError("unsupported SSE field %r" % field)
    flush()
    return tuple(events)


def _canonical_skip_reason(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return "-".join(value.strip().lower().replace("_", "-").split())


def _repo_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if name.casefold().startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.removesuffix(".git").strip("/")
    if name.count("/") != 1 or any(not part for part in name.split("/", 1)):
        return None
    return name


class SourcegraphDiscovery:
    """Transport-injectable Sourcegraph Stream API client.

    ``transport`` receives the final query string and returns the SSE body (a
    string, bytes, or iterable of lines).  The production transport can perform
    HTTP I/O; fixture tests inject static streams.
    """

    def __init__(
        self,
        transport: Callable[[str], str | bytes | Iterable[str | bytes]],
        *,
        allowed_skips: Iterable[str] = DEFAULT_INTENTIONAL_SKIPS,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._transport = transport
        self._allowed_skips = frozenset(
            reason
            for reason in (_canonical_skip_reason(item) for item in allowed_skips)
            if reason
        )
        self._clock = clock
        self._monotonic = monotonic

    @staticmethod
    def complete_query(query: str) -> str:
        """Apply the explicit, intentional public-index coverage policy."""
        terms = query.split()
        folded = tuple(term.casefold() for term in terms)
        additions: list[str] = []
        if not any(term.startswith("patterntype:") for term in folded):
            additions.append("patternType:keyword")
        if not any(term.startswith("repo:") for term in folded):
            additions.append(r"repo:^github\.com/")
        if not any(term.startswith("visibility:") for term in folded):
            additions.append("visibility:public")
        if not any(term.startswith("select:") for term in folded):
            additions.append("select:file")
        if not any(term.startswith("count:") for term in folded):
            additions.append("count:%d" % SOURCEGRAPH_RESULT_LIMIT)
        if not any(term.startswith("timeout:") for term in folded):
            additions.append("timeout:1m")
        if not any(term.startswith("fork:") for term in folded):
            additions.append("fork:no")
        if not any(term.startswith("archived:") for term in folded):
            additions.append("archived:no")
        return " ".join([query.strip()] + additions)

    @staticmethod
    def _numeric_count_limit(query: str) -> int | None:
        match = re.search(r"(?:^|\s)count:(\d+)(?:\s|$)", query)
        if match is None:
            return None
        return int(match.group(1))

    def search(
        self,
        *,
        library_id: str,
        signal_id: str,
        query: str,
        query_fingerprint: str | None = None,
        deadline_monotonic: float | None = None,
    ) -> DiscoveryResult:
        started = self._clock()
        final_query = self.complete_query(query)
        count_limit = self._numeric_count_limit(final_query)
        fingerprint = query_fingerprint or hashlib.sha256(
            final_query.encode("utf-8")
        ).hexdigest()
        gaps: list[CoverageGap] = []
        observations: list[DiscoveryObservation] = []
        intentional_skips: set[str] = set()
        terminal = False
        final_progress: dict = {}
        source_lags: list[int] = []
        events: tuple[SSEEvent, ...] = ()

        try:
            if (
                deadline_monotonic is not None
                and self._monotonic() >= deadline_monotonic
            ):
                raise TimeoutError("wall deadline exhausted before request")
            try:
                payload = self._transport(
                    final_query,
                    deadline_monotonic=deadline_monotonic,
                )
            except TypeError as exc:
                if "deadline_monotonic" not in str(exc):
                    raise
                payload = self._transport(final_query)
            events = parse_sse(payload)
        except Exception as exc:
            gaps.append(
                CoverageGap(
                    (
                        "deadline_exhausted"
                        if isinstance(exc, TimeoutError)
                        or "deadline" in str(exc).casefold()
                        else "malformed_stream"
                    ),
                    "%s: %s" % (type(exc).__name__, str(exc)),
                    retryable=True,
                )
            )

        progress_done_index: int | None = None
        stream_done_index: int | None = None
        for index, event in enumerate(events):
            if (
                deadline_monotonic is not None
                and self._monotonic() >= deadline_monotonic
            ):
                gaps.append(
                    CoverageGap(
                        "deadline_exhausted",
                        "wall deadline exhausted while consuming stream",
                        retryable=True,
                    )
                )
                break
            try:
                data = json.loads(event.data)
            except (TypeError, json.JSONDecodeError) as exc:
                gaps.append(
                    CoverageGap(
                        "malformed_event_json",
                        "event %d (%s): %s" % (index, event.name, exc),
                        retryable=True,
                    )
                )
                continue

            if event.name == "matches":
                if not isinstance(data, list):
                    gaps.append(
                        CoverageGap(
                            "malformed_matches",
                            "matches event %d is not a list" % index,
                            retryable=True,
                        )
                    )
                    continue
                for match_index, match in enumerate(data):
                    if not isinstance(match, dict):
                        gaps.append(
                            CoverageGap(
                                "malformed_match",
                                "event %d match %d is not an object" % (index, match_index),
                            )
                        )
                        continue
                    repo = _repo_name(match.get("repository"))
                    path = match.get("path")
                    commit = match.get("commit")
                    if (
                        repo is None
                        or not isinstance(path, str)
                        or not path
                        or not isinstance(commit, str)
                        or not commit
                    ):
                        gaps.append(
                            CoverageGap(
                                "malformed_match",
                                "event %d match %d lacks repository/path/commit"
                                % (index, match_index),
                            )
                        )
                        continue
                    fetched_raw = (
                        match.get("repoLastFetched")
                        or match.get("repositoryLastFetched")
                        or match.get("lastFetched")
                    )
                    fetched = parse_timestamp(fetched_raw)
                    if fetched_raw is not None and fetched is None:
                        gaps.append(
                            CoverageGap(
                                "malformed_source_timestamp",
                                "event %d match %d has an invalid source timestamp"
                                % (index, match_index),
                            )
                        )
                        continue
                    lag: int | None = None
                    if fetched is not None:
                        lag = int((started - fetched).total_seconds())
                        if lag < 0:
                            gaps.append(
                                CoverageGap(
                                    "future_source_timestamp",
                                    "event %d match %d source timestamp is in the future"
                                    % (index, match_index),
                                )
                            )
                            continue
                        source_lags.append(lag)
                    observations.append(
                        DiscoveryObservation(
                            repo_full_name=repo,
                            library_id=library_id,
                            signal_id=signal_id,
                            source=SOURCE,
                            query_fingerprint=fingerprint,
                            observed_at=started,
                            visibility=PUBLIC,
                            matched_path=path,
                            matched_commit=commit,
                            source_fetched_at=fetched,
                            source_lag_seconds=lag,
                            partition="stream",
                        )
                    )
            elif event.name == "progress":
                if not isinstance(data, dict):
                    gaps.append(
                        CoverageGap(
                            "malformed_progress",
                            "progress event %d is not an object" % index,
                            retryable=True,
                        )
                    )
                    continue
                skipped = data.get("skipped", [])
                if skipped is None:
                    skipped = []
                if not isinstance(skipped, list):
                    gaps.append(
                        CoverageGap(
                            "malformed_skips",
                            "progress event %d skipped value is not a list" % index,
                        )
                    )
                    skipped = []
                for skip in skipped:
                    reason_value = skip.get("reason") if isinstance(skip, dict) else skip
                    reason = _canonical_skip_reason(reason_value)
                    if reason is None:
                        gaps.append(
                            CoverageGap(
                                "malformed_skip",
                                "progress event %d has a skip without a reason" % index,
                            )
                        )
                    elif reason in self._allowed_skips:
                        intentional_skips.add(reason)
                    else:
                        gaps.append(
                            CoverageGap(
                                "unexpected_skip",
                                "Sourcegraph reported non-policy skip %r" % reason,
                                retryable=True,
                            )
                        )
                if data.get("done") is True:
                    if progress_done_index is not None:
                        gaps.append(
                            CoverageGap(
                                "duplicate_progress_done",
                                "stream contains more than one progress done=true event",
                            )
                        )
                    progress_done_index = index
                    final_progress = data
            elif event.name == "done":
                if stream_done_index is not None:
                    gaps.append(
                        CoverageGap(
                            "duplicate_terminal_done",
                            "stream contains more than one terminal done event",
                        )
                    )
                stream_done_index = index
                terminal = True
                if data != {}:
                    gaps.append(
                        CoverageGap(
                            "malformed_terminal_done",
                            "terminal done event data must be an empty object",
                        )
                    )
            elif event.name in ("filters",):
                continue
            else:
                gaps.append(
                    CoverageGap(
                        "unexpected_event",
                        "unexpected Sourcegraph event %r" % event.name,
                        retryable=event.name in ("alert", "error"),
                    )
                )

        if progress_done_index is None:
            gaps.append(
                CoverageGap(
                    "missing_progress_done",
                    "stream ended without progress done=true",
                    retryable=True,
                )
            )
        match_count = final_progress.get("matchCount")
        if progress_done_index is not None and (
            not isinstance(match_count, int)
            or isinstance(match_count, bool)
            or match_count < 0
        ):
            gaps.append(
                CoverageGap(
                    "malformed_match_count",
                    "terminal progress lacks a non-negative integer matchCount",
                    retryable=True,
                )
            )
        if count_limit is None:
            gaps.append(
                CoverageGap(
                    "unsafe_count_policy",
                    "Sourcegraph coverage requires a numeric count ceiling",
                )
            )
        elif isinstance(match_count, int) and match_count >= count_limit:
            gaps.append(
                CoverageGap(
                    "result_limit_reached",
                    "Sourcegraph reached its %d-result coverage ceiling"
                    % count_limit,
                    retryable=False,
                )
            )
        duration_ms = final_progress.get("durationMs")
        if progress_done_index is not None and (
            not isinstance(duration_ms, (int, float))
            or isinstance(duration_ms, bool)
            or duration_ms < 0
        ):
            gaps.append(
                CoverageGap(
                    "malformed_duration",
                    "terminal progress lacks a non-negative durationMs",
                    retryable=True,
                )
            )
        if (
            isinstance(duration_ms, (int, float))
            and not isinstance(duration_ms, bool)
            and duration_ms >= SOURCEGRAPH_TIMEOUT_BOUNDARY_MS
        ):
            gaps.append(
                CoverageGap(
                    "server_timeout_boundary",
                    "Sourcegraph reached its one-minute server search boundary",
                    retryable=True,
                )
            )
        if stream_done_index is None:
            gaps.append(
                CoverageGap(
                    "missing_terminal_done",
                    "stream ended without the required final done event",
                    retryable=True,
                )
            )
        elif stream_done_index != len(events) - 1:
            gaps.append(
                CoverageGap(
                    "nonterminal_done",
                    "terminal done marker was not the final SSE event",
                    retryable=True,
                )
            )

        completed = self._clock()
        complete = (
            terminal
            and progress_done_index is not None
            and not gaps
            and stream_done_index == len(events) - 1
        )
        unique: dict[tuple[str, str, str], DiscoveryObservation] = {}
        for observation in observations:
            unique[
                (
                    observation.repo_full_name.casefold(),
                    observation.matched_path or "",
                    observation.matched_commit or "",
                )
            ] = observation
        valid = tuple(
            unique[key]
            for key in sorted(unique, key=lambda item: tuple(v.casefold() for v in item))
        )
        publishable = valid if complete else ()
        quarantined = () if complete else valid
        partition = CoveragePartition(
            key="stream",
            query=final_query,
            total_count=(
                final_progress.get("matchCount")
                if isinstance(final_progress.get("matchCount"), int)
                and not isinstance(final_progress.get("matchCount"), bool)
                else None
            ),
            fetched_count=len(valid),
            page_count=1,
            complete=complete,
            incomplete_results=not complete,
            gaps=tuple(gaps),
        )
        metrics = {
            key: final_progress[key]
            for key in ("matchCount", "repositoriesCount", "durationMs")
            if isinstance(final_progress.get(key), (int, float))
            and not isinstance(final_progress.get(key), bool)
        }
        certificate = CoverageCertificate(
            source=SOURCE,
            library_id=library_id,
            query_fingerprint=fingerprint,
            epoch_started_at=started,
            epoch_completed_at=completed if terminal else None,
            complete=complete,
            terminal=terminal,
            observations_count=len(publishable),
            quarantined_count=len(quarantined),
            partitions=(partition,),
            intentional_skips=tuple(sorted(intentional_skips)),
            gaps=tuple(gaps),
            source_lag_max_seconds=max(source_lags) if source_lags else None,
            metrics=metrics,
        )
        return DiscoveryResult(publishable, quarantined, certificate)
