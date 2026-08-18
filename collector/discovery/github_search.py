"""Partitioned, fail-closed GitHub REST code-search discovery.

The adapter owns serialization and pacing, but not HTTP.  Its injected
transport makes cap, pagination, visibility, retry, and malformed-response
behavior deterministic in tests.

GitHub's live code-search ``total_count`` and advertised last page are not a
safe completeness boundary for multi-page results. Accepted leaf partitions
therefore either fit in one short response or, at an exact byte size below the
1,000-result API ceiling, are paged through an explicit empty response. The
bounded walk ignores ``Link``, rejects incomplete/malformed pages, and requires
at least as many unique items as the largest count reported by any page.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, Mapping

from .base import (
    PUBLIC,
    CoverageCertificate,
    CoverageGap,
    CoveragePartition,
    DiscoveryObservation,
    DiscoveryResult,
    utc_now,
)


SOURCE = "github-code-search"
DEFAULT_RESULT_CAP = 1_000
DEFAULT_PER_PAGE = 100
# Legacy GitHub code search ignores files at or above 384 KiB.
DEFAULT_MAX_FILE_SIZE = 384 * 1024 - 1
DEFAULT_MAX_PATH_SPLITS = 24
DEFAULT_MAX_PAGINATION_SWEEPS = 3
_SAFE_PATH_TOKEN = re.compile(r"[A-Za-z0-9_.-]{2,}")
_SAFE_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?/"
    r"[A-Za-z0-9_.-]+"
)


@dataclass(frozen=True)
class _Response:
    status: int
    data: object
    headers: Mapping[str, str]


@dataclass(frozen=True)
class _Partition:
    extension: str | None
    size_min: int | None
    size_max: int | None
    path_includes: tuple[str, ...] = ()
    path_excludes: tuple[str, ...] = ()
    repo_excludes: tuple[str, ...] = ()
    member_signal_id: str | None = None

    @property
    def key(self) -> str:
        ext = self.extension or "all"
        size = (
            "%d..%d" % (self.size_min, self.size_max)
            if self.size_min is not None and self.size_max is not None
            else "all"
        )
        path = ",".join(
            ["+" + token for token in self.path_includes]
            + ["-" + token for token in self.path_excludes]
            + ["-repo:" + repo for repo in self.repo_excludes]
        ) or "all"
        member = (
            "member=%s;" % self.member_signal_id
            if self.member_signal_id is not None
            else ""
        )
        return member + "extension=%s;size=%s;path=%s" % (
            ext,
            size,
            path,
        )


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key).lower(): str(item) for key, item in value.items()}


def _normalize_response(value: object) -> _Response:
    if isinstance(value, _Response):
        return value
    if isinstance(value, tuple):
        if len(value) == 3:
            status, data, headers = value
            return _Response(int(status), data, _headers(headers))
        if len(value) == 2:
            data, headers = value
            return _Response(200, data, _headers(headers))
    if hasattr(value, "status") and hasattr(value, "data"):
        return _Response(
            int(getattr(value, "status")),
            getattr(value, "data"),
            _headers(getattr(value, "headers", {})),
        )
    if isinstance(value, Mapping):
        if "status" in value and "data" in value:
            return _Response(
                int(value["status"]), value["data"], _headers(value.get("headers", {}))
            )
        return _Response(200, value, {})
    raise TypeError("search transport returned an unsupported response")


class GitHubCodeSearch:
    """Complete a declared file-class search universe without silent caps."""

    def __init__(
        self,
        transport: Callable[..., object],
        *,
        min_interval: float = 7.0,
        per_page: int = DEFAULT_PER_PAGE,
        result_cap: int = DEFAULT_RESULT_CAP,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_path_splits: int = DEFAULT_MAX_PATH_SPLITS,
        max_retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
        utc_clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if min_interval < 0:
            raise ValueError("min_interval cannot be negative")
        if not 1 <= per_page <= 100:
            raise ValueError("per_page must be between 1 and 100")
        if result_cap < per_page:
            raise ValueError("result_cap cannot be smaller than per_page")
        if max_file_size < 0:
            raise ValueError("max_file_size cannot be negative")
        if max_path_splits <= 0:
            raise ValueError("max_path_splits must be positive")
        self._transport = transport
        self._min_interval = min_interval
        self._per_page = per_page
        self._result_cap = result_cap
        self._max_file_size = max_file_size
        self._max_path_splits = max_path_splits
        self._max_retries = max_retries
        self._sleep = sleep
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._utc_clock = utc_clock
        self._last_request: float | None = None
        self._request_lock = threading.Lock()

    def _wait_for_retry(self, headers: Mapping[str, str]) -> float:
        retry = headers.get("retry-after")
        if retry:
            try:
                return max(0.0, float(retry))
            except ValueError:
                pass
        reset = headers.get("x-ratelimit-reset")
        if reset:
            try:
                return max(0.0, float(reset) - self._wall_time()) + 1.0
            except ValueError:
                pass
        return 60.0

    def _request(
        self,
        query: str,
        page: int,
        deadline_monotonic: float | None = None,
    ) -> _Response:
        """Serialize and pace all calls, including injected production transports."""
        with self._request_lock:
            for attempt in range(self._max_retries + 1):
                now = self._monotonic()
                if deadline_monotonic is not None and now >= deadline_monotonic:
                    return _Response(
                        598, {"error": "wall_deadline_exhausted"}, {}
                    )
                if self._last_request is not None:
                    wait = self._min_interval - (now - self._last_request)
                    if wait > 0:
                        if (
                            deadline_monotonic is not None
                            and wait >= deadline_monotonic - now
                        ):
                            return _Response(
                                598,
                                {"error": "wall_deadline_exhausted"},
                                {},
                            )
                        self._sleep(wait)
                self._last_request = self._monotonic()
                try:
                    transport = self._transport
                    kwargs = {
                        "query": query,
                        "page": page,
                        "per_page": self._per_page,
                        "deadline_monotonic": deadline_monotonic,
                    }
                    if hasattr(transport, "search_code"):
                        call = transport.search_code
                    else:
                        call = transport
                    try:
                        raw = call(**kwargs)
                    except TypeError as exc:
                        if "deadline_monotonic" not in str(exc):
                            raise
                        kwargs.pop("deadline_monotonic")
                        raw = call(**kwargs)
                    response = _normalize_response(raw)
                except Exception as exc:
                    if attempt < self._max_retries:
                        wait = float(2**attempt)
                        if (
                            deadline_monotonic is not None
                            and wait >= deadline_monotonic - self._monotonic()
                        ):
                            return _Response(
                                598,
                                {"error": "wall_deadline_exhausted"},
                                {},
                            )
                        self._sleep(wait)
                        continue
                    return _Response(
                        599,
                        {
                            "error": "transport_error",
                            "type": type(exc).__name__,
                        },
                        {},
                    )
                if response.status not in (403, 429):
                    return response
                if attempt < self._max_retries:
                    wait = self._wait_for_retry(response.headers)
                    if (
                        deadline_monotonic is not None
                        and wait >= deadline_monotonic - self._monotonic()
                    ):
                        return _Response(
                            598,
                            {"error": "wall_deadline_exhausted"},
                            {},
                        )
                    self._sleep(wait)
                    continue
                return response
        raise AssertionError("unreachable")

    @staticmethod
    def _query(base_query: str, partition: _Partition) -> str:
        terms = [base_query.strip()]
        if partition.extension:
            terms.append("extension:%s" % partition.extension)
        if partition.size_min is not None and partition.size_max is not None:
            terms.append("size:%d..%d" % (partition.size_min, partition.size_max))
        terms.extend(
            'path:"%s"' % token for token in partition.path_includes
        )
        terms.extend(
            '-path:"%s"' % token for token in partition.path_excludes
        )
        terms.extend(
            "-repo:%s" % repo for repo in partition.repo_excludes
        )
        return " ".join(terms)

    @staticmethod
    def _repo_peel(
        items: list, partition: _Partition
    ) -> tuple[str, object] | None:
        """Choose a repeated public repository and one membership witness.

        Discovery needs a complete repository candidate universe, not every
        matching file. At an exact-size tie, a repository with several files
        can therefore be accepted from the current response and excluded from
        the complementary remainder. This avoids a linear chain of long
        filename exclusions while retaining a concrete public match witness.
        """
        used = {repo.casefold() for repo in partition.repo_excludes}
        counts: dict[str, tuple[str, int, object]] = {}
        for item in items:
            if not isinstance(item, Mapping):
                continue
            repository = item.get("repository")
            if not isinstance(repository, Mapping):
                continue
            if repository.get("private") is not False:
                continue
            full_name = repository.get("full_name") or repository.get(
                "nameWithOwner"
            )
            if (
                not isinstance(full_name, str)
                or _SAFE_REPOSITORY.fullmatch(full_name) is None
                or full_name.casefold() in used
            ):
                continue
            folded = full_name.casefold()
            previous = counts.get(folded)
            counts[folded] = (
                full_name if previous is None else previous[0],
                1 if previous is None else previous[1] + 1,
                item if previous is None else previous[2],
            )
        repeated = [
            (folded, value)
            for folded, value in counts.items()
            if value[1] > 1
        ]
        if not repeated:
            return None
        _folded, (full_name, _count, witness) = min(
            repeated,
            key=lambda item: (-item[1][1], item[0]),
        )
        return full_name, witness

    @staticmethod
    def _path_split_token(
        items: list, partition: _Partition
    ) -> str | None:
        """Choose a safe path segment for a complementary include/exclude split."""
        used = {
            token.casefold()
            for token in partition.path_includes + partition.path_excludes
        }
        counts: dict[str, tuple[str, int]] = {}
        for item in items:
            if not isinstance(item, Mapping):
                continue
            path = item.get("path")
            if not isinstance(path, str):
                continue
            item_tokens: dict[str, str] = {}
            for segment in path.split("/"):
                if _SAFE_PATH_TOKEN.fullmatch(segment) is None:
                    continue
                folded = segment.casefold()
                if folded in used:
                    continue
                item_tokens.setdefault(folded, segment)
            for folded, token in item_tokens.items():
                previous = counts.get(folded)
                counts[folded] = (
                    token if previous is None else previous[0],
                    1 if previous is None else previous[1] + 1,
                )
        if not counts:
            return None
        target = len(items) / 2
        _folded, (token, _count) = min(
            counts.items(),
            key=lambda item: (
                abs(item[1][1] - target),
                item[0],
            ),
        )
        return token

    @staticmethod
    def _payload(
        response: _Response, partition: _Partition, query: str
    ) -> tuple[int | None, list | None, CoverageGap | None, bool]:
        if response.status != 200:
            return (
                None,
                None,
                CoverageGap(
                    "search_http_error",
                    "GitHub code search returned HTTP %d" % response.status,
                    partition.key,
                    retryable=response.status in (
                        403, 429, 500, 502, 503, 504, 598, 599
                    ),
                ),
                False,
            )
        data = response.data
        if not isinstance(data, Mapping):
            return (
                None,
                None,
                CoverageGap(
                    "malformed_search_response",
                    "GitHub code search payload is not an object",
                    partition.key,
                ),
                False,
            )
        total = data.get("total_count")
        items = data.get("items")
        incomplete = data.get("incomplete_results")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or not isinstance(items, list)
            or not isinstance(incomplete, bool)
        ):
            return (
                None,
                None,
                CoverageGap(
                    "malformed_search_response",
                    "GitHub code search lacks typed total/items/incomplete fields",
                    partition.key,
                ),
                False,
            )
        if incomplete:
            return (
                total,
                items,
                CoverageGap(
                    "incomplete_results",
                    "GitHub marked the search response incomplete",
                    partition.key,
                    retryable=True,
                ),
                True,
            )
        return total, items, None, False

    @staticmethod
    def _has_next_page(response: _Response) -> bool:
        link = response.headers.get("link", "")
        return 'rel="next"' in link or "rel=next" in link

    @staticmethod
    def _item_observation(
        item: object,
        *,
        library_id: str,
        signal_id: str,
        fingerprint: str,
        observed_at: datetime,
        partition: _Partition,
    ) -> tuple[DiscoveryObservation | None, str | None]:
        if not isinstance(item, Mapping):
            return None, "malformed_item"
        repo = item.get("repository")
        if not isinstance(repo, Mapping):
            return None, "malformed_item"
        # A broad credential can return private data.  Only an explicit false
        # private flag crosses this boundary; unknown visibility is quarantined.
        if repo.get("private") is True:
            return None, "explicit_private"
        if repo.get("private") is not False:
            return None, "unverified_visibility"
        full_name = repo.get("full_name") or repo.get("nameWithOwner")
        path = item.get("path")
        blob = item.get("sha")
        if (
            not isinstance(full_name, str)
            or full_name.count("/") != 1
            or any(not part for part in full_name.split("/", 1))
            or not isinstance(path, str)
            or not path
            or not isinstance(blob, str)
            or not blob
        ):
            return None, "malformed_item"
        node_id = repo.get("node_id")
        if node_id is not None and (not isinstance(node_id, str) or not node_id):
            return None, "malformed_item"
        return (
            DiscoveryObservation(
                repo_full_name=full_name,
                repo_node_id=node_id,
                library_id=library_id,
                signal_id=signal_id,
                source=SOURCE,
                query_fingerprint=fingerprint,
                observed_at=observed_at,
                visibility=PUBLIC,
                matched_path=path,
                matched_blob=blob,
                partition=partition.key,
            ),
            None,
        )

    def search(
        self,
        *,
        library_id: str,
        signal_id: str,
        query: str,
        extensions: Iterable[str] = (),
        member_queries: Iterable[str] = (),
        member_signal_ids: Iterable[str] = (),
        query_fingerprint: str | None = None,
        deadline_monotonic: float | None = None,
    ) -> DiscoveryResult:
        """Search a declared extension universe, splitting capped leaves by size."""
        started = self._utc_clock()
        normalized_extensions = tuple(
            sorted(
                {
                    item.strip().lower().removeprefix(".")
                    for item in extensions
                    if isinstance(item, str) and item.strip()
                }
            )
        )
        raw_member_queries = tuple(member_queries)
        raw_member_ids = tuple(member_signal_ids)
        if any(
            not isinstance(item, str) or not item.strip()
            for item in raw_member_queries + raw_member_ids
        ):
            raise ValueError("member query identity fields must be non-empty")
        normalized_member_queries = tuple(
            item.strip() for item in raw_member_queries
        )
        normalized_member_ids = tuple(
            item.strip() for item in raw_member_ids
        )
        if normalized_member_queries:
            if (
                len(normalized_member_queries) != len(normalized_member_ids)
                or len(set(normalized_member_queries))
                != len(normalized_member_queries)
                or len(set(normalized_member_ids))
                != len(normalized_member_ids)
                or " OR ".join(normalized_member_queries) != query.strip()
            ):
                raise ValueError(
                    "member queries must exactly decompose the logical OR pack"
                )
        elif normalized_member_ids:
            raise ValueError("member signal IDs require member queries")
        if len(normalized_member_queries) <= 1:
            execution_queries = ((None, query.strip()),)
        else:
            execution_queries = tuple(
                zip(normalized_member_ids, normalized_member_queries)
            )
        current_query = query.strip()
        fingerprint = query_fingerprint or hashlib.sha256(
            json.dumps(
                {
                    "query": query.strip(),
                    "extensions": normalized_extensions,
                    "max_file_size": self._max_file_size,
                    "max_path_splits": self._max_path_splits,
                    "per_page": self._per_page,
                    "result_cap": self._result_cap,
                    "leaf_policy": "single-empty-page-bounded-retry-v4",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        observations: list[DiscoveryObservation] = []
        partitions: list[CoveragePartition] = []
        gaps: list[CoverageGap] = []
        unverified_visibility = 0
        excluded_private = 0
        malformed_items = 0
        outside_declared_extensions = 0
        request_count = 0
        reported_count_mismatches = 0
        paginated_leaf_count = 0
        pagination_request_count = 0
        pagination_fallback_count = 0
        pagination_sweep_count = 0
        pagination_retry_count = 0

        def item_identity(item: object) -> tuple[str, str, str] | None:
            if not isinstance(item, Mapping):
                return None
            repository = item.get("repository")
            if not isinstance(repository, Mapping):
                return None
            repository_id = (
                repository.get("node_id")
                or repository.get("full_name")
                or repository.get("nameWithOwner")
            )
            path = item.get("path")
            blob = item.get("sha")
            if not all(
                isinstance(value, str) and value
                for value in (repository_id, path, blob)
            ):
                return None
            return repository_id.casefold(), path, blob

        def consume_items(items: list, partition: _Partition) -> None:
            nonlocal unverified_visibility, excluded_private, malformed_items
            nonlocal outside_declared_extensions
            for item in items:
                if (
                    normalized_extensions
                    and partition.extension is None
                    and isinstance(item, Mapping)
                ):
                    path = item.get("path")
                    suffix = (
                        path.rsplit(".", 1)[-1].casefold()
                        if isinstance(path, str) and "." in path
                        else ""
                    )
                    if suffix not in normalized_extensions:
                        outside_declared_extensions += 1
                        continue
                observation, rejection = self._item_observation(
                    item,
                    library_id=library_id,
                    signal_id=signal_id,
                    fingerprint=fingerprint,
                    observed_at=started,
                    partition=partition,
                )
                if observation is not None:
                    observations.append(observation)
                elif rejection == "explicit_private":
                    excluded_private += 1
                elif rejection == "unverified_visibility":
                    unverified_visibility += 1
                    gaps.append(
                        CoverageGap(
                            "unverified_visibility",
                            "search item visibility is unresolved",
                            partition.key,
                        )
                    )
                else:
                    malformed_items += 1
                    gaps.append(
                        CoverageGap(
                            "malformed_search_item",
                            "search item lacks required repository/path/blob fields",
                            partition.key,
                        )
                    )

        def visit(partition: _Partition) -> None:
            nonlocal request_count, reported_count_mismatches
            nonlocal paginated_leaf_count, pagination_request_count
            nonlocal pagination_fallback_count
            nonlocal pagination_sweep_count, pagination_retry_count
            if gaps:
                return
            if (
                deadline_monotonic is not None
                and self._monotonic() >= deadline_monotonic
            ):
                gaps.append(
                    CoverageGap(
                        "deadline_exhausted",
                        "GitHub search wall deadline exhausted",
                        partition.key,
                        retryable=True,
                    )
                )
                return
            built_query = self._query(current_query, partition)
            response = self._request(
                built_query, 1, deadline_monotonic
            )
            request_count += 1
            total, first_items, gap, incomplete = self._payload(
                response, partition, built_query
            )
            if gap is not None:
                gaps.append(gap)
                partitions.append(
                    CoveragePartition(
                        key=partition.key,
                        query=built_query,
                        total_count=total,
                        fetched_count=len(first_items or ()),
                        page_count=1,
                        complete=False,
                        capped=bool(total is not None and total > self._result_cap),
                        incomplete_results=incomplete,
                        extension=partition.extension,
                        size_min=partition.size_min,
                        size_max=partition.size_max,
                        gaps=(gap,),
                    )
                )
                return
            assert total is not None and first_items is not None
            if len(first_items) != total:
                reported_count_mismatches += 1
            # Never accept a potentially multi-page leaf directly. The live
            # endpoint can return distinct items beyond both ``total_count``
            # and its advertised last page, and it can return more items than
            # ``total_count``. Exact-size leaves get the stronger bounded
            # empty-page proof below; all other full responses subdivide.
            requires_split = (
                len(first_items) >= self._per_page
                or self._has_next_page(response)
                or total > len(first_items)
            )
            if requires_split:
                partitions.append(
                    CoveragePartition(
                        key=partition.key,
                        query=built_query,
                        total_count=total,
                        fetched_count=len(first_items),
                        page_count=1,
                        complete=True,
                        capped=total > self._result_cap,
                        subdivided=True,
                        extension=partition.extension,
                        size_min=partition.size_min,
                        size_max=partition.size_max,
                    )
                )
                # Probe the complete base query first. Only a capped base query
                # fans out across the declared file classes. This preserves the
                # extension-completeness contract without paying one zero-result
                # request per extension for every query pack.
                if (
                    partition.extension is None
                    and partition.size_min is None
                    and partition.size_max is None
                    and normalized_extensions
                ):
                    for extension in normalized_extensions:
                        visit(
                            _Partition(
                                extension,
                                None,
                                None,
                                member_signal_id=(
                                    partition.member_signal_id
                                ),
                            )
                        )
                        if gaps:
                            break
                    return
                low = 0 if partition.size_min is None else partition.size_min
                high = (
                    self._max_file_size
                    if partition.size_max is None
                    else partition.size_max
                )
                if low >= high:
                    # At an exact byte size, exhaust a result set that begins
                    # below GitHub's 1,000-row ceiling by walking bounded pages
                    # until the service returns an explicit empty page. Do not
                    # trust total_count or Link as the terminal boundary.
                    if total <= self._result_cap:
                        pagination_gap = None
                        accepted_page = None
                        paged_items = list(first_items)
                        page_count = 1
                        max_reported_total = total
                        max_data_pages = (
                            self._result_cap // self._per_page
                        )
                        for sweep in range(DEFAULT_MAX_PAGINATION_SWEEPS):
                            pagination_sweep_count += 1
                            if sweep:
                                pagination_retry_count += 1
                                first_response = self._request(
                                    built_query, 1, deadline_monotonic
                                )
                                request_count += 1
                                pagination_request_count += 1
                                (
                                    sweep_total,
                                    sweep_items,
                                    sweep_gap,
                                    _sweep_incomplete,
                                ) = self._payload(
                                    first_response, partition, built_query
                                )
                                if sweep_gap is not None:
                                    pagination_gap = sweep_gap
                                    break
                                assert (
                                    sweep_total is not None
                                    and sweep_items is not None
                                )
                                paged_items = list(sweep_items)
                                max_reported_total = sweep_total
                            else:
                                paged_items = list(first_items)
                                max_reported_total = total
                            page_count = 1
                            explicit_empty = False
                            for page in range(2, max_data_pages + 1):
                                page_response = self._request(
                                    built_query, page, deadline_monotonic
                                )
                                request_count += 1
                                pagination_request_count += 1
                                (
                                    page_total,
                                    page_items,
                                    page_gap,
                                    _page_incomplete,
                                ) = self._payload(
                                    page_response, partition, built_query
                                )
                                page_count = page
                                if page_gap is not None:
                                    pagination_gap = page_gap
                                    break
                                assert (
                                    page_total is not None
                                    and page_items is not None
                                )
                                max_reported_total = max(
                                    max_reported_total, page_total
                                )
                                if not page_items:
                                    explicit_empty = True
                                    break
                                paged_items.extend(page_items)
                            if pagination_gap is not None:
                                break
                            identities = [
                                identity
                                for item in paged_items
                                if (
                                    identity := item_identity(item)
                                ) is not None
                            ]
                            unique_count = len(set(identities))
                            if (
                                explicit_empty
                                and len(identities) == len(paged_items)
                                and unique_count >= max_reported_total
                            ):
                                accepted_page = (
                                    list(paged_items),
                                    page_count,
                                    max_reported_total,
                                    unique_count,
                                )
                                break
                        if accepted_page is not None:
                            (
                                paged_items,
                                page_count,
                                max_reported_total,
                                unique_count,
                            ) = accepted_page
                            paginated_leaf_count += 1
                            if unique_count != max_reported_total:
                                reported_count_mismatches += 1
                            partitions[-1] = CoveragePartition(
                                key=partition.key,
                                query=built_query,
                                total_count=max_reported_total,
                                fetched_count=len(paged_items),
                                page_count=page_count,
                                complete=True,
                                capped=False,
                                extension=partition.extension,
                                size_min=partition.size_min,
                                size_max=partition.size_max,
                            )
                            consume_items(paged_items, partition)
                            return
                        if pagination_gap is not None:
                            gaps.append(pagination_gap)
                            partitions[-1] = CoveragePartition(
                                key=partition.key,
                                query=built_query,
                                total_count=max_reported_total,
                                fetched_count=len(paged_items),
                                page_count=page_count,
                                complete=False,
                                capped=False,
                                extension=partition.extension,
                                size_min=partition.size_min,
                                size_max=partition.size_max,
                                gaps=(pagination_gap,),
                            )
                            return
                        pagination_fallback_count += 1
                    token = self._path_split_token(
                        first_items, partition
                    )
                    repo_peel = self._repo_peel(
                        first_items, partition
                    )
                    split_count = (
                        len(partition.path_includes)
                        + len(partition.path_excludes)
                        + len(partition.repo_excludes)
                    )
                    if (
                        repo_peel is not None
                        and split_count < self._max_path_splits
                    ):
                        repo_name, witness = repo_peel
                        consume_items([witness], partition)
                        visit(
                            _Partition(
                                partition.extension,
                                partition.size_min,
                                partition.size_max,
                                partition.path_includes,
                                partition.path_excludes,
                                partition.repo_excludes + (repo_name,),
                                partition.member_signal_id,
                            )
                        )
                        return
                    if (
                        token is not None
                        and split_count < self._max_path_splits
                    ):
                        visit(
                            _Partition(
                                partition.extension,
                                partition.size_min,
                                partition.size_max,
                                partition.path_includes + (token,),
                                partition.path_excludes,
                                partition.repo_excludes,
                                partition.member_signal_id,
                            )
                        )
                        visit(
                            _Partition(
                                partition.extension,
                                partition.size_min,
                                partition.size_max,
                                partition.path_includes,
                                partition.path_excludes + (token,),
                                partition.repo_excludes,
                                partition.member_signal_id,
                            )
                        )
                        return
                    unsplittable = CoverageGap(
                        "unsplittable_page",
                        "one-byte size/path partition still exceeds one response page",
                        partition.key,
                    )
                    gaps.append(unsplittable)
                    partitions[-1] = CoveragePartition(
                        key=partition.key,
                        query=built_query,
                        total_count=total,
                        fetched_count=len(first_items),
                        page_count=1,
                        complete=False,
                        capped=total > self._result_cap,
                        extension=partition.extension,
                        size_min=partition.size_min,
                        size_max=partition.size_max,
                        gaps=(unsplittable,),
                    )
                    return
                midpoint = (low + high) // 2
                visit(
                    _Partition(
                        partition.extension,
                        low,
                        midpoint,
                        partition.path_includes,
                        partition.path_excludes,
                        partition.repo_excludes,
                        partition.member_signal_id,
                    )
                )
                visit(
                    _Partition(
                        partition.extension,
                        midpoint + 1,
                        high,
                        partition.path_includes,
                        partition.path_excludes,
                        partition.repo_excludes,
                        partition.member_signal_id,
                    )
                )
                return

            raw_items = list(first_items)
            part_gaps = tuple(gap for gap in gaps if gap.partition == partition.key)
            complete = not part_gaps
            partitions.append(
                CoveragePartition(
                    key=partition.key,
                    query=built_query,
                    total_count=total,
                    fetched_count=len(raw_items),
                    page_count=1,
                    complete=complete,
                    incomplete_results=any(
                        gap.code == "incomplete_results" for gap in part_gaps
                    ),
                    extension=partition.extension,
                    size_min=partition.size_min,
                    size_max=partition.size_max,
                    gaps=part_gaps,
                )
            )
            if complete:
                consume_items(raw_items, partition)

        for member_signal_id, member_query in execution_queries:
            current_query = member_query
            visit(
                _Partition(
                    None,
                    None,
                    None,
                    member_signal_id=member_signal_id,
                )
            )
            if gaps:
                break

        completed_at = self._utc_clock()
        unique: dict[tuple[str, str, str], DiscoveryObservation] = {}
        for observation in observations:
            unique[
                (
                    observation.repo_node_id
                    or observation.repo_full_name.casefold(),
                    observation.matched_path or "",
                    observation.matched_blob or "",
                )
            ] = observation
        valid = tuple(
            unique[key]
            for key in sorted(unique, key=lambda item: tuple(v.casefold() for v in item))
        )
        complete = not gaps and all(part.complete for part in partitions)
        publishable = valid if complete else ()
        quarantined = () if complete else valid
        certificate = CoverageCertificate(
            source=SOURCE,
            library_id=library_id,
            query_fingerprint=fingerprint,
            epoch_started_at=started,
            epoch_completed_at=completed_at,
            complete=complete,
            terminal=True,
            observations_count=len(publishable),
            quarantined_count=(
                len(quarantined) + unverified_visibility + malformed_items
            ),
            partitions=tuple(partitions),
            gaps=tuple(gaps),
            metrics={
                "request_count": request_count,
                "excluded_non_public_or_unverified": unverified_visibility,
                "excluded_explicit_private": excluded_private,
                "malformed_items": malformed_items,
                "excluded_outside_declared_extensions": (
                    outside_declared_extensions
                ),
                "extensions_count": len(normalized_extensions),
                "base_query_first": True,
                "execution_query_count": len(execution_queries),
                "logical_query_decomposed": len(execution_queries) > 1,
                "member_queries_sha256": hashlib.sha256(
                    json.dumps(
                        normalized_member_queries or (query.strip(),),
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                "reported_count_mismatches": reported_count_mismatches,
                "paginated_leaf_count": paginated_leaf_count,
                "pagination_request_count": pagination_request_count,
                "pagination_fallback_count": pagination_fallback_count,
                "pagination_sweep_count": pagination_sweep_count,
                "pagination_retry_count": pagination_retry_count,
            },
        )
        return DiscoveryResult(publishable, quarantined, certificate)
