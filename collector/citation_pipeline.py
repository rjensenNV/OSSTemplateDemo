"""Stateful, cache-dominant REQ-14 citation enrichment.

The network boundary is an injected source adapter.  This module never imports
the GitHub client and never fetches ``CITATION.cff``: repository-wide CFF text
or already-parsed references must arrive from the scanner's local checkout.
Query snapshots and individual work payloads are persisted in
``StateDB.citation_cache``.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from .fingerprints import fingerprint
from .redaction import redact_sensitive
from .state import StateDB


METHOD_VERSION = "req14-citations-v2"
QUERY_SNAPSHOT_WORK_ID = "__query_snapshot_v1__"
CFF_ANALYSIS_FP = "req14-local-cff-v1"
SCHOLARLY_TYPES = {
    "article",
    "preprint",
    "review",
    "book-chapter",
    "dissertation",
    "report",
    "book",
    "letter",
}
NVIDIA_INSTITUTION_IDS = {"I4210127875", "I1304085615"}

_DOI_RE = re.compile(r"10\.\d{4,9}/[-._;()/:A-Za-z0-9]+", re.IGNORECASE)
_ARXIV_RE = re.compile(
    r"(?:arxiv\.org/abs/|arXiv:\s*)(\d{4}\.\d{4,5}(?:v\d+)?)",
    re.IGNORECASE,
)
_GITHUB_RE = re.compile(
    r"(?:https?://)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
_TRAILING_PUNCTUATION = re.compile(r"[.,);:\]}]+$")


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(moment: datetime.datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def citation_query_fingerprint(
    library: Mapping[str, Any], *, max_works: int | None = None
) -> str:
    """Fingerprint only query/filter semantics, not presentation metadata."""
    library_id = str(library["id"])
    declaration = {
        "method": METHOD_VERSION,
        "query": library.get("citation_query"),
        "cooccur": list(library.get("citation_cooccur", ())),
        "source": library.get("citation_source", "openalex"),
        "filters": library.get("citation_filters", {}),
        "released_on": library.get("released_on"),
        "exclude_nvidia_authored": True,
        "scholarly_types": sorted(SCHOLARLY_TYPES),
    }
    if max_works is not None:
        declaration["max_works"] = int(max_works)
    return fingerprint(f"citation-query:{library_id}", declaration)


def payload_fingerprint(work: Mapping[str, Any]) -> str:
    return fingerprint("citation-work-payload", work)


def _normalize_doi(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    value = re.sub(r"^https?://(?:dx\.)?doi\.org/", "", value, flags=re.IGNORECASE)
    match = _DOI_RE.search(value)
    return _TRAILING_PUNCTUATION.sub("", match.group(0)).lower() if match else None


def parse_cff_references(text: str) -> tuple[str, ...]:
    """Extract normalized DOI references from local CFF text."""
    found = {_normalize_doi(match.group(0)) for match in _DOI_RE.finditer(text or "")}
    for match in _ARXIV_RE.finditer(text or ""):
        arxiv_id = re.sub(r"v\d+$", "", match.group(1), flags=re.IGNORECASE)
        found.add(("10.48550/arxiv." + arxiv_id).lower())
    return tuple(sorted(value for value in found if value))


@dataclasses.dataclass(frozen=True)
class RepositoryCFF:
    """Repository-wide local CFF evidence produced by one HEAD scan."""

    repository_id: str
    full_name: str
    head_sha: str
    text: str | None = None
    references: tuple[str, ...] = ()
    parsed: bool = False


@dataclasses.dataclass(frozen=True)
class CitationQueryResult:
    works: tuple[Mapping[str, Any], ...] = ()
    total: int | None = None
    complete: bool = True
    capped: bool = False
    as_of: str | None = None
    errors: tuple[str, ...] = ()
    new_7d: int | None = None
    growth_90d: Mapping[str, int] | None = None
    growth_365d: Mapping[str, int] | None = None


class CitationSource(Protocol):
    name: str

    def query(
        self,
        library: Mapping[str, Any],
        query_fp: str,
        max_works: int,
    ) -> CitationQueryResult: ...


class OpenAlexCitationSource:
    """Production adapter over the existing stdlib OpenAlex client.

    Network calls occur only when :class:`CitationPipeline` invokes this
    adapter.  Tests use fixture adapters instead.
    """

    name = "OpenAlex (full-text search)"

    def __init__(self, *, clock=_utc_now, log=None) -> None:
        self.clock = clock
        self.log = log or (lambda message: None)
        self._request_budget = None
        self._deadline_monotonic = None

    def configure_deadline(self, deadline_monotonic: float | None) -> None:
        self._deadline_monotonic = deadline_monotonic

    def configure_request_budget(self, limit: int | None) -> None:
        """Reset the exact HTTP-attempt budget for one refresh run."""
        from .openalex_api import RequestBudget

        self._request_budget = RequestBudget(
            limit,
            deadline_monotonic=self._deadline_monotonic,
        )

    @property
    def request_count(self) -> int:
        return int(self._request_budget.used if self._request_budget else 0)

    @staticmethod
    def _filters(
        library: Mapping[str, Any],
        *,
        from_date: datetime.date | None = None,
        to_date: datetime.date | None = None,
    ) -> list[str]:
        terms = ["fulltext.search:" + str(library["citation_query"])]
        terms.extend(
            "fulltext.search:" + str(value)
            for value in library.get("citation_cooccur", ())
        )
        terms.extend(
            "authorships.institutions.lineage:!" + institution_id
            for institution_id in sorted(NVIDIA_INSTITUTION_IDS)
        )
        terms.append("type:" + "|".join(sorted(SCHOLARLY_TYPES)))
        released_on = _library_release_date(library)
        effective_from = max(
            (value for value in (released_on, from_date) if value is not None),
            default=None,
        )
        if effective_from is not None:
            terms.append("from_publication_date:" + effective_from.isoformat())
        if to_date is not None:
            terms.append("to_publication_date:" + to_date.isoformat())
        return terms

    def query(
        self,
        library: Mapping[str, Any],
        query_fp: str,
        max_works: int,
    ) -> CitationQueryResult:
        from . import openalex_api

        filters = self._filters(library)
        total = openalex_api.count(filters, budget=self._request_budget)
        observed_at = self.clock()
        as_of = _iso(observed_at)
        if total is None:
            return CitationQueryResult(
                complete=False,
                as_of=as_of,
                errors=("OpenAlex count failed",),
            )
        if total == 0:
            zero_growth = {"current": 0, "prev": 0}
            return CitationQueryResult(
                total=0,
                complete=True,
                as_of=as_of,
                new_7d=0,
                growth_90d=zero_growth,
                growth_365d=zero_growth,
            )
        messages: list[str] = []
        works, reported_total, capped = openalex_api.works(
            filters,
            max_works,
            messages.append,
            budget=self._request_budget,
        )
        for message in messages:
            self.log(message)
        errors = tuple(message for message in messages if "WARN" in message.upper())
        if total and not works and not errors:
            errors = ("OpenAlex returned no works for a nonzero count",)

        today = observed_at.date()

        new_7d = openalex_api.count(
            self._filters(
                library,
                from_date=today - datetime.timedelta(days=6),
                to_date=today,
            ),
            budget=self._request_budget,
        )

        def growth_window(days: int) -> tuple[dict[str, int] | None, str | None]:
            current = openalex_api.count(
                self._filters(
                    library,
                    from_date=today - datetime.timedelta(days=days),
                    to_date=today,
                ),
                budget=self._request_budget,
            )
            previous = openalex_api.count(
                self._filters(
                    library,
                    from_date=today - datetime.timedelta(days=2 * days),
                    to_date=today - datetime.timedelta(days=days + 1),
                ),
                budget=self._request_budget,
            )
            if current is None or previous is None:
                return None, f"OpenAlex {days}-day growth window failed"
            return {"current": current, "prev": previous}, None

        growth_90d, error_90d = growth_window(90)
        growth_365d, error_365d = growth_window(365)
        errors = errors + tuple(
            error
            for error in (
                "OpenAlex 7-day paper count failed" if new_7d is None else None,
                error_90d,
                error_365d,
            )
            if error
        )
        return CitationQueryResult(
            works=tuple(works),
            total=reported_total if reported_total is not None else total,
            complete=not capped and not errors,
            capped=bool(capped),
            as_of=as_of,
            errors=errors,
            new_7d=new_7d,
            growth_90d=growth_90d,
            growth_365d=growth_365d,
        )

    def resolve_reference(self, reference: str) -> Mapping[str, Any] | None:
        from . import openalex_api

        return openalex_api.work_by_doi(
            reference,
            budget=self._request_budget,
        )

    def extract_repository_urls(
        self, work: Mapping[str, Any]
    ) -> Any:
        # The bounded extractor has no GitHub credential or publication
        # capability. Its result is cached by work payload fingerprint.
        from .citation_extract import extract_repo_urls

        return extract_repo_urls(
            work,
            deadline_monotonic=self._deadline_monotonic,
        )


@dataclasses.dataclass
class CitationRefreshResult:
    document: dict[str, Any]
    publishable: bool
    all_failed: bool
    used_last_good: bool
    metrics: dict[str, int]


def _normalized_repository_url_extraction(value: Any) -> dict[str, Any]:
    """Normalize structured production results and legacy sequence fixtures."""
    if all(
        hasattr(value, field)
        for field in (
            "urls",
            "attempted_sources",
            "successful_sources",
            "errors",
            "status",
            "source_available",
        )
    ):
        status = str(value.status)
        if status not in {"complete", "not_available", "failed"}:
            raise ValueError("repository URL extraction status is invalid")
        attempted = tuple(str(item) for item in value.attempted_sources)
        successful = tuple(str(item) for item in value.successful_sources)
        errors = tuple(
            redact_sensitive(str(item)) for item in value.errors
        )
        source_available = bool(value.source_available)
        if status == "complete" and not successful:
            raise ValueError(
                "complete repository URL extraction lacks a successful source"
            )
        if status == "not_available" and (
            source_available or attempted or successful or errors
        ):
            raise ValueError(
                "not-available repository URL extraction is inconsistent"
            )
        if status == "failed" and (
            not source_available
            or not attempted
            or successful
            or not errors
        ):
            raise ValueError(
                "failed repository URL extraction is inconsistent"
            )
        urls = tuple(value.urls)
    else:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError(
                "repository URL extractor returned an unsupported result"
            )
        # Existing injected fixture adapters returned only a URL sequence. A
        # successful call, including an empty sequence, remains complete.
        urls = tuple(value)
        attempted = ("legacy-extractor",)
        successful = ("legacy-extractor",)
        errors = ()
        status = "complete"
        source_available = True
    if not all(isinstance(item, str) for item in urls):
        raise ValueError("repository URL extraction contains a non-string URL")
    return {
        "urls": urls,
        "attempted_sources": attempted,
        "successful_sources": successful,
        "errors": errors,
        "status": status,
        "source_available": source_available,
    }


def _work_id(work: Mapping[str, Any]) -> str:
    ids = work.get("ids") or {}
    openalex_id = work.get("id") or ids.get("openalex")
    if openalex_id:
        return str(openalex_id).rstrip("/").split("/")[-1]
    doi = _normalize_doi(work.get("doi") or ids.get("doi"))
    if doi:
        return "doi:" + doi
    stable = {
        "title": work.get("title"),
        "publication_date": work.get("publication_date"),
        "year": work.get("publication_year"),
    }
    return "anon:" + hashlib.sha256(_canonical(stable).encode("utf-8")).hexdigest()


def _work_doi(work: Mapping[str, Any]) -> str | None:
    ids = work.get("ids") or {}
    return _normalize_doi(work.get("doi") or ids.get("doi"))


def _is_nvidia_authored(work: Mapping[str, Any]) -> bool:
    for authorship in work.get("authorships", ()) or ():
        for institution in authorship.get("institutions", ()) or ():
            institution_id = str(institution.get("id") or "").rstrip("/").split("/")[-1]
            if institution_id in NVIDIA_INSTITUTION_IDS:
                return True
    return False


def _library_release_date(library: Mapping[str, Any]) -> datetime.date | None:
    raw = library.get("released_on")
    if not raw:
        return None
    try:
        return datetime.date.fromisoformat(str(raw)[:7] + "-01")
    except ValueError as exc:
        raise ValueError(
            f"{library.get('id', 'library')} has invalid released_on: {raw!r}"
        ) from exc


def _eligible_work(
    work: Mapping[str, Any], *, not_before: datetime.date | None = None
) -> bool:
    work_type = work.get("type")
    if (work_type and work_type not in SCHOLARLY_TYPES) or _is_nvidia_authored(work):
        return False
    if not_before is None:
        return True
    raw_date = work.get("publication_date")
    if raw_date:
        try:
            return datetime.date.fromisoformat(str(raw_date)[:10]) >= not_before
        except ValueError:
            return False
    raw_year = work.get("publication_year")
    if raw_year is not None:
        try:
            return int(raw_year) >= not_before.year
        except (TypeError, ValueError):
            return False
    return True


def _title_key(title: str | None) -> str:
    return re.sub(
        r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", (title or "").lower())
    ).strip()


def _paper_row(work: Mapping[str, Any]) -> dict[str, Any]:
    location = work.get("primary_location") or {}
    source = location.get("source") or {}
    doi = _work_doi(work)
    return {
        "title": work.get("title"),
        "doi": doi,
        "year": work.get("publication_year"),
        "publication_date": work.get("publication_date"),
        "venue": source.get("display_name"),
        "cited_by": int(work.get("cited_by_count") or 0),
        "oa_url": (work.get("open_access") or {}).get("oa_url"),
        "repo": None,
        "repo_url": None,
        "code_available": False,
    }


def _repo_urls(work: Mapping[str, Any]) -> tuple[str, ...]:
    explicit = work.get("repository_urls") or work.get("repo_urls") or ()
    if isinstance(explicit, str):
        explicit = (explicit,)
    found = set()
    for value in explicit:
        rendered = str(value)
        match = _GITHUB_RE.search(rendered)
        if match:
            name = _TRAILING_PUNCTUATION.sub("", match.group(2))
            if name.lower().endswith(".git"):
                name = name[:-4]
            found.add(f"{match.group(1)}/{name}")
            continue
        plain = re.fullmatch(
            r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", rendered.strip()
        )
        if plain:
            found.add(f"{plain.group(1)}/{plain.group(2)}")
    return tuple(sorted(found, key=str.lower))


def _months(start: str, end: str) -> list[str]:
    year, month = map(int, start.split("-"))
    end_year, end_month = map(int, end.split("-"))
    result = []
    while (year, month) <= (end_year, end_month):
        result.append(f"{year:04d}-{month:02d}")
        month += 1
        if month == 13:
            year += 1
            month = 1
    return result


def _monthly(rows: Sequence[Mapping[str, Any]], today: datetime.date) -> list[dict[str, Any]]:
    dates = []
    today_iso = today.isoformat()
    for row in rows:
        date = row.get("publication_date")
        if not date and row.get("year"):
            date = f"{int(row['year']):04d}-01-01"
        date = min(str(date or today_iso), today_iso)
        dates.append(date[:7])
    if not dates:
        return []
    counts: dict[str, int] = {}
    for month in dates:
        counts[month] = counts.get(month, 0) + 1
    cumulative = 0
    result = []
    for month in _months(min(dates), max(today.strftime("%Y-%m"), min(dates))):
        cumulative += counts.get(month, 0)
        result.append({"month": month, "cumulative": cumulative})
    return result


class CitationPipeline:
    def __init__(
        self,
        state: StateDB,
        source: CitationSource,
        *,
        clock=_utc_now,
        refresh_after: datetime.timedelta = datetime.timedelta(days=6),
    ) -> None:
        self.state = state
        self.source = source
        self.clock = clock
        self.refresh_after = refresh_after

    def _cached_rows(self, library_id: str, query_fp: str) -> dict[str, dict[str, Any]]:
        rows = self.state.connection.execute(
            """
            SELECT work_id, payload_fp, payload_json, source_json, status, fetched_at
            FROM citation_cache
            WHERE library_id=? AND query_fp=?
            ORDER BY work_id
            """,
            (library_id, query_fp),
        )
        return {row["work_id"]: dict(row) for row in rows}

    def _latest_snapshot(
        self, library_id: str, *, excluding_query_fp: str
    ) -> dict[str, Any] | None:
        row = self.state.connection.execute(
            """
            SELECT work_id, payload_fp, payload_json, source_json, status, fetched_at
            FROM citation_cache
            WHERE library_id=? AND work_id=? AND query_fp != ?
            ORDER BY fetched_at DESC, query_fp
            LIMIT 1
            """,
            (library_id, QUERY_SNAPSHOT_WORK_ID, excluding_query_fp),
        ).fetchone()
        return dict(row) if row is not None else None

    def _public_repository_names(self, values: Sequence[str]) -> list[str]:
        """Normalize extracted GitHub links and retain explicit-public repos only."""
        normalized = _repo_urls({"repository_urls": values})
        admitted = []
        for full_name in normalized:
            row = self.state.connection.execute(
                """
                SELECT full_name FROM repositories
                WHERE visibility='public' AND lower(full_name)=lower(?)
                """,
                (full_name,),
            ).fetchone()
            if row is not None:
                admitted.append(row["full_name"])
        return sorted(set(admitted), key=str.lower)

    @staticmethod
    def _decode(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        try:
            value = json.loads(row["payload_json"])
            return value if isinstance(value, dict) else None
        except (KeyError, TypeError, json.JSONDecodeError):
            return None

    def _snapshot_is_fresh(
        self, row: Mapping[str, Any] | None, now: datetime.datetime
    ) -> bool:
        if row is None or row.get("status") != "fresh":
            return False
        fetched = _parse_iso(row.get("fetched_at"))
        return bool(fetched and now - fetched < self.refresh_after)

    def _prepare_cff(
        self,
        repository_cff: Sequence[RepositoryCFF],
        metrics: dict[str, int],
    ) -> dict[tuple[str, str], tuple[str, ...]]:
        prepared: dict[tuple[str, str], tuple[str, ...]] = {}
        seen_fingerprints: dict[tuple[str, str], str] = {}
        for item in repository_cff:
            key = (item.repository_id, item.head_sha)
            admitted = self.state.connection.execute(
                """
                SELECT full_name, head_sha FROM repositories
                WHERE node_id=? AND visibility='public'
                """,
                (item.repository_id,),
            ).fetchone()
            if (
                admitted is None
                or admitted["full_name"].lower() != item.full_name.lower()
                or admitted["head_sha"] != item.head_sha
            ):
                metrics["cff_state_rejections"] += 1
                continue
            references = tuple(
                sorted(
                    {
                        normalized
                        for value in item.references
                        if (normalized := _normalize_doi(value))
                    }
                )
            )
            cff_fp = fingerprint(
                "repository-cff",
                {"text": item.text} if item.text is not None else {"references": references},
            )
            if key in seen_fingerprints:
                if seen_fingerprints[key] != cff_fp:
                    raise ValueError("conflicting CFF evidence for one repository HEAD")
                continue
            seen_fingerprints[key] = cff_fp
            # Pre-parsed references are repository-wide scanner/state results;
            # consuming them must not parse or persist the CFF again.
            if item.parsed:
                metrics["cff_cache_hits"] += 1
                prepared[key] = references
                continue
            row = self.state.connection.execute(
                """
                SELECT analysis_json FROM repo_analysis
                WHERE repository_id=? AND head_sha=? AND ai_fp=? AND cff_fp=?
                  AND status='clean'
                """,
                (item.repository_id, item.head_sha, CFF_ANALYSIS_FP, cff_fp),
            ).fetchone()
            if row is not None:
                try:
                    cached = json.loads(row["analysis_json"])
                    references = tuple(cached.get("citation_refs", ()))
                    metrics["cff_cache_hits"] += 1
                except (TypeError, json.JSONDecodeError):
                    row = None
            if row is None:
                if item.text is not None:
                    references = parse_cff_references(item.text)
                    metrics["cff_parses"] += 1
                try:
                    self.state.record_repo_analysis(
                        repository_id=item.repository_id,
                        head_sha=item.head_sha,
                        ai_fp=CFF_ANALYSIS_FP,
                        cff_fp=cff_fp,
                        analysis={
                            "citation_refs": list(references),
                            "full_name": item.full_name,
                        },
                        status="clean",
                    )
                except ValueError:
                    # Defense in depth if repository state changed between
                    # admission and persistence.
                    metrics["cff_state_rejections"] += 1
                    continue
            prepared[key] = references
        metrics["cff_heads"] = len(prepared)
        return prepared

    def _state_cff(self) -> tuple[RepositoryCFF, ...]:
        """Load prior repository-wide parsed CFF results for unchanged HEADs."""
        rows = self.state.connection.execute(
            """
            SELECT r.node_id, r.full_name, a.head_sha, a.analysis_json
            FROM repo_analysis a
            JOIN repositories r ON r.node_id = a.repository_id
            WHERE a.ai_fp=? AND a.status='clean' AND r.visibility='public'
              AND a.head_sha=r.head_sha
            ORDER BY r.node_id, a.head_sha
            """,
            (CFF_ANALYSIS_FP,),
        )
        result = []
        for row in rows:
            try:
                analysis = json.loads(row["analysis_json"])
                references = tuple(analysis.get("citation_refs", ()))
            except (TypeError, json.JSONDecodeError):
                continue
            result.append(
                RepositoryCFF(
                    repository_id=row["node_id"],
                    full_name=row["full_name"],
                    head_sha=row["head_sha"],
                    references=references,
                    parsed=True,
                )
            )
        return tuple(result)

    def _last_good(
        self,
        snapshot: Mapping[str, Any] | None,
        *,
        error: str,
    ) -> dict[str, Any] | None:
        payload = self._decode(snapshot)
        record = (payload or {}).get("library_record")
        if not isinstance(record, dict):
            return None
        carried = dict(record)
        carried["stale"] = True
        carried["new_since_last"] = 0
        carried["new_7d"] = None
        carried["errors"] = [error]
        coverage = dict(carried.get("coverage") or {})
        coverage.update({"stale": True, "carried_forward": True, "complete": False})
        carried["coverage"] = coverage
        return carried

    def refresh(
        self,
        libraries: Sequence[Mapping[str, Any]],
        *,
        repository_cff: Sequence[RepositoryCFF] = (),
        confirmed_repositories: Mapping[str, Sequence[str]] | None = None,
        max_works: int = 400,
        max_extract: int = 200,
        max_openalex_requests: int | None = None,
        max_source_extractions: int | None = None,
        deadline_monotonic: float | None = None,
        force: bool = False,
    ) -> CitationRefreshResult:
        """Refresh citation state and return a publication-ready document.

        ``confirmed_repositories`` values may contain public repository node IDs
        or ``owner/name`` strings.  CFF parsing happens before the per-library
        loop and is keyed by repository node ID plus HEAD.
        """
        if max_works <= 0:
            raise ValueError("max_works must be positive")
        if max_extract < 0:
            raise ValueError("max_extract cannot be negative")
        if max_openalex_requests is not None and max_openalex_requests < 0:
            raise ValueError("max_openalex_requests cannot be negative")
        if max_source_extractions is not None and max_source_extractions < 0:
            raise ValueError("max_source_extractions cannot be negative")
        def check_deadline():
            if (
                deadline_monotonic is not None
                and time.monotonic() >= deadline_monotonic
            ):
                raise TimeoutError("citation wall deadline exhausted")

        check_deadline()
        confirmed_repositories = confirmed_repositories or {}
        now = self.clock()
        if not isinstance(now, datetime.datetime):
            raise TypeError("clock must return datetime")
        if now.tzinfo is None:
            now = now.replace(tzinfo=datetime.timezone.utc)
        metrics = {
            "query_cache_hits": 0,
            "query_calls": 0,
            "work_cache_hits": 0,
            "work_cache_writes": 0,
            "resolve_calls": 0,
            "resolve_cache_hits": 0,
            "source_extract_calls": 0,
            "source_extract_cache_hits": 0,
            "source_extract_budget_skips": 0,
            "cff_heads": 0,
            "cff_parses": 0,
            "cff_cache_hits": 0,
            "cff_state_rejections": 0,
        }
        configure_request_budget = getattr(
            self.source, "configure_request_budget", None
        )
        configure_deadline = getattr(self.source, "configure_deadline", None)
        if callable(configure_deadline):
            configure_deadline(deadline_monotonic)
        exact_request_budget = callable(configure_request_budget)
        if exact_request_budget:
            configure_request_budget(max_openalex_requests)
        logical_source_requests = 0

        def reserve_source_request() -> None:
            """Enforce a logical-call budget for non-OpenAlex fixture adapters."""
            nonlocal logical_source_requests
            if exact_request_budget:
                return
            if (
                max_openalex_requests is not None
                and logical_source_requests >= max_openalex_requests
            ):
                raise RuntimeError(
                    "citation source request budget exhausted (%d/%d)"
                    % (logical_source_requests, max_openalex_requests)
                )
            logical_source_requests += 1
        merged_cff = {
            (item.repository_id, item.head_sha): item for item in self._state_cff()
        }
        merged_cff.update(
            {(item.repository_id, item.head_sha): item for item in repository_cff}
        )
        repository_cff = tuple(merged_cff.values())
        cff_by_head = self._prepare_cff(repository_cff, metrics)
        cff_items = {
            (item.repository_id, item.head_sha): item
            for item in repository_cff
            if (item.repository_id, item.head_sha) in cff_by_head
        }
        resolved_refs: dict[str, Mapping[str, Any] | None] = {}
        resolution_errors: dict[str, str] = {}
        output: dict[str, Any] = {}
        failures = 0
        carried = 0
        quality: dict[str, Any] = {}

        for library in sorted(libraries, key=lambda item: str(item["id"])):
            check_deadline()
            library_id = str(library["id"])
            if not library.get("citation_query"):
                continue
            query_fp = citation_query_fingerprint(library, max_works=max_works)
            cached = self._cached_rows(library_id, query_fp)
            snapshot_row = cached.get(QUERY_SNAPSHOT_WORK_ID)
            snapshot = self._decode(snapshot_row)

            confirmed: set[str] = set()
            confirmed_names: dict[str, str] = {}
            for value in confirmed_repositories.get(library_id, ()):
                rendered = str(value)
                admitted_repo = self.state.connection.execute(
                    """
                    SELECT node_id, full_name FROM repositories
                    WHERE visibility='public'
                      AND (node_id=? OR lower(full_name)=lower(?))
                    """,
                    (rendered, rendered),
                ).fetchone()
                if admitted_repo is None:
                    continue
                confirmed.add(admitted_repo["node_id"].lower())
                confirmed.add(admitted_repo["full_name"].lower())
                confirmed_names[admitted_repo["full_name"].lower()] = admitted_repo[
                    "full_name"
                ]
            cff_repos_by_ref: dict[str, set[str]] = {}
            local_evidence = []
            for key, references in cff_by_head.items():
                item = cff_items[key]
                if (
                    item.repository_id.lower() not in confirmed
                    and item.full_name.lower() not in confirmed
                ):
                    continue
                local_evidence.append(
                    {
                        "repository_id": item.repository_id,
                        "head_sha": item.head_sha,
                        "references": list(references),
                    }
                )
                for reference in references:
                    cff_repos_by_ref.setdefault(reference, set()).add(
                        item.full_name
                    )
            local_fp = fingerprint(
                f"citation-local-links:{library_id}",
                {
                    "confirmed": sorted(confirmed),
                    "cff": sorted(
                        local_evidence,
                        key=lambda value: (
                            value["repository_id"], value["head_sha"]
                        ),
                    ),
                    "max_extract": max_extract,
                },
            )

            cached_query = not force and self._snapshot_is_fresh(snapshot_row, now)
            if cached_query and (snapshot or {}).get("local_fp") == local_fp:
                record = (snapshot or {}).get("library_record")
                cached_coverage = (
                    (record.get("coverage") or {})
                    if isinstance(record, dict)
                    else {}
                )
                if (
                    isinstance(record, dict)
                    and cached_coverage.get("local_enrichment_complete", True)
                ):
                    output[library_id] = record
                    metrics["query_cache_hits"] += 1
                    metrics["work_cache_hits"] += len(
                        (snapshot or {}).get("work_ids", ())
                    )
                    quality[library_id] = record.get("coverage", {})
                    continue

            if cached_query:
                cached_coverage = (snapshot or {}).get("coverage") or {}
                cached_works = tuple(
                    payload
                    for work_id in (snapshot or {}).get("work_ids", ())
                    if (
                        payload := self._decode(cached.get(work_id))
                    )
                )
                query_result = CitationQueryResult(
                    works=cached_works,
                    total=cached_coverage.get("source_total"),
                    complete=bool(cached_coverage.get("complete")),
                    capped=bool(cached_coverage.get("capped")),
                    as_of=cached_coverage.get("as_of"),
                    errors=tuple(cached_coverage.get("errors", ())),
                    new_7d=((snapshot or {}).get("library_record") or {}).get(
                        "new_7d"
                    ),
                    growth_90d=((snapshot or {}).get("library_record") or {}).get(
                        "growth_90d"
                    ),
                    growth_365d=((snapshot or {}).get("library_record") or {}).get(
                        "growth_365d"
                    ),
                )
                metrics["query_cache_hits"] += 1
                metrics["work_cache_hits"] += len(cached_works)
            else:
                metrics["query_calls"] += 1
                try:
                    reserve_source_request()
                    query_result = self.source.query(library, query_fp, max_works)
                    if not isinstance(query_result, CitationQueryResult):
                        raise TypeError("citation source returned an invalid query result")
                except Exception as exc:
                    query_result = CitationQueryResult(
                        complete=False,
                        as_of=_iso(now),
                        errors=(
                            redact_sensitive(
                                f"{type(exc).__name__}: {exc}"
                            ),
                        ),
                    )
            query_result = dataclasses.replace(
                query_result,
                errors=tuple(
                    redact_sensitive(error)
                    for error in query_result.errors
                ),
            )

            hard_failure = (
                not query_result.complete
                and not query_result.works
                and bool(query_result.errors)
            )
            if hard_failure:
                failures += 1
                error = "; ".join(query_result.errors)
                prior_row = snapshot_row or self._latest_snapshot(
                    library_id, excluding_query_fp=query_fp
                )
                prior = self._last_good(prior_row, error=error)
                if prior is not None:
                    output[library_id] = prior
                    quality[library_id] = prior["coverage"]
                    carried += 1
                    prior_payload = self._decode(prior_row) or {}
                    stale_payload = {
                        "library_record": prior,
                        "coverage": prior["coverage"],
                        "work_ids": prior_payload.get("work_ids", []),
                        "local_fp": local_fp,
                    }
                    self.state.put_citation_cache(
                        library_id=library_id,
                        query_fp=query_fp,
                        work_id=QUERY_SNAPSHOT_WORK_ID,
                        payload_fp=payload_fingerprint(stale_payload),
                        payload=stale_payload,
                        sources={"origin": "last-good-carry-forward"},
                        status="stale",
                    )
                else:
                    quality[library_id] = {
                        "complete": False,
                        "capped": False,
                        "stale": True,
                        "as_of": query_result.as_of or _iso(now),
                        "errors": list(query_result.errors),
                    }
                continue

            release_floor = _library_release_date(library)
            works: dict[str, Mapping[str, Any]] = {}
            for work in query_result.works[:max_works]:
                if _eligible_work(work, not_before=release_floor):
                    works[_work_id(work)] = dict(work)

            by_doi = {
                doi: work_id
                for work_id, work in works.items()
                if (doi := _work_doi(work))
            }
            resolver = getattr(self.source, "resolve_reference", None)
            for reference in sorted(cff_repos_by_ref):
                if reference in by_doi:
                    metrics["resolve_cache_hits"] += 1
                    continue
                cached_match = next(
                    (
                        (work_id, self._decode(row))
                        for work_id, row in cached.items()
                        if work_id != QUERY_SNAPSHOT_WORK_ID
                        and _work_doi(self._decode(row) or {}) == reference
                    ),
                    None,
                )
                if (
                    cached_match is not None
                    and _eligible_work(cached_match[1], not_before=release_floor)
                ):
                    works[cached_match[0]] = cached_match[1]
                    by_doi[reference] = cached_match[0]
                    metrics["resolve_cache_hits"] += 1
                    continue
                if not callable(resolver):
                    continue
                if reference not in resolved_refs:
                    check_deadline()
                    metrics["resolve_calls"] += 1
                    try:
                        reserve_source_request()
                        resolved_refs[reference] = resolver(reference)
                    except Exception as exc:
                        resolved_refs[reference] = None
                        resolution_errors[reference] = redact_sensitive(
                            f"{type(exc).__name__}: {exc}"
                        )
                work = resolved_refs[reference]
                if work and _eligible_work(work, not_before=release_floor):
                    work_id = _work_id(work)
                    works[work_id] = dict(work)
                    by_doi[reference] = work_id

            extraction_errors: list[str] = []
            extraction_budget_exhausted = False
            work_sources: dict[str, dict[str, Any]] = {}
            extractor = getattr(self.source, "extract_repository_urls", None)
            extractable_ids = sorted(works)[:max_extract]
            for work_id, original in sorted(works.items()):
                check_deadline()
                work = dict(original)
                raw_url_hints = list(_repo_urls(work))
                # Repository URLs are derived/cache metadata, not part of the
                # OpenAlex payload fingerprint.  Never persist an unverified
                # repository name from a paper.
                work.pop("repository_urls", None)
                work.pop("repo_urls", None)
                work_fp = payload_fingerprint(work)
                old = cached.get(work_id)
                old_sources: dict[str, Any] = {}
                if old is not None:
                    try:
                        decoded_sources = json.loads(old["source_json"])
                        if isinstance(decoded_sources, dict):
                            old_sources = decoded_sources
                    except (TypeError, json.JSONDecodeError):
                        pass
                explicit_urls = self._public_repository_names(raw_url_hints)
                if explicit_urls:
                    source_info = {
                        "origin": "work-payload",
                        "repository_urls": explicit_urls,
                        "payload_fp": work_fp,
                        "extraction_complete": True,
                        "extraction_status": "complete",
                        "source_available": True,
                        "attempted_sources": [],
                        "successful_sources": ["work-payload"],
                        "errors": [],
                    }
                elif (
                    old
                    and old["payload_fp"] == work_fp
                    and old_sources.get("extraction_complete")
                ):
                    source_info = dict(old_sources)
                    source_info["repository_urls"] = self._public_repository_names(
                        source_info.get("repository_urls", ())
                    )
                    source_info.setdefault("extraction_status", "complete")
                    source_info.setdefault("source_available", True)
                    source_info.setdefault("attempted_sources", [])
                    source_info.setdefault("successful_sources", [])
                    source_info.setdefault("errors", [])
                    metrics["source_extract_cache_hits"] += 1
                elif work_id in extractable_ids and callable(extractor):
                    if (
                        max_source_extractions is not None
                        and metrics["source_extract_calls"]
                        >= max_source_extractions
                    ):
                        extraction_budget_exhausted = True
                        metrics["source_extract_budget_skips"] += 1
                        source_info = {
                            "origin": "source-extraction-budget",
                            "repository_urls": [],
                            "payload_fp": work_fp,
                            "extraction_complete": False,
                            "extraction_status": "budget_skipped",
                            "source_available": None,
                            "attempted_sources": [],
                            "successful_sources": [],
                            "errors": [
                                "source extraction budget exhausted"
                            ],
                            "error": "source extraction budget exhausted",
                        }
                    else:
                        metrics["source_extract_calls"] += 1
                        try:
                            check_deadline()
                            extraction = (
                                _normalized_repository_url_extraction(
                                    extractor(work)
                                )
                            )
                            check_deadline()
                            source_info = {
                                "origin": "source-extraction",
                                "repository_urls": self._public_repository_names(
                                    extraction["urls"]
                                ),
                                "payload_fp": work_fp,
                                "extraction_complete": (
                                    extraction["status"] != "failed"
                                ),
                                "extraction_status": extraction["status"],
                                "source_available": extraction[
                                    "source_available"
                                ],
                                "attempted_sources": list(
                                    extraction["attempted_sources"]
                                ),
                                "successful_sources": list(
                                    extraction["successful_sources"]
                                ),
                                "errors": list(extraction["errors"]),
                            }
                            if extraction["status"] == "failed":
                                message = "; ".join(extraction["errors"])
                                extraction_errors.append(
                                    "repository URL extraction %s: %s"
                                    % (work_id, message)
                                )
                                source_info["error"] = message
                        except Exception as exc:
                            message = redact_sensitive(
                                f"{type(exc).__name__}: {exc}"
                            )
                            extraction_errors.append(
                                f"repository URL extraction {work_id}: {message}"
                            )
                            source_info = {
                                "origin": "source-extraction",
                                "repository_urls": [],
                                "payload_fp": work_fp,
                                "extraction_complete": False,
                                "extraction_status": "failed",
                                "source_available": None,
                                "attempted_sources": [],
                                "successful_sources": [],
                                "errors": [message],
                                "error": message,
                            }
                else:
                    source_info = {
                        "origin": "not-extracted",
                        "repository_urls": [],
                        "payload_fp": work_fp,
                        "extraction_complete": not callable(extractor),
                        "extraction_status": (
                            "not_available"
                            if not callable(extractor)
                            else "capped"
                        ),
                        "source_available": (
                            False if not callable(extractor) else None
                        ),
                        "attempted_sources": [],
                        "successful_sources": [],
                        "errors": [],
                    }
                work_sources[work_id] = source_info
                works[work_id] = work

            rows: list[dict[str, Any]] = []
            rows_by_key: dict[str, int] = {}
            repo_papers: dict[str, dict[str, Any]] = {}
            for work_id in sorted(works):
                work = works[work_id]
                row = _paper_row(work)
                doi = row["doi"]
                repos = set(cff_repos_by_ref.get(doi, ()))
                repository_urls = set(_repo_urls(work))
                repository_urls.update(
                    work_sources.get(work_id, {}).get("repository_urls", ())
                )
                for candidate in repository_urls:
                    if candidate.lower() in confirmed_names:
                        repos.add(confirmed_names[candidate.lower()])
                ordered_repos = sorted(repos, key=str.casefold)
                repo = ordered_repos[0] if ordered_repos else None
                row["repos"] = ordered_repos
                if repo is not None:
                    row["repo"] = repo
                    row["repo_url"] = "https://github.com/" + repo
                    row["code_available"] = True
                key = doi or _title_key(row["title"])
                if key and key in rows_by_key:
                    index = rows_by_key[key]
                    current = rows[index]
                    if row["cited_by"] > current["cited_by"]:
                        merged_repos = sorted(
                            set(row.get("repos", ()))
                            | set(current.get("repos", ())),
                            key=str.casefold,
                        )
                        row["repos"] = merged_repos
                        if merged_repos:
                            row["repo"] = merged_repos[0]
                            row["repo_url"] = (
                                "https://github.com/" + merged_repos[0]
                            )
                            row["code_available"] = True
                        rows[index] = row
                    else:
                        merged_repos = sorted(
                            set(current.get("repos", ()))
                            | set(row.get("repos", ())),
                            key=str.casefold,
                        )
                        current["repos"] = merged_repos
                        if merged_repos:
                            current.update(
                                {
                                    "repo": merged_repos[0],
                                    "repo_url": (
                                        "https://github.com/"
                                        + merged_repos[0]
                                    ),
                                    "code_available": True,
                                }
                            )
                    continue
                rows_by_key[key] = len(rows)
                rows.append(row)

            for row in rows:
                for repository in row.get("repos", ()):
                    repo_papers.setdefault(
                        repository,
                        {
                            "title": row["title"],
                            "doi": row["doi"],
                            "oa_url": row["oa_url"],
                        },
                    )
            rows.sort(key=lambda row: (-(row["cited_by"] or 0), -(row["year"] or 0)))
            previous_record = (snapshot or {}).get("library_record") or {}
            previous_total = previous_record.get("total")
            displayed_total = len(rows)
            total = (
                int(query_result.total)
                if query_result.capped and query_result.total is not None
                else displayed_total
            )
            errors = list(query_result.errors)
            errors.extend(extraction_errors)
            if extraction_budget_exhausted:
                errors.append("source extraction budget exhausted")
            errors.extend(
                f"CFF reference {reference}: {resolution_errors[reference]}"
                for reference in sorted(cff_repos_by_ref)
                if reference in resolution_errors
            )
            local_resolution_failed = any(
                reference in resolution_errors for reference in cff_repos_by_ref
            )
            source_extraction_capped = bool(
                callable(extractor)
                and (len(works) > max_extract or extraction_budget_exhausted)
            )
            query_complete = bool(query_result.complete and not query_result.capped)
            local_enrichment_complete = bool(
                not local_resolution_failed and not extraction_errors
            )
            source_available_count = sum(
                item.get("source_available") is True
                for item in work_sources.values()
            )
            source_unavailable_count = sum(
                item.get("source_available") is False
                for item in work_sources.values()
            )
            effective_complete = bool(
                query_complete
                and local_enrichment_complete
                and not source_extraction_capped
            )
            coverage = {
                "source": getattr(self.source, "name", type(self.source).__name__),
                "query_fp": query_fp,
                "as_of": query_result.as_of or _iso(now),
                "complete": effective_complete,
                "capped": bool(query_result.capped),
                "stale": not effective_complete,
                "returned": len(query_result.works),
                "eligible": displayed_total,
                "source_total": query_result.total,
                "headline_total_basis": (
                    "source_total" if query_result.capped else "displayed_papers"
                ),
                "local_cff_complete": not local_resolution_failed,
                "local_enrichment_complete": local_enrichment_complete,
                "source_extraction_capped": source_extraction_capped,
                "source_extraction_budget_exhausted": extraction_budget_exhausted,
                "source_extracted": min(len(works), max_extract)
                if callable(extractor)
                else 0,
                "source_available": source_available_count > 0,
                "source_available_count": source_available_count,
                "source_unavailable_count": source_unavailable_count,
                "errors": errors,
            }
            record = {
                "name": library.get("name", library_id),
                "query": library.get("citation_query"),
                "tier": library.get("citation_tier", "A"),
                "confidence": library.get("citation_confidence", "high"),
                "total": total,
                "displayed_papers_count": displayed_total,
                "new_since_last": (
                    None
                    if previous_total is None
                    else max(0, total - int(previous_total))
                ),
                "new_7d": query_result.new_7d,
                "growth_90d": query_result.growth_90d,
                "growth_365d": query_result.growth_365d,
                "monthly": _monthly(rows, now.date()),
                "papers": rows,
                "repo_papers": repo_papers,
                "papers_capped": bool(query_result.capped),
                "monthly_capped": bool(query_result.capped),
                "as_of": coverage["as_of"],
                "stale": not effective_complete,
                "coverage": coverage,
                "errors": errors,
            }

            with self.state.transaction(immediate=True):
                work_ids = []
                for work_id, work in sorted(works.items()):
                    work_ids.append(work_id)
                    work_fp = payload_fingerprint(work)
                    old = cached.get(work_id)
                    prior_sources = {}
                    if old is not None:
                        try:
                            decoded_sources = json.loads(
                                old["source_json"]
                            )
                            if isinstance(decoded_sources, dict):
                                prior_sources = decoded_sources
                        except (TypeError, json.JSONDecodeError):
                            pass
                    if (
                        old
                        and old["payload_fp"] == work_fp
                        and prior_sources == work_sources.get(work_id, {})
                    ):
                        metrics["work_cache_hits"] += 1
                        continue
                    self.state.put_citation_cache(
                        library_id=library_id,
                        query_fp=query_fp,
                        work_id=work_id,
                        payload_fp=work_fp,
                        payload=work,
                        sources=work_sources.get(
                            work_id, {"origin": "query-or-local-cff"}
                        ),
                        status="fresh",
                    )
                    metrics["work_cache_writes"] += 1
                snapshot_payload = {
                    "library_record": record,
                    "coverage": coverage,
                    "work_ids": work_ids,
                    "local_fp": local_fp,
                }
                self.state.put_citation_cache(
                    library_id=library_id,
                    query_fp=query_fp,
                    work_id=QUERY_SNAPSHOT_WORK_ID,
                    payload_fp=payload_fingerprint(snapshot_payload),
                    payload=snapshot_payload,
                    sources={"origin": "query-snapshot"},
                    # Cache freshness describes the OpenAlex query snapshot.
                    # Local enrichment gaps are retried from cached works.
                    status="fresh" if query_complete else "stale",
                )
                if query_complete:
                    obsolete = set(cached).difference(work_ids).difference(
                        {QUERY_SNAPSHOT_WORK_ID}
                    )
                    if obsolete:
                        placeholders = ",".join("?" for _ in obsolete)
                        self.state.connection.execute(
                            f"""
                            DELETE FROM citation_cache
                            WHERE library_id=? AND query_fp=?
                              AND work_id IN ({placeholders})
                            """,
                            (library_id, query_fp, *sorted(obsolete)),
                        )
            output[library_id] = record
            quality[library_id] = coverage

        wanted_count = sum(bool(library.get("citation_query")) for library in libraries)
        all_failed = wanted_count > 0 and failures == wanted_count
        exact_count = getattr(self.source, "request_count", None)
        metrics["openalex_requests"] = (
            int(exact_count)
            if isinstance(exact_count, int)
            else logical_source_requests
        )
        document = {
            "generated_at": _iso(now),
            "source": getattr(self.source, "name", type(self.source).__name__),
            "method_version": METHOD_VERSION,
            "as_of": max(
                (record.get("as_of") or "" for record in output.values()),
                default=_iso(now),
            ),
            "stale": (
                any(record.get("stale") for record in output.values())
                or any(item.get("stale") for item in quality.values())
            ),
            "coverage": quality,
            "libraries": output,
            "errors": {
                library_id: coverage.get("errors", [])
                for library_id, coverage in quality.items()
                if coverage.get("errors")
            },
            "budget": {
                "openalex_requests": {
                    "used": metrics["openalex_requests"],
                    "limit": max_openalex_requests,
                },
                "source_extractions": {
                    "used": metrics["source_extract_calls"],
                    "limit": max_source_extractions,
                    "skipped": metrics["source_extract_budget_skips"],
                },
            },
        }
        return CitationRefreshResult(
            document=document,
            publishable=bool(output),
            all_failed=all_failed,
            used_last_good=bool(carried),
            metrics=metrics,
        )
