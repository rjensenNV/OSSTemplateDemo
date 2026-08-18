"""Minimal, dependency-free OpenAlex API client (stdlib only).

Mirrors github_api.py. Handles the API key (OPENALEX_API_KEY env, falling back
to ~/.config/openalex-api-key), an optional OPENALEX_MAILTO polite-pool contact, retry/backoff on
429/5xx, and explicit request pacing.

OpenAlex permits casual keyless access, but this project's production-scale
collection path requires a free API key. The collector reads server-provided
rate-limit state and also applies a smaller explicit per-run request budget so
an implementation mistake cannot create unbounded usage.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from .http_transport import (
    _call_with_absolute_deadline,
    _close_without_blocking,
)
from .redaction import redact_sensitive

API = "https://api.openalex.org"
MAILTO = os.environ.get("OPENALEX_MAILTO", "").strip()
if any(ord(character) < 32 for character in MAILTO):
    raise ValueError("OPENALEX_MAILTO cannot contain control characters")
UA = "cuda-x-developer-intelligence"
if MAILTO:
    UA += " (mailto:%s)" % MAILTO
# OpenAlex institution ids for NVIDIA (US + UK). Used to flag NVIDIA-authored
# papers (devrel) vs community/research, mirroring the GitHub org exclusion.
NVIDIA_INSTITUTION_IDS = ("I4210127875", "I1304085615")

_MIN_INTERVAL = 0.12          # be polite; well under any per-second cap
_last_call = [0.0]
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 60.0


class RequestBudgetExceeded(RuntimeError):
    """Raised before an HTTP attempt would exceed the caller's hard limit."""


class RequestBudget:
    def __init__(
        self,
        limit,
        *,
        deadline_monotonic=None,
        monotonic=time.monotonic,
    ):
        if limit is not None and int(limit) < 0:
            raise ValueError("OpenAlex request budget cannot be negative")
        self.limit = None if limit is None else int(limit)
        self.used = 0
        self.deadline_monotonic = deadline_monotonic
        self.monotonic = monotonic

    def remaining_seconds(self, maximum=None):
        if self.deadline_monotonic is None:
            return maximum
        remaining = self.deadline_monotonic - self.monotonic()
        if remaining <= 0:
            raise RequestBudgetExceeded("OpenAlex wall deadline exhausted")
        return remaining if maximum is None else min(float(maximum), remaining)

    def consume(self):
        self.remaining_seconds()
        if self.limit is not None and self.used >= self.limit:
            raise RequestBudgetExceeded(
                "OpenAlex request budget exhausted (%d/%d)"
                % (self.used, self.limit)
            )
        self.used += 1


def _key():
    k = os.environ.get("OPENALEX_API_KEY")
    if k:
        return k.strip()
    path = os.path.expanduser("~/.config/openalex-api-key")
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


_KEY = _key()


def have_key():
    return bool(_KEY)


def _attempt_remaining(
    budget, attempt_deadline, *, outer_deadline_is_bound=False
):
    remaining = attempt_deadline - time.monotonic()
    if remaining <= 0:
        if outer_deadline_is_bound:
            raise RequestBudgetExceeded(
                "OpenAlex wall deadline exhausted"
            )
        raise TimeoutError("OpenAlex response timed out")
    if budget is not None:
        budget_remaining = budget.remaining_seconds()
        if budget_remaining is not None:
            remaining = min(remaining, budget_remaining)
    return remaining


def _read_response(
    resp,
    budget,
    attempt_deadline,
    max_bytes,
    *,
    outer_deadline_is_bound,
):
    def remaining():
        return _attempt_remaining(
            budget,
            attempt_deadline,
            outer_deadline_is_bound=outer_deadline_is_bound,
        )

    def timeout_error():
        if outer_deadline_is_bound:
            return RequestBudgetExceeded(
                "OpenAlex wall deadline exhausted"
            )
        return TimeoutError("OpenAlex response timed out")

    def read_all():
        chunks = []
        total = 0
        while True:
            chunk = resp.read(min(64 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise RequestBudgetExceeded(
                    "OpenAlex returned a non-byte response"
                )
            total += len(chunk)
            if total > max_bytes:
                raise RequestBudgetExceeded(
                    "OpenAlex response byte budget exhausted"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    return _call_with_absolute_deadline(
        read_all,
        remaining=remaining,
        timeout_error=timeout_error,
    )


def _get(path, params, retries=4, *, budget=None):
    p = dict(params)
    if MAILTO:
        p["mailto"] = MAILTO
    if _KEY:
        p["api_key"] = _KEY
    # safe=':"' keeps filter syntax (fulltext.search:"x") readable/intact.
    url = API + path + "?" + urllib.parse.urlencode(p, safe=':"|')
    for attempt in range(retries):
        if budget is not None:
            budget.consume()
        delta = time.time() - _last_call[0]
        if delta < _MIN_INTERVAL:
            wait = _MIN_INTERVAL - delta
            if budget is not None:
                wait = budget.remaining_seconds(wait)
            time.sleep(wait)
        _last_call[0] = time.time()
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        response = None
        try:
            outer_remaining = (
                budget.remaining_seconds()
                if (
                    budget is not None
                    and budget.deadline_monotonic is not None
                )
                else None
            )
            timeout = (
                REQUEST_TIMEOUT_SECONDS
                if outer_remaining is None
                else min(REQUEST_TIMEOUT_SECONDS, outer_remaining)
            )
            outer_deadline_is_bound = (
                outer_remaining is not None
                and outer_remaining <= REQUEST_TIMEOUT_SECONDS
            )
            attempt_deadline = time.monotonic() + timeout

            def remaining():
                return _attempt_remaining(
                    budget,
                    attempt_deadline,
                    outer_deadline_is_bound=outer_deadline_is_bound,
                )

            def timeout_error():
                if outer_deadline_is_bound:
                    return RequestBudgetExceeded(
                        "OpenAlex wall deadline exhausted"
                    )
                return TimeoutError("OpenAlex response timed out")

            response = _call_with_absolute_deadline(
                lambda: urllib.request.urlopen(req, timeout=timeout),
                remaining=remaining,
                timeout_error=timeout_error,
                late_result=_close_without_blocking,
            )
            body = _read_response(
                response,
                budget,
                attempt_deadline,
                MAX_RESPONSE_BYTES,
                outer_deadline_is_bound=outer_deadline_is_bound,
            )
            return _call_with_absolute_deadline(
                lambda: json.loads(body.decode("utf-8")),
                remaining=remaining,
                timeout_error=timeout_error,
            )
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 503):
                retry_after = e.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else min(2 ** attempt, 30)
                if attempt < retries - 1:
                    if budget is not None:
                        wait = budget.remaining_seconds(wait)
                    time.sleep(wait)
                    continue
            body = ""
            try:
                error_outer_remaining = (
                    budget.remaining_seconds()
                    if (
                        budget is not None
                        and budget.deadline_monotonic is not None
                    )
                    else None
                )
                error_timeout = (
                    REQUEST_TIMEOUT_SECONDS
                    if error_outer_remaining is None
                    else min(
                        REQUEST_TIMEOUT_SECONDS,
                        error_outer_remaining,
                    )
                )
                error_deadline_is_bound = (
                    error_outer_remaining is not None
                    and error_outer_remaining
                    <= REQUEST_TIMEOUT_SECONDS
                )
                error_deadline = time.monotonic() + error_timeout
                body = _call_with_absolute_deadline(
                    lambda: e.read(200),
                    remaining=lambda: _attempt_remaining(
                        budget,
                        error_deadline,
                        outer_deadline_is_bound=(
                            error_deadline_is_bound
                        ),
                    ),
                    timeout_error=lambda: (
                        RequestBudgetExceeded(
                            "OpenAlex wall deadline exhausted"
                        )
                        if error_deadline_is_bound
                        else TimeoutError(
                            "OpenAlex response timed out"
                        )
                    ),
                ).decode("utf-8", "ignore")[:200]
            except RequestBudgetExceeded:
                raise
            except Exception:
                pass
            finally:
                _close_without_blocking(e)
            return {
                "_http_error": e.code,
                "message": redact_sensitive(body, secrets=(_KEY,)),
            }
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries - 1:
                wait = 2 ** attempt
                if budget is not None:
                    wait = budget.remaining_seconds(wait)
                time.sleep(wait)
                continue
            return {
                "_http_error": "network",
                "message": redact_sensitive(e, secrets=(_KEY,)),
            }
        finally:
            if response is not None:
                _close_without_blocking(response)
    return {"_http_error": "exhausted"}


def _filter(terms):
    """Join a list of filter clauses with commas (OpenAlex AND semantics)."""
    return ",".join(terms)


def count(filter_terms, *, budget=None):
    """meta.count for a filter (list of clauses). Returns int or None on error."""
    d = _get(
        "/works",
        {"filter": _filter(filter_terms), "per-page": "1"},
        budget=budget,
    )
    if not isinstance(d, dict) or d.get("_http_error"):
        return None
    return d.get("meta", {}).get("count")


_PAPER_SELECT =("title,doi,publication_year,publication_date,cited_by_count,"
                 "authorships,primary_location,open_access,ids")


def works(filter_terms, max_results, log, *, budget=None):
    """Page through works for a filter. Returns (papers, true_total, capped).

    Cursor paging (handles >10k). `capped` True if we stopped at max_results
    before exhausting (no silent truncation — caller logs it).
    """
    out = []
    cursor = "*"
    true_total = None
    while True:
        d = _get(
            "/works",
            {
                "filter": _filter(filter_terms),
                "per-page": "200",
                "cursor": cursor,
                "select": _PAPER_SELECT,
            },
            budget=budget,
        )
        if not isinstance(d, dict) or d.get("_http_error"):
            log("    WARN openalex works error: %s" % (d.get("message") if isinstance(d, dict) else d))
            break
        if true_total is None:
            true_total = d.get("meta", {}).get("count")
        for w in d.get("results", []):
            out.append(w)
            if len(out) >= max_results:
                return out, true_total, (true_total or 0) > len(out)
        cursor = d.get("meta", {}).get("next_cursor")
        if not cursor or not d.get("results"):
            break
    return out, true_total, False


def work_by_doi(doi, *, budget=None):
    """Resolve a single work by DOI (singleton endpoint, $0). Returns dict or None."""
    doi = (doi or "").strip().rstrip(".,;)")
    if not doi:
        return None
    d = _get(
        "/works/https://doi.org/" + urllib.parse.quote(doi, safe="/"),
        {},
        budget=budget,
    )
    if not isinstance(d, dict) or d.get("_http_error"):
        # 404 = DOI legitimately not in OpenAlex; log anything else (don't degrade silently).
        if isinstance(d, dict) and d.get("_http_error") not in (404, None):
            print("    WARN openalex work_by_doi error %s for %s" % (d.get("_http_error"), doi), flush=True)
        return None
    return d


def is_nvidia_authored(work):
    for a in work.get("authorships", []):
        for inst in a.get("institutions", []):
            iid = (inst.get("id") or "")
            if any(nid in iid for nid in NVIDIA_INSTITUTION_IDS):
                return True
    return False
