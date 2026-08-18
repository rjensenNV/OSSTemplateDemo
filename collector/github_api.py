"""Minimal, dependency-free GitHub API client (stdlib only).

Handles auth (GITHUB_TOKEN env, falling back to `gh auth token` locally),
JSON GET, primary + secondary rate limits, and code-search throttling
(code search is capped at 10 requests/minute).
"""
import json
import os
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
UA = "cuda-x-developer-intelligence"

# Code search allows ~10 req/min. Space calls out conservatively.
_CODE_SEARCH_MIN_INTERVAL = 7.0
_last_code_search = [0.0]

# Hard wall-clock cap per HTTP call, enforced via SIGALRM. This BACKSTOPS urlopen's own
# timeout= (below): a stalled SSL read once hung the weekly refresh for >1h at 0% CPU
# without the socket timeout ever firing (2026-07-01), and a launchd run that never
# completes (no data, no push, no alert) is worse than one that errors. SIGALRM reliably
# interrupts the blocked syscall. Set > urlopen's 60s so the socket timeout normally fires
# first; the alarm only triggers when that fails. Main-thread only (signals can't be armed
# off the main thread) — a future parallel scan worker falls back to the urlopen timeout.
_HARD_TIMEOUT = 90


class _HardTimeout(TimeoutError):
    """Raised by the SIGALRM watchdog. Subclasses TimeoutError so the existing
    retry/backoff `except (URLError, TimeoutError, OSError)` catches and retries it."""


def _hard_timeout_handler(signum, frame):
    raise _HardTimeout("network call exceeded %ds hard cap" % _HARD_TIMEOUT)


def _token():
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        return tok.strip()
    try:  # local convenience
        return subprocess.check_output(["gh", "auth", "token"], text=True).strip()
    except Exception:
        return ""


_TOKEN = _token()


def _headers():
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28"}
    if _TOKEN:
        h["Authorization"] = "Bearer " + _TOKEN
    return h


def _get(path, params=None, retries=4):
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=_headers())
        try:
            # Arm a SIGALRM hard-timeout around the blocking network I/O so a stalled read
            # can't hang the run indefinitely (urlopen's timeout= has proven unreliable for
            # certain SSL read stalls). Disarmed in the inner finally BEFORE any backoff sleep
            # in the except handlers, so the alarm never fires during a retry wait.
            use_alarm = threading.current_thread() is threading.main_thread()
            if use_alarm:
                _old_handler = signal.signal(signal.SIGALRM, _hard_timeout_handler)
                signal.alarm(_HARD_TIMEOUT)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = resp.read().decode("utf-8")
                    hdrs = resp.headers
                return json.loads(body), hdrs
            finally:
                if use_alarm:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, _old_handler)
        except urllib.error.HTTPError as e:
            # 403/429: rate limited or abuse detection -> back off and retry.
            if e.code in (403, 429):
                reset = e.headers.get("X-RateLimit-Reset")
                retry_after = e.headers.get("Retry-After")
                wait = 60.0
                if retry_after:
                    wait = float(retry_after)
                elif reset:
                    wait = max(1.0, float(reset) - time.time()) + 1
                wait = min(wait, 120.0)
                if attempt < retries - 1:
                    time.sleep(wait)
                    continue
            if e.code == 422:  # e.g. >1000 results page -> caller handles
                return {"_http_error": 422, "message": e.read().decode("utf-8", "ignore")}, e.headers
            if e.code in (404, 451):
                return {"_http_error": e.code}, e.headers
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            return {"_http_error": e.code, "message": str(e)}, e.headers
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # OSError covers ConnectionResetError / socket / SSL read errors raised DURING
            # resp.read() (not just urlopen) — a transient "connection reset by peer" over a
            # long discovery of hundreds of code-search calls previously crashed the whole
            # run (2026-07-01). Retry with backoff; only give up after `retries`.
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            return {"_http_error": "network", "message": str(e)}, {}
    return {"_http_error": "exhausted"}, {}


def repo(full_name):
    """Repo metadata. Returns the metadata dict on success, or an error dict
    {"_http_error": <code|"network"|...>} on failure — so callers can distinguish a
    CONFIRMED 404/451 (repo deleted/private → safe to drop) from a transient 403 /
    rate-limit / network blip (must NOT drop). (Was: returned None on any failure,
    collapsing those cases — unsafe for the incremental refresh, which evicts on drop.)"""
    data, _ = _get("/repos/" + full_name)
    return data if isinstance(data, dict) else {"_http_error": "unknown"}


def default_head_sha(full_name):
    """Latest commit SHA on the repo's DEFAULT branch (the branch scan_repo scans). Returns the
    SHA, or None if unavailable (empty repo / transient error) — callers treat None as "cannot
    confirm unchanged" and re-scan. One cheap REST call; /commits defaults to the default branch,
    so no separate default_branch lookup is needed."""
    data, _ = _get("/repos/" + full_name + "/commits", {"per_page": 1})
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0].get("sha")
    return None


def code_search(query, per_page=100, page=1):
    """One code-search request, throttled to respect the 10/min cap.

    Returns (total_count, items, coverage_gap). The final flag is true if this
    page hit the 1000-result ceiling, GitHub marked the response incomplete, or
    no valid search result was returned after the HTTP client's retries.
    """
    delta = time.time() - _last_code_search[0]
    if delta < _CODE_SEARCH_MIN_INTERVAL:
        time.sleep(_CODE_SEARCH_MIN_INTERVAL - delta)
    _last_code_search[0] = time.time()
    data, _ = _get("/search/code", {"q": query, "per_page": per_page, "page": page})
    if isinstance(data, dict) and data.get("_http_error") == 422:
        return None, [], True
    if (not isinstance(data, dict)
            or not isinstance(data.get("total_count"), int)
            or isinstance(data.get("total_count"), bool)
            or not isinstance(data.get("items"), list)):
        return None, [], True
    # GitHub can return HTTP 200 with incomplete_results=true. Treat that as a
    # coverage gap instead of silently accepting an undercount.
    return (data["total_count"], data["items"],
            bool(data.get("incomplete_results")))
