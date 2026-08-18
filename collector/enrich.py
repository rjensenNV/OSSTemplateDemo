"""Repo metadata enrichment via the GitHub REST API."""
from . import github_api as gh


def enrich(full_name):
    """Return a metadata dict, or a minimal stub if the repo is inaccessible.
    On failure the stub carries `http_status` so callers can tell a CONFIRMED 404/451
    (deleted/private → safe to drop) from a transient 403 / rate-limit / network error
    (must be retained by the incremental refresh, not evicted). Never raises."""
    r = gh.repo(full_name)
    if not isinstance(r, dict) or r.get("_http_error"):
        status = r.get("_http_error") if isinstance(r, dict) else "unknown"
        return {
            "full_name": full_name,
            "html_url": "https://github.com/" + full_name,
            "accessible": False,
            "http_status": status,                 # 404/451 = gone; 403/429/network = transient
            "gone": status in (404, 451),          # only these mean "safe to drop"
        }
    # Fail closed on visibility. An authenticated token may read private repositories,
    # but the published dashboard is explicitly an external/public adoption index.
    # Do not make the extra default-HEAD request for a repository we cannot publish.
    if r.get("private") is not False:
        return {
            "full_name": r.get("full_name", full_name),
            "html_url": r.get("html_url", "https://github.com/" + full_name),
            "accessible": False,
            "gone": False,
            "visibility_excluded": True,
        }
    lic = (r.get("license") or {}).get("spdx_id")
    return {
        "full_name": r.get("full_name", full_name),
        "html_url": r.get("html_url", "https://github.com/" + full_name),
        "owner": (r.get("owner") or {}).get("login"),
        "owner_type": (r.get("owner") or {}).get("type"),  # User | Organization
        "description": r.get("description"),
        "stars": r.get("stargazers_count", 0),
        "forks": r.get("forks_count", 0),
        "language": r.get("language"),
        "topics": r.get("topics", []),
        "license": None if lic in (None, "NOASSERTION") else lic,
        "is_fork": bool(r.get("fork")),
        # Parent/source full_name for forks (used by the NVPL pre-clone vendor filter
        # to drop copies of pytorch/llama.cpp/ggml/lammps before the expensive clone).
        "parent": (r.get("parent") or {}).get("full_name"),
        "source": (r.get("source") or {}).get("full_name"),
        "size": r.get("size", 0),   # KB
        "archived": bool(r.get("archived")),
        "created_at": (r.get("created_at") or "")[:10],
        "pushed_at": (r.get("pushed_at") or "")[:10],
        # Default-branch HEAD SHA: the exact "has the scanned content changed?" signal the reuse
        # gate + scanned-ledger compare against. Kept in enrich metadata only (NOT persisted to
        # current.json) so the published payload stays lean. One extra cheap REST call.
        "head_sha": gh.default_head_sha(r.get("full_name", full_name)),
        "accessible": True,
    }
