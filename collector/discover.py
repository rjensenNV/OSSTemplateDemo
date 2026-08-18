"""Discovery: find candidate repos per library via partitioned code search.

GitHub code search hard-caps at 1000 results/query and matches cluster, so a
single token query silently misses repos. We partition by file extension and,
if a partition still hits the 1000 ceiling, by size ranges -- then union the
distinct repos. Any partition that still hits the ceiling is reported as a
coverage gap (no silent truncation).
"""
from . import github_api as gh
from .config import (EXCLUDED_REPOS, PY_DEP_FILENAMES, PY_SIGNALS, PY_SOURCE_EXTS,
                     SOURCE_EXTS, TARGETED_EXTS, TARGETED_FILENAMES)

# Size buckets (bytes) used to sub-partition an extension that overflows 1000.
_SIZE_BUCKETS = ["0..2000", "2001..6000", "6001..20000", "20001..80000", ">80000"]


class DiscoveryCoverageGap(RuntimeError):
    """A query cannot be proven complete; the caller must stop the run."""


def _owner_excluded(full_name, excluded_orgs, prefixes, name_substrs):
    owner = full_name.split("/", 1)[0].lower()
    name = full_name.split("/", 1)[1].lower() if "/" in full_name else ""
    if full_name.lower() in EXCLUDED_REPOS:   # hand-verified false-positives (exact repo)
        return True
    if owner in excluded_orgs:
        return True
    if any(owner.startswith(p) for p in prefixes):
        return True
    if any(s in name for s in name_substrs):  # `name` is already lowercased above
        return True
    return False


def _add_public_results(items, repos, visibility_excluded):
    """Add only explicitly-public repositories from a code-search response.

    The authenticated GitHub user may be able to search private repositories.
    This project publishes an external-adoption dashboard, so visibility is
    fail-closed: a missing/malformed `private` flag is excluded along with
    `private=true`. Repository names are retained only in-memory for a distinct
    exclusion count and are never logged.
    """
    for item in items:
        repo = item.get("repository") if isinstance(item, dict) else None
        repo = repo if isinstance(repo, dict) else {}
        full_name = repo.get("full_name")
        if isinstance(full_name, str) and full_name and repo.get("private") is False:
            repos.add(full_name)
        elif isinstance(full_name, str) and full_name:
            visibility_excluded.add(full_name.lower())


def _collect(query, repos, cap_hits, visibility_excluded, terminal_partition=False):
    """Page through one query (<=1000), add distinct repo full_names to `repos`.
    Returns total_count for the query; appends to cap_hits if any page has a
    ceiling, incomplete response, or exhausted request failure.

    A non-terminal query above 1000 returns after page 1 so its caller can
    size-partition without wasting nine capped pages. A terminal size bucket
    above 1000 is itself an unrecoverable coverage gap.
    """
    total, items, coverage_gap = gh.code_search(query, per_page=100, page=1)
    _add_public_results(items, repos, visibility_excluded)
    if coverage_gap:
        cap_hits.append(query)
        raise DiscoveryCoverageGap(query)
    if total is None:
        cap_hits.append(query)
        raise DiscoveryCoverageGap(query)
    if total > 1000:
        if terminal_partition:
            detail = "%s (>1000 matches)" % query
            cap_hits.append(detail)
            raise DiscoveryCoverageGap(detail)
        return total
    pages = (min(total, 1000) + 99) // 100
    for page in range(2, pages + 1):
        _t, items, coverage_gap = gh.code_search(query, per_page=100, page=page)
        _add_public_results(items, repos, visibility_excluded)
        if coverage_gap:
            detail = "%s (page %d)" % (query, page)
            cap_hits.append(detail)
            raise DiscoveryCoverageGap(detail)
    return total


def discover_library(lib, excluded_orgs, prefixes, name_substrs, log):
    """Return (kept_repos:set, stats:dict) for one library.

    Dispatches on library type: the NVPL CPU family uses its own multi-signal
    discovery; pip-distributed Python libraries use the import/dependency
    discovery below; everything else uses the C++ include-token discovery."""
    if lib.get("family") == "nvpl":
        return _discover_nvpl(lib, excluded_orgs, prefixes, name_substrs, log)
    if lib.get("language") == "python":
        return _discover_python(lib, excluded_orgs, prefixes, name_substrs, log)
    token = lib["token"]
    repos = set()
    cap_hits = []
    visibility_excluded = set()
    per_ext_total = {}
    for ext in SOURCE_EXTS:
        q = "%s extension:%s" % (token, ext)
        total = _collect(q, repos, cap_hits, visibility_excluded)  # page 1 + pagination
        per_ext_total[ext] = total
        if total > 1000:
            # extension partition overflowed the 1000 ceiling -> sub-partition by size
            log("    %s/%s: %d hits > 1000, sub-partitioning by size" % (token, ext, total))
            for bucket in _SIZE_BUCKETS:
                _collect("%s size:%s" % (q, bucket), repos, cap_hits,
                         visibility_excluded, terminal_partition=True)
    # Python device-extension path (nvmath.device.* in .py files) -> integration.
    for sig in PY_SIGNALS.get(lib["id"], []):
        total = _collect("%s extension:py" % sig, repos, cap_hits, visibility_excluded)
        per_ext_total["py:" + sig] = total
        if total > 1000:
            for bucket in _SIZE_BUCKETS:
                _collect("%s extension:py size:%s" % (sig, bucket), repos, cap_hits,
                         visibility_excluded, terminal_partition=True)
    # "Targeted" path: token in the repo's own code/build files (generators,
    # build wiring, non-C++ kernels). Doc-only file types are not searched.
    for ext in TARGETED_EXTS:
        total = _collect("%s extension:%s" % (token, ext), repos, cap_hits,
                         visibility_excluded)
        per_ext_total["t:" + ext] = total
        if total > 1000:
            for bucket in _SIZE_BUCKETS:
                _collect("%s extension:%s size:%s" % (token, ext, bucket), repos, cap_hits,
                         visibility_excluded, terminal_partition=True)
    for fn in TARGETED_FILENAMES:
        _collect("%s filename:%s" % (token, fn), repos, cap_hits,
                 visibility_excluded, terminal_partition=True)
    raw_count = len(repos)
    kept = {r for r in repos if not _owner_excluded(r, excluded_orgs, prefixes, name_substrs)}
    stats = {
        "raw_candidate_repos": raw_count,
        "after_org_exclusion": len(kept),
        "private_candidate_repos_excluded": len(visibility_excluded),
        "per_extension_total_matches": per_ext_total,
        "coverage_gaps": cap_hits,
    }
    if cap_hits:
        log("    WARNING %s: %d incomplete/capped query response(s) (coverage gap)"
            % (token, len(cap_hits)))
    if visibility_excluded:
        log("    %s: excluded %d non-public or unverified repository candidate(s)"
            % (token, len(visibility_excluded)))
    return kept, stats


def _discover_python(lib, excluded_orgs, prefixes, name_substrs, log):
    """Discover candidate repos for a pip-distributed library (DALI, etc.).

    Two surfaces, unioned: (1) source IMPORT of the library namespace in .py and
    .ipynb files (strict anchor, e.g. "nvidia.dali" — avoids bare-'dali' FPs);
    (2) the pip package name in dependency manifests + Dockerfiles. Same 1000-cap
    size sub-partitioning and coverage-gap reporting as the C++ path.
    """
    ns = lib["import_namespace"]   # strict anchor, e.g. nvidia.dali
    pips = lib["pip_pattern"]      # str (nvidia-dali) or list (cuQuantum wheels)
    pips = pips if isinstance(pips, list) else [pips]
    repos = set()
    cap_hits = []
    visibility_excluded = set()
    per_q_total = {}
    # 1) Source imports of the namespace (.py + .ipynb).
    for ext in PY_SOURCE_EXTS:
        q = '"%s" extension:%s' % (ns, ext)
        total = _collect(q, repos, cap_hits, visibility_excluded)
        per_q_total["import:" + ext] = total
        if total > 1000:
            log("    %s/import.%s: %d hits > 1000, sub-partitioning by size" % (pips[0], ext, total))
            for bucket in _SIZE_BUCKETS:
                _collect("%s size:%s" % (q, bucket), repos, cap_hits,
                         visibility_excluded, terminal_partition=True)
    # 2) Dependency declarations + Dockerfile installs of the pip package(s).
    for pip in pips:
        for fname in PY_DEP_FILENAMES:
            q = '"%s" filename:%s' % (pip, fname)
            total = _collect(q, repos, cap_hits, visibility_excluded)
            per_q_total["dep:%s:%s" % (pip, fname)] = total
            if total > 1000:
                for bucket in _SIZE_BUCKETS:
                    _collect("%s size:%s" % (q, bucket), repos, cap_hits,
                             visibility_excluded, terminal_partition=True)
    # 3) C++ component headers (dual-surface libs like cuQuantum). Own-source
    # #include of any component header is a confirmed integration at scan time;
    # here we just surface the candidate repos. Guarded on `cpp_headers` so the
    # pure-Python libs (DALI) are unaffected.
    for header in lib.get("cpp_headers", []):
        for ext in SOURCE_EXTS:
            q = '"%s" extension:%s' % (header, ext)
            total = _collect(q, repos, cap_hits, visibility_excluded)
            per_q_total["hdr:%s:%s" % (header, ext)] = total
            if total > 1000:
                for bucket in _SIZE_BUCKETS:
                    _collect("%s size:%s" % (q, bucket), repos, cap_hits,
                             visibility_excluded, terminal_partition=True)
    raw_count = len(repos)
    kept = {r for r in repos if not _owner_excluded(r, excluded_orgs, prefixes, name_substrs)}
    stats = {
        "raw_candidate_repos": raw_count,
        "after_org_exclusion": len(kept),
        "private_candidate_repos_excluded": len(visibility_excluded),
        "per_extension_total_matches": per_q_total,
        "coverage_gaps": cap_hits,
    }
    if cap_hits:
        log("    WARNING %s: %d incomplete/capped query response(s) (coverage gap)"
            % (pips[0], len(cap_hits)))
    if visibility_excluded:
        log("    %s: excluded %d non-public or unverified repository candidate(s)"
            % (pips[0], len(visibility_excluded)))
    return kept, stats


def _discover_nvpl(lib, excluded_orgs, prefixes, name_substrs, log):
    """Discover candidate repos for the NVPL CPU family (Arm/Grace). Multi-signal,
    wide net: distinctive component header/API tokens (nvpl_blas, nvpl_fftw,
    nvpl_lapack, nvpl_scalapack, nvpl_blacs, nvpl_sparse, nvpl_rand, nvpl_tensor,
    nvpltensor) plus build-integration tokens (find_package(nvpl, nvpl::). Recall
    here is deliberately broad (includes vendored llama.cpp/ggml copies); scan.py
    applies the precision guards — own-source #include = confirmed, build tokens =
    Build-integrated, a conditional include in an optional-backend file = not use.
    Quoted phrases only (bare tokens tokenize into noise)."""
    repos = set()
    cap_hits = []
    visibility_excluded = set()
    per_q_total = {}
    header_tokens = sorted(set(lib.get("components", {}).keys()))   # nvpl_blas, nvpltensor, ...
    build_tokens = ["find_package(nvpl", "nvpl::"]
    for tok in header_tokens + build_tokens:
        q = '"%s"' % tok
        total = _collect(q, repos, cap_hits, visibility_excluded)
        per_q_total[tok] = total
        if total > 1000:
            log("    nvpl/%s: %d hits > 1000, sub-partitioning by size" % (tok, total))
            for bucket in _SIZE_BUCKETS:
                _collect("%s size:%s" % (q, bucket), repos, cap_hits,
                         visibility_excluded, terminal_partition=True)
    raw_count = len(repos)
    kept = {r for r in repos if not _owner_excluded(r, excluded_orgs, prefixes, name_substrs)}
    stats = {
        "raw_candidate_repos": raw_count,
        "after_org_exclusion": len(kept),
        "private_candidate_repos_excluded": len(visibility_excluded),
        "per_extension_total_matches": per_q_total,
        "coverage_gaps": cap_hits,
    }
    if cap_hits:
        log("    WARNING nvpl: %d incomplete/capped query response(s) (coverage gap)"
            % len(cap_hits))
    if visibility_excluded:
        log("    nvpl: excluded %d non-public or unverified repository candidate(s)"
            % len(visibility_excluded))
    return kept, stats
