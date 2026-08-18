"""Retired V1 command tombstone and V2 materialization helpers.

``python -m collector.run`` deliberately refuses to collect. The supported
REQ-14 command surface is :mod:`collector.cli`; the pure helpers retained here
are still used to materialize V2 from migrated V1-shaped scan results.
"""
import argparse
import datetime
import os
import sys

METHOD_VERSION = "1.0"
CAVEATS = [
    "Integration = a repo's OWN source uses the library — a C/C++/CUDA #include, a Python nvmath.device call, or (for pip-distributed libraries like DALI) an import of the library's namespace in the repo's own .py/.ipynb source. Vendored copies and dependency-only declarations are reported separately.",
    "For pip-distributed libraries, 'Declared' (shown in place of Bundled) means a dependency manifest or Dockerfile names the package but no import was found in the repo's own source. Detection anchors strictly on the library namespace (e.g. nvidia.dali), so it under-counts aliased imports — a precision-over-recall lower bound.",
    "Operators/functions are heuristic string matches — Python fn.*/ops.* and C++ Dx descriptors (Function<>, Size<>, Precision<>, Type<>, ...) in files that use the library, not an AST parse.",
    "False positives are excluded: a 3rd-party copy/vendoring of another project (an embedded project under its own subdirectory, an srcext/ or third_party/ tree), a hand-copy of an NVIDIA sample repo, a checked-in environment dump, and a package named only in a comment are NOT counted — only the repo's own genuine use.",
    "AI-authorship counts are a LOWER BOUND: Cursor, Gemini-CLI, inline Copilot and web/copy-paste use leave no commit marker. 'none detected' != 'no AI'.",
    "Discovery via GitHub code search (1000-result cap mitigated by extension/size partitioning); any capped, incomplete, or exhausted query blocks publication.",
    "Date adopted = author date of the first commit introducing the usage/reference (squash/rebase can shift this).",
    "Mirror/re-uploaded repos are de-duplicated: repos sharing an integration commit SHA are the same codebase, so only the canonical copy (most stars) is counted.",
    "NVPL is the one additive family: component pages count their own integrations and the NVPL parent totals/timeline sum those component integrations plus NVPL-only evidence that maps to no component. A repo using several components contributes once to each component and therefore multiple times to the parent integration metric; the parent repository table still lists each distinct repository once.",
]


def _detection_hash():
    """Content hash of the detection-relevant code+config (scan.py + discover.py +
    config.py). ANY edit to a regex, the LIBRARIES registry, a `released_on`, EXCLUDED_*,
    PY_SIGNALS, or a vendor filter changes this hash → the incremental cache is invalidated
    and a full re-scan runs that week. Automatic + can't-forget, so a detection change never
    silently serves stale cached results (adversarial-review MF-2, which also subsumes the
    released_on-clamp staleness MF-3 and the undated-then-logic-improved case NF-3)."""
    import hashlib
    h = hashlib.sha256()
    here = os.path.dirname(__file__)
    for fn in ("scan.py", "discover.py", "config.py"):
        with open(os.path.join(here, fn), "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()[:16]


def log(msg):
    print(msg, flush=True)


def _month_iter(start_ym, end_ym):
    y, m = int(start_ym[:4]), int(start_ym[5:7])
    ey, em = int(end_ym[:4]), int(end_ym[5:7])
    out = []
    while (y, m) <= (ey, em):
        out.append("%04d-%02d" % (y, m))
        m += 1
        if m > 12:
            m, y = 1, y + 1
    return out


def _days_ago(date_str, ref):
    try:
        d = datetime.date.fromisoformat(date_str)
        return (ref - d).days
    except Exception:
        return 10 ** 6


def _ago(today, days):
    return (today - datetime.timedelta(days=days)).isoformat()


def _between(dates, lo, hi):
    """Count ISO date strings d with lo < d <= hi (rolling-window counter)."""
    return sum(1 for d in dates if d and lo < d[:10] <= hi)


def _growth(hl_dates, days, today, released_on):
    """Period-over-period new-adopter counts for the velocity cards — or None when the library is
    younger than a FULL prior comparison window (the prior period [today-2*days, today-days] would
    begin before released_on). None -> the UI shows a pending "—" instead of a misleading % (a
    library only a few months old has no honest 90d/365d growth: its prior window is empty, so any
    real adoption reads as a fake "▲ new"). Recomputed every run, so it auto-fills once enough
    history since release accrues."""
    if _ago(today, 2 * days)[:7] < released_on:
        return None
    return {"current": _between(hl_dates, _ago(today, days), today.isoformat()),
            "prev": _between(hl_dates, _ago(today, 2 * days), _ago(today, days))}


def _dedup_mirrors(repos, log):
    """Drop mirror / re-uploaded duplicate repos.

    A repo that shares an integration commit SHA with another is the same
    codebase re-hosted (a manual mirror — `fork=false`, so the GitHub-fork
    exclusion misses it). Commit SHAs are globally unique, so a shared SHA is a
    reliable signal. Group repos transitively by shared SHA, keep the canonical
    copy (most stars, then most commits, then name), drop the rest.
    Returns (kept_repos, dropped) where dropped lists {dropped, kept, shared_commit}.
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    sha_owner, sha_for = {}, {}
    for r in repos:
        fn = r["full_name"]
        find(fn)
        for e in r["libraries"]:
            sha = e.get("first_integration_commit")
            if sha:
                if sha in sha_owner:
                    union(sha_owner[sha], fn)
                else:
                    sha_owner[sha] = fn
                sha_for.setdefault(fn, sha)

    groups = {}
    for r in repos:
        groups.setdefault(find(r["full_name"]), []).append(r)

    def evidence_signature(repo):
        """Current adoption evidence that must be identical before two repositories
        can be collapsed as mirrors.

        A shared historical commit proves common ancestry, not continued identity.
        Diverged reuploads may add a second library or move/change their evidence
        after the shared commit. The old implementation dropped the whole divergent
        repository and could therefore lose unique current integrations.
        """
        rows = []
        for entry in repo.get("libraries", []):
            rows.append((
                entry.get("library_id"),
                entry.get("classification"),
                entry.get("first_integration_commit") or "",
                tuple(sorted(entry.get("own_source_files") or ())),
                tuple(sorted(entry.get("operators") or ())),
            ))
        return tuple(sorted(rows))

    kept, dropped = [], []
    for grp in groups.values():
        if len(grp) == 1:
            kept.append(grp[0])
            continue
        by_evidence = {}
        for repo in grp:
            by_evidence.setdefault(evidence_signature(repo), []).append(repo)
        if len(by_evidence) > 1:
            log("  DEDUP: retained %d diverged repositories sharing historical commits"
                % len(grp))
        for identical in by_evidence.values():
            if len(identical) == 1:
                kept.append(identical[0])
                continue
            # Only byte-equivalent evidence variants are mirrors. Prefer the
            # most visible/current canonical repository for display.
            identical.sort(
                key=lambda r: (r.get("stars", 0), r.get("total_commits", 0),
                               r["full_name"]),
                reverse=True)
            canonical = identical[0]
            kept.append(canonical)
            for repo in identical[1:]:
                dropped.append({
                    "dropped": repo["full_name"],
                    "kept": canonical["full_name"],
                    "shared_commit": sha_for.get(repo["full_name"], ""),
                    "confirmed_libs": [
                        e["library_id"] for e in repo["libraries"]
                        if e.get("classification") == "confirmed"
                    ],
                })
                log("  DEDUP: dropped evidence-identical mirror %s (canonical %s)"
                    % (repo["full_name"], canonical["full_name"]))
    return kept, dropped


def _component_children(lib, repos, today, end_ym):
    """First-class child sub-library aggregates + timeseries for a parent lib that declares
    `component_children` (NVPL). Children are a RE-PROJECTION of the parent's already-scanned
    per-repo component labels — NO new detection. For each child: confirmed/bundled/targeted repos
    = the parent's repos of that class whose component `label` is present in the parent entry's
    operators; confirmed DATES use the parent entry's per-component `component_detail` (precise
    per-component first-#include) when present, else the parent's family date; bundled/targeted
    dates use the family date. A date earlier than the child's OWN released_on is dropped to undated
    (per-component release clamp — a wrong date corrupts the child graph's x-axis anchor). Returns
    (child_lib_out:list, child_ts:dict). The parent entry is untouched; its headline still sums all
    components (children can total less — some Backend/targeted adoption names no single component)."""
    pid = lib["id"]
    counts_build = bool(lib.get("adoption_counts_build"))
    ents = []
    for r in repos:
        e = next((x for x in r["libraries"] if x["library_id"] == pid), None)
        if e:
            ents.append((r, e))
    children_out, child_ts = [], {}
    for child in lib["component_children"]:
        label, rel = child["label"], child["released_on"]

        def _clamp(d, _rel=rel):
            return d if (d and d[:7] >= _rel) else None

        def _cd(e):
            return (e.get("component_detail") or {}).get(label) or {}

        # Membership per band. CONFIRMED keys on `component_detail` (the component was actually
        # #included) — NOT operators, which on a confirmed repo ALSO carries build-level labels
        # (a repo that #includes nvpl_scalapack but only find_package()s BLAS must not read as
        # BLAS-confirmed). Fall back to operators only for old carried-forward entries with no
        # per-component detail. Backend/targeted bands use operators (build/mention level by nature).
        conf, bund, targ = [], [], []
        for (r, e) in ents:
            ops = e.get("operators") or []
            kl = e["classification"]
            if kl == "confirmed":
                cdmap = e.get("component_detail")
                if (label in cdmap) if cdmap else (label in ops):
                    conf.append((r, e))
            elif kl == "bundled" and label in ops:
                bund.append((r, e))
            elif kl == "targeted" and label in ops:
                targ.append((r, e))

        def _conf_date(e):
            return _clamp(_cd(e).get("first_integration") or e.get("first_integration"))

        conf_dates = [d for (r, e) in conf for d in [_conf_date(e)] if d]
        bund_dates = [d for (r, e) in bund for d in [_clamp(e.get("first_integration"))] if d]
        targ_dates = [d for (r, e) in targ for d in [_clamp(e.get("first_integration"))] if d]
        ai_dates = [d for (r, e) in conf for d in [_conf_date(e)]
                    if d and (_cd(e).get("ai_on_integration_commit") or e.get("ai_on_integration_commit"))]
        cc = len(conf)
        hl_dates = (conf_dates + bund_dates) if counts_build else conf_dates
        headline = cc + (len(bund) if counts_build else 0)
        children_out.append({
            "id": child["id"], "name": child["name"], "tier": lib["tier"],
            "language": lib.get("language", "cpp"),
            "parent_id": pid, "is_component": True, "component_label": label,
            "released_on": rel, "released_confidence": child.get("released_confidence", lib["released_confidence"]),
            "description": "%s — %s component of the %s CPU library family." % (child["name"], label, lib["name"]),
            "confirmed_count": cc, "targeted_count": len(targ), "bundled_count": len(bund),
            "headline_count": headline,
            "adoption_counts_build": counts_build,
            "bundled_label": lib.get("bundled_label"),
            "integration_ai_count": len(ai_dates),
            "repo_ai_count": sum(1 for (r, e) in conf if r.get("ai_assisted")),
            "first_seen_earliest": min(conf_dates) if conf_dates else None,
            "trending_30d": sum(1 for d in conf_dates if _days_ago(d, today) <= 30),
            "trending_90d": sum(1 for d in conf_dates if _days_ago(d, today) <= 90),
            "growth_90d": _growth(hl_dates, 90, today, rel),
            "growth_365d": _growth(hl_dates, 365, today, rel),
            "citation_growth_90d": None, "citation_growth_365d": None,
            "coverage_gaps": 0, "scan_capped": None,
        })
        alld = conf_dates + bund_dates + targ_dates
        start = rel
        if alld:
            earliest = min(d[:7] for d in alld)
            if earliest < start:
                start = earliest
        pts = [{"month": ym,
                "confirmed": sum(1 for d in conf_dates if d[:7] <= ym),
                "bundled": sum(1 for d in bund_dates if d[:7] <= ym),
                "targeted": sum(1 for d in targ_dates if d[:7] <= ym),
                "cumulative_ai": sum(1 for d in ai_dates if d[:7] <= ym)}
               for ym in _month_iter(start, end_ym)]
        child_ts[child["id"]] = {"released_on": start,
                                 "released_confidence": child.get("released_confidence", "high"),
                                 "points": pts}
    return children_out, child_ts


def aggregate(repos, libs, today, discovery_stats, capped_note, mirror_drops):
    """Per-library aggregates + stacked time-series + the `current` dict, built
    from a scanned repo list. Pure (no I/O) so both the full run and a targeted
    re-scan/patch reuse identical logic. Returns (current, ts_out)."""
    lib_out, ts_out = [], {}
    generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    timeseries_as_of = today.isoformat()
    end_ym = "%04d-%02d" % (today.year, today.month)
    for lib in libs:
        lid = lib["id"]

        def entry(r, _lid=lid):
            return next((e for e in r["libraries"] if e["library_id"] == _lid), None)

        confirmed = [r for r in repos if (entry(r) or {}).get("classification") == "confirmed"]
        bundled = [r for r in repos if (entry(r) or {}).get("classification") == "bundled"]
        targeted = [r for r in repos if (entry(r) or {}).get("classification") == "targeted"]
        conf_dates = [entry(r)["first_integration"] for r in confirmed if entry(r)["first_integration"]]
        bundled_dates = [entry(r)["first_integration"] for r in bundled if entry(r)["first_integration"]]
        targeted_dates = [entry(r)["first_integration"] for r in targeted if entry(r)["first_integration"]]
        ai_dates = [entry(r)["first_integration"] for r in confirmed
                    if entry(r).get("ai_on_integration_commit") and entry(r)["first_integration"]]
        repo_ai = [r for r in confirmed if r["ai_assisted"]]
        cc = len(confirmed)
        # NVPL-style libs (CPU drop-in backends) count build-level "Backend" adoption
        # into the headline + velocity via a per-lib flag; all other libs stay
        # confirmed-only (REQ-05 trust keystone). hl_dates = the dated set the
        # velocity windows are computed over; headline_count = the big number.
        counts_build = bool(lib.get("adoption_counts_build"))
        hl_dates = (conf_dates + bundled_dates) if counts_build else conf_dates
        headline_count = cc + (len(bundled) if counts_build else 0)
        lib_out.append({
            "id": lid, "name": lib["name"], "tier": lib["tier"],
            "language": lib.get("language", "cpp"),
            "released_on": lib["released_on"], "released_confidence": lib["released_confidence"],
            "description": lib["description"],
            "confirmed_count": cc,
            "targeted_count": len(targeted),
            "bundled_count": len(bundled),
            "headline_count": headline_count,            # confirmed (+ bundled if counts_build)
            "adoption_counts_build": counts_build,
            "bundled_label": lib.get("bundled_label"),   # e.g. "Backend" for NVPL; else None
            "integration_ai_count": len(ai_dates),
            "repo_ai_count": len(repo_ai),
            "first_seen_earliest": min(conf_dates) if conf_dates else None,
            "trending_30d": sum(1 for d in conf_dates if _days_ago(d, today) <= 30),
            "trending_90d": sum(1 for d in conf_dates if _days_ago(d, today) <= 90),
            # Key-takeaways cards (auto-updated each refresh): ROLLING-window new
            # adopters — last 90 days vs the prior 90, and last 365 vs the prior 365
            # (over hl_dates, so flagged libs include Backend). Equal-length windows.
            "growth_90d": _growth(hl_dates, 90, today, lib["released_on"]),
            "growth_365d": _growth(hl_dates, 365, today, lib["released_on"]),
            # Citation growth (REQ-07, not built yet) — placeholders for when it lands.
            "citation_growth_90d": None,
            "citation_growth_365d": None,
            "coverage_gaps": len(discovery_stats[lid]["coverage_gaps"]) if lid in discovery_stats else 0,
            "scan_capped": capped_note.get(lid),
            # Mature detectors evaluate all historical bands.  REQ-14's XXL
            # additions explicitly evaluate confirmed direct use only.
            "classification_coverage": {
                band: (
                    "evaluated"
                    if band in lib.get(
                        "classification_coverage",
                        ("confirmed", "bundled", "targeted"),
                    )
                    else "not_evaluated"
                )
                for band in ("confirmed", "bundled", "targeted")
            },
            "not_evaluated_classes": list(lib.get("not_evaluated_classes", ())),
            "rollup_to": lib.get("rollup_to"),
        })
        # stacked monthly cumulative time-series; anchor at release date, clamp
        # earlier if any first-seen (confirmed/bundled/targeted) predates it.
        alldates = conf_dates + bundled_dates + targeted_dates
        start = lib["released_on"]
        if alldates:
            earliest = min(d[:7] for d in alldates)
            if earliest < start:
                start = earliest
        pts = []
        for ym in _month_iter(start, end_ym):
            pts.append({
                "month": ym,
                "confirmed": sum(1 for d in conf_dates if d[:7] <= ym),
                "bundled": sum(1 for d in bundled_dates if d[:7] <= ym),
                "targeted": sum(1 for d in targeted_dates if d[:7] <= ym),
                "cumulative_ai": sum(1 for d in ai_dates if d[:7] <= ym),
            })
        ts_out[lid] = {"released_on": start, "released_confidence": lib["released_confidence"], "points": pts}

        # Parent -> children split (NVPL): expand each detected component into a first-class
        # sub-library entry + its own series, so each gets a page+graph. Added to lib_out BEFORE
        # the sparkline post-pass so children get sparklines uniformly. Parent entry unchanged.
        if lib.get("component_children"):
            ch_out, ch_ts = _component_children(lib, repos, today, end_ym)
            lib_out.extend(ch_out)
            ts_out.update(ch_ts)

    for l in lib_out:
        pts = ts_out[l["id"]]["points"]
        # Home-card graph = the full ADOPTER trend (confirmed + bundled + targeted).
        # The headline NUMBER stays confirmed-only (REQ-05); the sparkline shows the
        # whole adoption picture. sparkline_months gives the x-axis tick labels.
        l["sparkline"] = [p["confirmed"] + p["bundled"] + p["targeted"] for p in pts]
        l["sparkline_months"] = [p["month"] for p in pts]

    for series in ts_out.values():
        series.setdefault("as_of", timeseries_as_of)

    current = {
        "generated_at": generated_at,
        "method_version": METHOD_VERSION,
        "detection_hash": _detection_hash(),   # incremental-refresh cache key (MF-2)
        "caveats": CAVEATS,
        "totals": {
            "tracked_libraries": len(libs),
            "confirmed_integrator_repos": sum(1 for r in repos if any(
                e["classification"] == "confirmed" for e in r["libraries"])),
            "ai_assisted_repos": sum(1 for r in repos if r["ai_assisted"]),
        },
        "libraries": lib_out,
        "repos": repos,
        "discovery_stats": discovery_stats,
        "deduped_mirrors": mirror_drops,
    }
    return current, ts_out


def _build_entry(fn, sc, m, libs):
    """Assemble one scanned repo's output dict from a scan_repo() result `sc` and its
    enriched metadata `m` (applying the release-date clamp per lib). Returns None if the
    repo confirms no library. Pure; shared by the full scan and the incremental rescan."""
    lib_entries = []
    for lib in libs:
        r = sc["libraries"].get(lib["id"])
        if not r:
            continue
        fi = r.get("first_integration")
        if fi and fi[:7] < lib["released_on"]:
            log("    CLAMP %s/%s: adopted %s predates release %s -> undated"
                % (fn, lib["id"], fi, lib["released_on"]))
            r["first_integration"] = None
            r["first_integration_commit"] = ""
        lib_entries.append(dict(library_id=lib["id"], **r))
    if not lib_entries:
        return None
    confirmed_dates = [e["first_integration"] for e in lib_entries
                       if e["classification"] == "confirmed" and e["first_integration"]]
    return {
        "full_name": fn,
        "html_url": m.get("html_url"), "owner": m.get("owner"), "owner_type": m.get("owner_type"),
        "description": m.get("description"),
        "stars": m.get("stars", 0), "forks": m.get("forks", 0),
        "language": m.get("language"), "topics": m.get("topics", []),
        "license": m.get("license"), "archived": m.get("archived", False),
        "created_at": m.get("created_at"), "pushed_at": m.get("pushed_at"),
        "total_commits": sc["total_commits"],
        "ai_agents": sc["ai_agents"], "ai_assisted": bool(sc["ai_agents"]),
        "ai_config_files": sc["ai_config_files"],
        "libraries": lib_entries,
        "earliest_integration": min(confirmed_dates) if confirmed_dates else None,
    }


def _drop_unpublishable_candidates(union, lib_candidates, meta, log):
    """Remove private/unverified, confirmed-gone, and forked repositories.

    Visibility and gone status are checked before fork status so each candidate
    has one reason. Cached entries are also handled by ledger.classify(), because
    they remain in the incremental `consider` set.
    """
    dropped_private = dropped_gone = dropped_fork = 0
    for fn in list(union):
        m = meta.get(fn, {})
        if m.get("visibility_excluded"):
            dropped_private += 1
        elif m.get("gone"):
            dropped_gone += 1
        elif m.get("is_fork"):
            dropped_fork += 1
        else:
            continue
        union.discard(fn)
        for candidates in lib_candidates.values():
            candidates.discard(fn)
    if dropped_private:
        log("  public-only filter: dropped %d private/unverified repo(s)"
            % dropped_private)
    if dropped_gone:
        log("  gone filter: dropped %d deleted/unavailable repo(s)" % dropped_gone)
    if dropped_fork:
        log("  fork filter: dropped %d repo(s)" % dropped_fork)
    return dropped_private, dropped_gone, dropped_fork


def _coverage_gap_count(discovery_stats):
    return sum(
        len(stats.get("coverage_gaps", ()))
        for stats in discovery_stats.values()
        if isinstance(stats, dict)
    )


def main(argv=None):
    # REQ-14 replaced this unbounded V1 collection command.  Aggregation and
    # migration helpers in this module remain importable, but module execution
    # must never reach network or generated-data writes.
    parser = argparse.ArgumentParser(
        description="Retired V1 CUDA-X collector command"
    )
    parser.add_argument("--max-per-lib")
    parser.add_argument("--libraries")
    parser.add_argument("--out")
    parser.add_argument("--incremental", action="store_true")
    parser.parse_known_args(argv)
    print(
        "ERROR: collector.run is retired by REQ-14; use "
        "`python3.12 -m collector.cli refresh` (or `plan`/`reconcile`)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
