"""Scanned-ledger — a side file (repo root, NOT data/) that records the default-branch HEAD SHA
we last scanned for EVERY repo, tracked or rejected. It does two jobs:

  1. Remembers CONFIDENT non-adopters (clean scan, zero tracked library) so a re-discovered reject
     whose HEAD is unchanged is SKIPPED instead of re-cloned — killing the incremental refresh's
     dominant cost (~83% of weekly re-scans are discovered-then-rejected repos, re-rejected every
     week because the cache only persisted *passing* repos).
  2. Carries the reuse-gate SHA for TRACKED repos too — kept out of current.json because head_sha
     is operational state that the frontend never reads. The ledger is ignored local data.

Correctness rests on one invariant, and every rule defends it:

  * THE INVARIANT — adopting a library requires committing an #include/import to the DEFAULT branch
    (scan_repo scans default-branch only). That commit changes the branch HEAD SHA. So a reject
    that later adopts a library ALWAYS fails `content_unchanged` -> re-scanned -> confirmed. It can
    never be silently skipped.
  * HEAD-SHA gate, not pushed_at — exact "did the scanned content change?" signal. No same-day-push
    blind spot (pushed_at is date-truncated), no any-branch over-trigger, catches default-branch
    reassignment. Missing SHA either side => re-scan (fail toward work, never toward a silent skip).
  * Confidence filter — only CLEAN scans are ledgered; an errored scan (clone/pickaxe/timeout) is
    never recorded, so a transient failure can't bury a real adopter. Enforced in `rebuild`:
    errored/gone repos appear in none of (repos, new_rejects, skipped) -> dropped -> retried.
  * Detection-hash binding — the ledger is valid only for the detection logic that wrote it. Any
    edit to scan.py/discover.py/config.py/LIBRARIES flips detection_hash (run.py:_detection_hash),
    so `load` returns {} -> everything re-scanned. A rule change or a NEW library re-measures full
    history automatically.
"""
import json
import os

LEDGER_FILE = "scanned_ledger.json"


def _path(out_dir):
    # Parent of out_dir ('data') = repo root -> ignored local operational state.
    return os.path.join(os.path.dirname(os.path.abspath(out_dir)), LEDGER_FILE)


def content_unchanged(meta, recorded_sha):
    """True iff we can CONFIDENTLY reuse a prior verdict: this run's default-branch HEAD SHA equals
    the SHA recorded when we last scanned. Missing SHA on either side => False (re-scan)."""
    cur = (meta or {}).get("head_sha")
    return bool(cur) and bool(recorded_sha) and cur == recorded_sha


def classify(fn, m, cached, shas, changed_fallback):
    """Single source of truth for the per-candidate incremental decision (used by run.py AND the
    tests). `cached` = tracked repos from prior current.json; `shas` = the ledger SHA-map (tracked
    + reject). Returns 'drop-private' | 'drop-gone' | 'drop-fork' | 'reuse' |
    'skip-reject' | 'rescan'.

    `changed_fallback(m, cached_entry) -> bool` is the legacy pushed_at test, consulted ONLY for a
    tracked repo that has no ledger SHA yet (first run after deploy) so the rollout doesn't force a
    full re-scan of the confirmed cache."""
    m = m or {}
    if m.get("visibility_excluded"):
        return "drop-private"
    if m.get("gone"):
        return "drop-gone"
    if m.get("is_fork"):
        return "drop-fork"
    if fn in cached:
        if not m.get("accessible", True):
            return "reuse"                       # SF-3 fail-safe: transient error -> retain cache
        rec = shas.get(fn)
        if rec:
            return "reuse" if content_unchanged(m, rec) else "rescan"
        return "reuse" if not changed_fallback(m, cached[fn]) else "rescan"   # pre-SHA migration
    if fn in shas and m.get("accessible", True) and content_unchanged(m, shas[fn]):
        return "skip-reject"                     # known non-adopter, HEAD unchanged
    return "rescan"                              # new, HEAD moved, error-retry, or unknown


def rebuild(repos, meta, new_rejects, skipped, prior_shas, failed=None):
    """Next SHA-map = HEAD SHAs of everything we still track or still reject:
       * tracked repos (in `repos`): this run's enriched HEAD SHA, or the carried prior SHA;
       * freshly-confirmed rejects (`new_rejects`: fn->sha): their scanned HEAD SHA;
       * skipped known-rejects (`skipped`: set of fn): carry their prior (unchanged) SHA.
    Errored/gone repos are in none of these -> dropped (the confidence filter). None SHAs dropped."""
    failed = set(failed or ())
    out = {}
    for r in repos:
        fn = r["full_name"]
        # A cached record retained after a failed re-scan must keep the OLD SHA.
        # Recording the new enriched SHA would make the next run believe the
        # unscanned content was already measured and silently skip it.
        if fn in failed:
            out[fn] = prior_shas.get(fn)
        else:
            out[fn] = (meta.get(fn, {}) or {}).get("head_sha") or prior_shas.get(fn)
    out.update(new_rejects)
    for fn in skipped:
        out[fn] = prior_shas.get(fn)
    return {fn: s for fn, s in out.items() if s}


def load(out_dir, detection_hash):
    """Return {full_name: head_sha} — but ONLY if written under the current detection logic. A hash
    mismatch (or missing/corrupt file) returns {}, forcing everything re-scanned this cycle (the
    new-library / rule-change safety net)."""
    try:
        with open(_path(out_dir)) as f:
            doc = json.load(f)
    except Exception:
        return {}
    if not isinstance(doc, dict) or doc.get("detection_hash") != detection_hash:
        return {}
    shas = doc.get("shas", {})
    return shas if isinstance(shas, dict) else {}


def save(out_dir, detection_hash, shas):
    """Persist the local SHA-map atomically, compact, and detection-hash bound."""
    path = _path(out_dir)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"detection_hash": detection_hash, "shas": shas}, f, separators=(",", ":"))
    os.replace(tmp, path)
