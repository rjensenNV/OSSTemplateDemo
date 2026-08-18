"""Snapshot persistence + diff (powers deltas and 'new since last refresh').

Each run writes data/snapshots/<date>.json. On the next run we diff the current
repo/library set against the most recent prior snapshot:
  - per library: delta in confirmed-integration count
  - per repo: is_new (first seen this refresh)
Bootstrap run (no prior snapshot) marks nothing 'new' (so the dashboard does
not flash everything green on first publish).
"""
import glob
import json
import os

SNAP_DIR = os.path.join("data", "snapshots")


def _prior_snapshot(before_path):
    # Read prior snapshots from the SAME dir we write into (derived from --out),
    # not a hardcoded path — otherwise a non-default --out reads diffs from the
    # wrong place and flags every repo "new" (TD-2).
    snap_dir = os.path.dirname(before_path) or SNAP_DIR
    os.makedirs(snap_dir, exist_ok=True)
    files = sorted(glob.glob(os.path.join(snap_dir, "*.json")))
    files = [f for f in files if os.path.abspath(f) != os.path.abspath(before_path)]
    if not files:
        return None
    with open(files[-1]) as fh:
        return json.load(fh)


def apply_diff(current, snapshot_path):
    """Mutate `current` in place: mark genuinely-new adoptions + per-library deltas.

    'New' means ADOPTED SINCE THE LAST REFRESH — a library entry whose
    first_integration date is after the prior snapshot's date — NOT merely
    first-seen in our crawl. So a newly ONBOARDED library does not flash its
    whole back-catalog as new, a newly-discovered OLD adopter is not "new," and
    mirror de-dups (old dates) never read as loss. Sets per-entry `is_new`,
    repo-level `is_new` (true if any entry is new), and per-library
    `delta_since_last` (count of repos that newly adopted since the prior refresh,
    any class — confirmed, declared/bundled, or targeted).
    Returns (is_bootstrap, prior_date)."""
    prior = _prior_snapshot(snapshot_path)
    if prior is None:
        for repo in current["repos"]:
            repo["is_new"] = False
            for e in repo["libraries"]:
                e["is_new"] = False
        for lib in current["libraries"]:
            lib["delta_since_last"] = 0
        return True, None

    prior_date = (prior.get("generated_at", "") or "")[:10]
    per_lib_new = {}
    for repo in current["repos"]:
        repo_new = False
        for e in repo["libraries"]:
            adopted = e.get("first_integration")
            # "new" = first appeared since the prior refresh, regardless of class
            # (a repo that newly shows up as confirmed, declared, or targeted counts).
            new = bool(adopted) and adopted > prior_date
            e["is_new"] = new
            if new:
                repo_new = True
                per_lib_new[e["library_id"]] = per_lib_new.get(e["library_id"], 0) + 1
        repo["is_new"] = repo_new
    for lib in current["libraries"]:
        lib["delta_since_last"] = per_lib_new.get(lib["id"], 0)
    return False, prior_date


def write_snapshot(current, snapshot_path):
    """Persist a compact snapshot for next run's diff."""
    snap = {
        "generated_at": current["generated_at"],
        "libraries": [{"id": l["id"], "confirmed_count": l.get("confirmed_count", 0)}
                      for l in current["libraries"]],
    }
    os.makedirs(os.path.dirname(snapshot_path), exist_ok=True)
    with open(snapshot_path, "w") as fh:
        json.dump(snap, fh, indent=2)
