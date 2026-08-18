"""Deterministic pre-push gate for a generated weekly refresh."""
import argparse
import datetime
import json
import math
import os
import subprocess
import sys

from .config import LIBRARIES
from .run import _component_children, _detection_hash

MAX_CURRENT_BYTES = 5 * 1024 * 1024
COUNT_FIELDS = ("confirmed_count", "bundled_count", "targeted_count", "headline_count")


def fail(message, errors):
    errors.append(message)
    print("ERROR: " + message)


def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def load_baseline(ref):
    raw = subprocess.check_output(
        ["git", "show", "%s:data/current.json" % ref], text=True)
    return json.loads(raw)


def load_v2_baseline(ref):
    raw = subprocess.check_output(
        ["git", "show", "%s:data/v2/manifest.json" % ref], text=True)
    return json.loads(raw)


def repo_counts(current):
    counts = {}
    confirmed_repos = set()
    for repo in current.get("repos", []):
        fn = repo.get("full_name")
        for entry in repo.get("libraries", []):
            lib_id = entry.get("library_id")
            klass = entry.get("classification")
            if not lib_id or klass not in ("confirmed", "bundled", "targeted"):
                continue
            counts.setdefault(lib_id, {"confirmed": 0, "bundled": 0, "targeted": 0})
            counts[lib_id][klass] += 1
            if klass == "confirmed" and fn:
                confirmed_repos.add(fn)
    return counts, confirmed_repos


def component_counts(current):
    """Re-project expected component-child counts from parent repo entries."""
    try:
        today = datetime.date.fromisoformat(current["generated_at"][:10])
    except (KeyError, TypeError, ValueError):
        return {}
    expected = {}
    end_ym = "%04d-%02d" % (today.year, today.month)
    for parent in LIBRARIES:
        if not parent.get("component_children"):
            continue
        children, _timeseries = _component_children(
            parent, current.get("repos", []), today, end_ym)
        for child in children:
            expected[child["id"]] = child
    return expected


def changed_paths():
    tracked = subprocess.check_output(
        ["git", "diff", "--name-only"], text=True).splitlines()
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard"], text=True).splitlines()
    return sorted(set(tracked + untracked))


def _count_anomalies(baseline, current):
    """Return unattended count changes shared by V1 and V2 gates."""
    errors = []
    old_libs = {lib["id"]: lib for lib in baseline.get("libraries", [])}
    new_libs = {lib["id"]: lib for lib in current.get("libraries", [])}
    if set(old_libs) != set(new_libs):
        errors.append(
            "library IDs changed: removed=%s added=%s"
            % (
                sorted(set(old_libs) - set(new_libs)),
                sorted(set(new_libs) - set(old_libs)),
            )
        )

    print("count changes (old -> new):")
    had_count_changes = False
    for lib_id in sorted(set(old_libs) & set(new_libs)):
        changes = []
        for field in COUNT_FIELDS:
            old = old_libs[lib_id].get(field)
            new = new_libs[lib_id].get(field)
            # Metric-contract-pending V2 cards intentionally use null counts.
            if old is None and new is None:
                continue
            if (
                not isinstance(old, int)
                or isinstance(old, bool)
                or not isinstance(new, int)
                or isinstance(new, bool)
            ):
                errors.append(
                    "%s %s changed between a count and a non-count (%r -> %r)"
                    % (lib_id, field, old, new)
                )
                continue
            if old != new:
                had_count_changes = True
                changes.append(
                    "%s %d->%d"
                    % (field.removesuffix("_count"), old, new)
                )
                threshold = max(10, int(math.ceil(max(old, 1) * 0.15)))
                if abs(new - old) >= threshold:
                    errors.append(
                        "unattended anomaly: %s %s changed %d -> %d (gate %d)"
                        % (lib_id, field, old, new, threshold)
                    )
        if changes:
            print("  %s: %s" % (lib_id, ", ".join(changes)))
    if not had_count_changes:
        print("  no per-library count changes")

    old_total = baseline.get("totals", {}).get("confirmed_integrator_repos")
    new_total = current.get("totals", {}).get("confirmed_integrator_repos")
    if (
        not isinstance(old_total, int)
        or isinstance(old_total, bool)
        or not isinstance(new_total, int)
        or isinstance(new_total, bool)
    ):
        errors.append(
            "portfolio confirmed total is invalid (%r -> %r)"
            % (old_total, new_total)
        )
    else:
        portfolio_gate = max(
            25, int(math.ceil(max(old_total, 1) * 0.15))
        )
        if abs(new_total - old_total) >= portfolio_gate:
            errors.append(
                "portfolio confirmed total changed %d -> %d (gate %d)"
                % (old_total, new_total, portfolio_gate)
            )
    return errors


def validate_v2_refresh(baseline_ref="HEAD"):
    """Retain the pre-push anomaly gate for REQ-14's V2-only releases.

    V1's global detector stamp is intentionally retired, so checking it here
    would reject every valid V2 refresh. This path validates the complete V2
    artifact closure, compares counts with the committed V2 manifest, keeps the
    retained ledger well-formed, and rejects unexpected worktree changes.
    """
    errors = []
    from .validate_v2 import validate_v2

    try:
        baseline = load_v2_baseline(baseline_ref)
    except Exception as exc:
        print(
            "ERROR: cannot load baseline %s:data/v2/manifest.json: %s"
            % (baseline_ref, exc)
        )
        return 1

    current = None
    if not os.path.isfile("data/v2/manifest.json"):
        fail("missing required output data/v2/manifest.json", errors)
    else:
        try:
            current = load_json("data/v2/manifest.json")
        except Exception as exc:
            fail("invalid JSON data/v2/manifest.json: %s" % exc, errors)

    ledger_doc = None
    if os.path.isfile("scanned_ledger.json"):
        try:
            ledger_doc = load_json("scanned_ledger.json")
        except Exception as exc:
            fail("invalid JSON scanned_ledger.json: %s" % exc, errors)
        if not isinstance(ledger_doc, dict):
            fail("scanned_ledger.json must contain an object", errors)
        elif not isinstance(ledger_doc.get("shas"), dict):
            fail("scanned_ledger.json shas must be an object", errors)

    if current is not None:
        for message in validate_v2("data/v2"):
            fail("V2 release: " + message, errors)
        for message in _count_anomalies(baseline, current):
            fail(message, errors)

    unexpected = [
        path
        for path in changed_paths()
        if not (
            path.startswith("data/v2/")
            or path.startswith("data/state-checkpoint/")
            or path == "scanned_ledger.json"
        )
    ]
    if unexpected:
        fail(
            "collector changed unexpected paths: %s"
            % ", ".join(unexpected),
            errors,
        )

    if errors:
        print(
            "V2 refresh validation FAILED (%d issue%s)"
            % (len(errors), "" if len(errors) == 1 else "s")
        )
        return 1
    print("V2 refresh validation PASSED")
    return 0


def validate(baseline_ref="HEAD"):
    errors = []
    try:
        baseline = load_baseline(baseline_ref)
    except Exception as exc:
        print("ERROR: cannot load baseline %s:data/current.json: %s" % (baseline_ref, exc))
        return 1

    required = ("data/current.json", "data/timeseries.json", "data/deltas.json",
                "scanned_ledger.json")
    for path in required:
        if not os.path.isfile(path):
            fail("missing required output %s" % path, errors)
    ledger_doc = None
    if os.path.isfile("scanned_ledger.json"):
        try:
            ledger_doc = load_json("scanned_ledger.json")
        except Exception as exc:
            fail("invalid JSON scanned_ledger.json: %s" % exc, errors)
    for root, _dirs, files in os.walk("data"):
        for name in files:
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            try:
                load_json(path)
            except Exception as exc:
                fail("invalid JSON %s: %s" % (path, exc), errors)

    if errors:
        return 1
    current = load_json("data/current.json")
    deltas = load_json("data/deltas.json")

    size = os.path.getsize("data/current.json")
    print("current.json size: %d bytes" % size)
    if size >= MAX_CURRENT_BYTES:
        fail("current.json is %d bytes; limit is strictly below %d"
             % (size, MAX_CURRENT_BYTES), errors)

    for key, expected in (("libraries", list), ("repos", list), ("totals", dict),
                          ("generated_at", str), ("detection_hash", str)):
        if not isinstance(current.get(key), expected):
            fail("current.json field %s has wrong/missing type" % key, errors)
    if errors:
        return 1

    old_hash = baseline.get("detection_hash")
    new_hash = current.get("detection_hash")
    code_hash = _detection_hash()
    if new_hash != code_hash:
        fail("generated detection hash %s does not match current collector code %s"
             % (new_hash, code_hash), errors)
    elif old_hash != new_hash:
        print("detection hash changed %s -> %s; output is stamped with current code"
              % (old_hash, new_hash))

    if not isinstance(ledger_doc, dict):
        fail("scanned_ledger.json must contain an object", errors)
    else:
        ledger_hash = ledger_doc.get("detection_hash")
        shas = ledger_doc.get("shas")
        if ledger_hash != code_hash:
            fail("ledger detection hash %s does not match current collector code %s"
                 % (ledger_hash, code_hash), errors)
        if not isinstance(shas, dict):
            fail("scanned_ledger.json shas must be an object", errors)
        elif any(not isinstance(name, str) or not name
                 or not isinstance(sha, str) or not sha
                 for name, sha in shas.items()):
            fail("scanned_ledger.json contains an invalid repository/SHA entry", errors)
    ledger_size = os.path.getsize("scanned_ledger.json")
    print("scanned_ledger.json size: %d bytes" % ledger_size)
    if ledger_size >= MAX_CURRENT_BYTES:
        fail("scanned_ledger.json is %d bytes; limit is strictly below %d"
             % (ledger_size, MAX_CURRENT_BYTES), errors)

    old_libs = {lib["id"]: lib for lib in baseline.get("libraries", [])}
    new_libs = {lib["id"]: lib for lib in current.get("libraries", [])}
    if set(old_libs) != set(new_libs):
        fail("library IDs changed: removed=%s added=%s"
             % (sorted(set(old_libs) - set(new_libs)),
                sorted(set(new_libs) - set(old_libs))), errors)

    measured, confirmed_repos = repo_counts(current)
    derived_components = component_counts(current)
    for lib_id, lib in new_libs.items():
        if lib.get("is_component"):
            expected = derived_components.get(lib_id)
            if expected is None:
                fail("%s is marked as a component but has no registry projection"
                     % lib_id, errors)
                continue
            for field in COUNT_FIELDS:
                if lib.get(field) != expected.get(field):
                    fail("%s %s=%r but parent projection measures %r"
                         % (lib_id, field, lib.get(field), expected.get(field)), errors)
            continue
        actual = measured.get(lib_id, {})
        for field, klass in (("confirmed_count", "confirmed"),
                             ("bundled_count", "bundled"),
                             ("targeted_count", "targeted")):
            if lib.get(field) != actual.get(klass, 0):
                fail("%s %s=%r but repo records measure %r"
                     % (lib_id, field, lib.get(field), actual.get(klass, 0)), errors)
        expected_headline = actual.get("confirmed", 0)
        if lib.get("adoption_counts_build"):
            expected_headline += actual.get("bundled", 0)
        if lib.get("headline_count") != expected_headline:
            fail("%s headline_count=%r but repo records measure %r"
                 % (lib_id, lib.get("headline_count"), expected_headline), errors)
    total = current.get("totals", {}).get("confirmed_integrator_repos")
    if total != len(confirmed_repos):
        fail("portfolio confirmed_integrator_repos=%r but repo records measure %d"
             % (total, len(confirmed_repos)), errors)
    coverage_gap_count = sum(
        len(stats.get("coverage_gaps", ()))
        for stats in current.get("discovery_stats", {}).values()
        if isinstance(stats, dict)
    )
    print("discovery coverage gaps: %d" % coverage_gap_count)
    if coverage_gap_count:
        fail("discovery contains %d incomplete/capped query response(s)"
             % coverage_gap_count, errors)

    print("count changes (old -> new):")
    anomaly_rows = []
    had_count_changes = False
    for lib_id in sorted(set(old_libs) & set(new_libs)):
        changes = []
        for field in COUNT_FIELDS:
            old = old_libs[lib_id].get(field, 0)
            new = new_libs[lib_id].get(field, 0)
            if old != new:
                changes.append("%s %d->%d" % (field.removesuffix("_count"), old, new))
                threshold = max(10, int(math.ceil(max(old, 1) * 0.15)))
                if abs(new - old) >= threshold:
                    anomaly_rows.append("%s %s changed %d -> %d (gate %d)"
                                        % (lib_id, field, old, new, threshold))
        if changes:
            had_count_changes = True
            print("  %s: %s" % (lib_id, ", ".join(changes)))
    if not had_count_changes:
        print("  no per-library count changes")
    for row in anomaly_rows:
        fail("unattended anomaly: " + row, errors)

    old_total = baseline.get("totals", {}).get("confirmed_integrator_repos", 0)
    new_total = current.get("totals", {}).get("confirmed_integrator_repos", 0)
    portfolio_gate = max(25, int(math.ceil(max(old_total, 1) * 0.15)))
    if abs(new_total - old_total) >= portfolio_gate:
        fail("portfolio confirmed total changed %d -> %d (gate %d)"
             % (old_total, new_total, portfolio_gate), errors)

    scan_errors = deltas.get("scan_error_count", 0)
    if not isinstance(scan_errors, int) or scan_errors < 0:
        fail("deltas.json scan_error_count is invalid", errors)
    print("scan errors: %s" % scan_errors)

    unexpected = [
        path for path in changed_paths()
        if not (path.startswith("data/") or path == "scanned_ledger.json")
    ]
    if unexpected:
        fail("collector changed unexpected paths: %s" % ", ".join(unexpected), errors)

    if errors:
        print("refresh validation FAILED (%d issue%s)"
              % (len(errors), "" if len(errors) == 1 else "s"))
        return 1
    print("refresh validation PASSED")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default="HEAD")
    parser.add_argument(
        "--v2",
        action="store_true",
        help="validate the REQ-14 V2 release and compare manifest counts",
    )
    args = parser.parse_args(argv)
    return (
        validate_v2_refresh(args.baseline)
        if args.v2
        else validate(args.baseline)
    )


if __name__ == "__main__":
    sys.exit(main())
