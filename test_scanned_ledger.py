"""Validation for the scanned-ledger (collector/ledger.py). Pure logic — no network, no token,
no clones. Proves the load-bearing guarantees before this goes near the live collector.

Run:  python3 test_scanned_ledger.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collector import ledger

P = 0
F = 0


def check(name, cond):
    global P, F
    if cond:
        P += 1
        print("  PASS  " + name)
    else:
        F += 1
        print("  FAIL  " + name)


def fb_unchanged(m, ce):
    return False        # legacy pushed_at test says "not changed" -> reuse


def fb_changed(m, ce):
    return True         # legacy pushed_at test says "changed" -> rescan


print("1) content_unchanged — the HEAD-SHA gate")
check("same HEAD -> unchanged", ledger.content_unchanged({"head_sha": "abc"}, "abc") is True)
check("different HEAD -> changed", ledger.content_unchanged({"head_sha": "xyz"}, "abc") is False)
check("no current HEAD (API miss) -> re-scan", ledger.content_unchanged({"head_sha": None}, "abc") is False)
check("no recorded HEAD (pre-ledger) -> re-scan", ledger.content_unchanged({"head_sha": "abc"}, None) is False)

print("\n2) THE question: a known non-adopter later ADOPTS the library")
shas = {"acme/widgets": "sha_OLD"}            # ledger knows it as a reject at sha_OLD
check("reject whose HEAD moved (adoption) -> RE-SCAN (caught)",
      ledger.classify("acme/widgets", {"head_sha": "sha_NEW", "accessible": True}, {}, shas, fb_changed) == "rescan")
check("reject with unchanged HEAD -> skip-reject (no wasted clone)",
      ledger.classify("acme/widgets", {"head_sha": "sha_OLD", "accessible": True}, {}, shas, fb_changed) == "skip-reject")
check("reject transiently inaccessible -> re-scan (never trust an unverifiable skip)",
      ledger.classify("acme/widgets", {"head_sha": "sha_OLD", "accessible": False}, {}, shas, fb_changed) == "rescan")

print("\n3) tracked repo reuse gate (SHA from side ledger) + migration fallback")
cached = {"acme/lib": {"libraries": [{"library_id": "dali"}]}}   # NOTE: no head_sha in current.json
tracked_shas = {"acme/lib": "H1"}
check("tracked, ledger HEAD unchanged -> reuse",
      ledger.classify("acme/lib", {"head_sha": "H1", "accessible": True}, cached, tracked_shas, fb_changed) == "reuse")
check("tracked, ledger HEAD moved -> re-scan",
      ledger.classify("acme/lib", {"head_sha": "H2", "accessible": True}, cached, tracked_shas, fb_changed) == "rescan")
check("tracked, 404 -> drop-gone",
      ledger.classify("acme/lib", {"gone": True}, cached, tracked_shas, fb_changed) == "drop-gone")
check("tracked, now a fork -> drop-fork",
      ledger.classify("acme/lib", {"is_fork": True, "accessible": True}, cached, tracked_shas, fb_changed) == "drop-fork")
check("tracked, NO ledger SHA yet (deploy run) + pushed_at unchanged -> reuse (migration)",
      ledger.classify("acme/lib", {"head_sha": "H1", "accessible": True}, cached, {}, fb_unchanged) == "reuse")
check("tracked, NO ledger SHA yet + pushed_at changed -> re-scan (migration)",
      ledger.classify("acme/lib", {"head_sha": "H1", "accessible": True}, cached, {}, fb_changed) == "rescan")

print("\n4) rebuild — carry-forward + confidence filter (errored/gone dropped)")
# prior rejects x (stays reject, re-scanned), q (skipped, unchanged), z (scan errored), g (gone)
prior = {"x": "sx", "q": "sq", "z": "sz", "g": "sg", "acme/lib": "H1"}
repos = [{"full_name": "acme/lib"}, {"full_name": "y"}]     # tracked (lib reused, y = ex-reject adopted)
meta = {"acme/lib": {"head_sha": "H1"}, "y": {"head_sha": "sy_new"}}
new_rejects = {"x": "sx2", "w": "sw"}      # x re-scanned still-reject (new HEAD), w newly rejected
skipped = {"q"}                            # q skipped (unchanged)
# z errored, g gone -> in none of repos/new_rejects/skipped
nxt = ledger.rebuild(repos, meta, new_rejects, skipped, prior)
check("adopter y now tracked, in ledger with its HEAD", nxt.get("y") == "sy_new")
check("tracked acme/lib keeps HEAD", nxt.get("acme/lib") == "H1")
check("still-reject x kept with UPDATED HEAD", nxt.get("x") == "sx2")
check("new reject w added", nxt.get("w") == "sw")
check("skipped reject q carries prior HEAD", nxt.get("q") == "sq")
check("errored z DROPPED (retried next run)", "z" not in nxt)
check("gone g DROPPED", "g" not in nxt)
failed_nxt = ledger.rebuild(
    [{"full_name": "acme/lib"}],
    {"acme/lib": {"head_sha": "H2"}},
    {}, set(), {"acme/lib": "H1"}, failed={"acme/lib"})
check("failed cached re-scan keeps OLD SHA so next week retries",
      failed_nxt.get("acme/lib") == "H1")

print("\n5) persistence: detection-hash binding + ignored local ledger + compact")
with tempfile.TemporaryDirectory() as d:
    out = os.path.join(d, "data")
    os.makedirs(out)
    ledger.save(out, "HASH_v1", {"acme/widgets": "sha_OLD"})
    lp = os.path.join(d, "scanned_ledger.json")
    check("ledger written at repo root, NOT in generated data/",
          os.path.exists(lp) and not os.path.exists(os.path.join(out, "scanned_ledger.json")))
    with open(lp) as fh:
        ledger_text = fh.read()
    check("stored compact (no pretty-print whitespace)", '": "' not in ledger_text)
    check("load same hash -> SHAs returned", ledger.load(out, "HASH_v1") == {"acme/widgets": "sha_OLD"})
    check("load changed hash -> {} (re-scan everything)", ledger.load(out, "HASH_v2") == {})

print("\n6) end-to-end: reject -> adopt across two weeks")
wk1 = ledger.rebuild([], {}, {"acme/widgets": "sha_OLD"}, set(), {})   # week1 recorded it as a reject
check("week2 quiet (HEAD unchanged) -> skip-reject",
      ledger.classify("acme/widgets", {"head_sha": "sha_OLD", "accessible": True}, {}, wk1, fb_changed) == "skip-reject")
check("week2 adoption (HEAD moved) -> rescan (never skipped)",
      ledger.classify("acme/widgets", {"head_sha": "sha_NEW", "accessible": True}, {}, wk1, fb_changed) == "rescan")

print("\n%d passed, %d failed" % (P, F))
sys.exit(1 if F else 0)
