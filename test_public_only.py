"""Local-only public-repository boundary tests.

No network calls, clones, or generated-data writes.
"""
from unittest import mock

from collector import discover, enrich, github_api, ledger, run


def main():
    items = [
        {"repository": {"full_name": "public/example", "private": False}},
        {"repository": {"full_name": "private/secret", "private": True}},
        {"repository": {"full_name": "unknown/visibility"}},
        {"not_repository": True},
    ]
    repos, cap_hits, visibility_excluded = set(), [], set()
    with mock.patch.object(
            discover.gh, "code_search", return_value=(len(items), items, False)):
        discover._collect("fixture", repos, cap_hits, visibility_excluded)
    assert repos == {"public/example"}
    assert visibility_excluded == {"private/secret", "unknown/visibility"}
    print("PASS discovery admits only explicitly-public search results")

    with mock.patch.object(enrich.gh, "repo", return_value={
            "full_name": "private/secret", "private": True,
            "html_url": "https://github.com/private/secret",
    }), mock.patch.object(enrich.gh, "default_head_sha") as head:
        result = enrich.enrich("private/secret")
    assert result["visibility_excluded"] is True
    assert result["accessible"] is False
    head.assert_not_called()
    print("PASS enrichment rejects private metadata before the HEAD request")

    union = {"public/example", "private/secret", "public/gone", "public/fork"}
    candidates = {"fixture": set(union)}
    meta = {
        "public/example": {"private": False},
        "private/secret": {"visibility_excluded": True},
        "public/gone": {"private": False, "gone": True},
        "public/fork": {"private": False, "is_fork": True},
    }
    counts = run._drop_unpublishable_candidates(
        union, candidates, meta, lambda _message: None)
    assert counts == (1, 1, 1)
    assert union == {"public/example"}
    assert candidates["fixture"] == {"public/example"}
    print("PASS private, gone, and fork candidates are removed before clone selection")

    cached = {"private/secret": {"full_name": "private/secret"}}
    decision = ledger.classify(
        "private/secret", {"visibility_excluded": True}, cached, {},
        lambda _meta, _cached: False)
    assert decision == "drop-private"
    print("PASS cached private repositories are dropped instead of reused")

    response = {
        "total_count": 7,
        "items": [{"repository": {"full_name": "public/partial", "private": False}}],
        "incomplete_results": True,
    }
    with mock.patch.object(github_api, "_get", return_value=(response, {})), \
            mock.patch.object(github_api.time, "sleep"):
        total, returned, incomplete = github_api.code_search("fixture")
    assert (total, returned, incomplete) == (7, response["items"], True)
    print("PASS incomplete GitHub search responses become coverage gaps")

    repos, cap_hits, visibility_excluded = set(), [], set()
    with mock.patch.object(
            discover.gh, "code_search",
            return_value=(7, response["items"], True)) as search:
        try:
            discover._collect(
                "fixture", repos, cap_hits, visibility_excluded)
        except discover.DiscoveryCoverageGap:
            pass
        else:
            raise AssertionError("incomplete search did not stop discovery")
    assert repos == {"public/partial"}
    assert cap_hits == ["fixture"]
    assert search.call_count == 1
    print("PASS incomplete search fails fast after its first partial page")

    with mock.patch.object(github_api, "_get",
                           return_value=({"_http_error": "network"}, {})), \
            mock.patch.object(github_api.time, "sleep"):
        total, returned, incomplete = github_api.code_search("fixture")
    assert (total, returned, incomplete) == (None, [], True)
    assert run._coverage_gap_count({
        "fixture": {"coverage_gaps": ["fixture query"]},
    }) == 1
    print("PASS exhausted search failures cannot masquerade as zero matches")

    with mock.patch.object(github_api, "_get",
                           return_value=({"items": []}, {})), \
            mock.patch.object(github_api.time, "sleep"):
        total, returned, incomplete = github_api.code_search("fixture")
    assert (total, returned, incomplete) == (None, [], True)
    print("PASS malformed search payloads fail closed")

    overflow_item = {
        "repository": {"full_name": "public/overflow", "private": False},
    }
    repos, cap_hits, visibility_excluded = set(), [], set()
    with mock.patch.object(
            discover.gh, "code_search",
            return_value=(1001, [overflow_item], False)) as search:
        try:
            discover._collect(
                "fixture size:1..100", repos, cap_hits, visibility_excluded,
                terminal_partition=True)
        except discover.DiscoveryCoverageGap:
            pass
        else:
            raise AssertionError("overflowing terminal bucket did not stop discovery")
    assert repos == {"public/overflow"}
    assert cap_hits == ["fixture size:1..100 (>1000 matches)"]
    assert search.call_count == 1
    print("PASS an overflowing terminal size bucket is a coverage gap")

    repos, cap_hits, visibility_excluded = set(), [], set()
    with mock.patch.object(
            discover.gh, "code_search",
            return_value=(1001, [overflow_item], False)) as search:
        total = discover._collect(
            "fixture extension:py", repos, cap_hits, visibility_excluded)
    assert total == 1001
    assert cap_hits == []
    assert search.call_count == 1
    print("PASS an overflowing base query skips redundant capped pagination")

    with mock.patch.object(discover, "discover_library") as discovery, \
            mock.patch.object(enrich, "enrich") as enrichment:
        result = run.main(["--libraries", "cufftdx", "--out", "must-not-exist"])
    assert result == 2
    discovery.assert_not_called()
    enrichment.assert_not_called()
    print("PASS the retired V1 command cannot reach discovery or enrichment")

    print("\n11 passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
