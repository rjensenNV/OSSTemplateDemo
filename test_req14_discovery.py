"""Fixture-only tests for REQ-14 discovery and GitHub metadata.

No network, credentials, clones, production data, or state database are used.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from collector.discovery import (
    CoverageCertificate,
    CoverageEpochRule,
    DiscoveryObservation,
    IncompleteCoverageError,
    PUBLIC,
    assess_coverage_epoch,
    can_retire_candidate,
    combine_discovery_results,
    durable_union,
)
from collector.discovery.github_search import GitHubCodeSearch
from collector.discovery.sourcegraph import SourcegraphDiscovery, parse_sse
from collector.github_client import (
    GitHubBudgetError,
    GitHubGraphQLClient,
    GitHubGraphQLError,
    GitHubRESTFallbackClient,
    REST_FALLBACK_FIELDS,
    RepositoryLookup,
)


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def observation(
    name: str,
    *,
    node_id: str | None = None,
    observed_at: datetime = NOW,
    source: str = "fixture",
) -> DiscoveryObservation:
    return DiscoveryObservation(
        repo_full_name=name,
        repo_node_id=node_id,
        library_id="cublas",
        signal_id="header",
        source=source,
        query_fingerprint="fp",
        observed_at=observed_at,
        visibility=PUBLIC,
        matched_path="src/use.cu",
        matched_commit="a" * 40,
    )


def certificate(
    source: str, completed_at: datetime, *, complete: bool = True
) -> CoverageCertificate:
    return CoverageCertificate(
        source=source,
        library_id="cublas",
        query_fingerprint="fp",
        epoch_started_at=completed_at - timedelta(minutes=1),
        epoch_completed_at=completed_at if complete else None,
        complete=complete,
        terminal=complete,
        observations_count=1 if complete else 0,
    )


def public_item(
    name: str,
    path: str,
    blob: str,
    *,
    private: object = False,
    node_id: str | None = None,
) -> dict:
    repo = {"full_name": name, "private": private}
    if node_id is not None:
        repo["node_id"] = node_id
    return {"path": path, "sha": blob, "repository": repo}


def search_payload(total: int, items: list, *, incomplete: bool = False) -> dict:
    return {
        "total_count": total,
        "items": items,
        "incomplete_results": incomplete,
    }


def graphql_repo(
    name: str,
    *,
    node_id: str = "R_1",
    visibility: object = "PUBLIC",
    private: object = False,
    fork: object = False,
    archived: object = False,
    branch: object = "main",
    head: str = "b" * 40,
) -> dict:
    default = (
        None
        if branch is None
        else {"name": branch, "target": {"oid": head}}
    )
    return {
        "__typename": "Repository",
        "id": node_id,
        "nameWithOwner": name,
        "visibility": visibility,
        "isPrivate": private,
        "isFork": fork,
        "isArchived": archived,
        "defaultBranchRef": default,
    }


def graphql_response(
    repositories: dict,
    *,
    cost: int = 1,
    remaining: int = 4_900,
    errors: list | None = None,
) -> dict:
    data = dict(repositories)
    data["rateLimit"] = {
        "cost": cost,
        "remaining": remaining,
        "resetAt": "2026-07-27T13:00:00Z",
    }
    result = {"data": data}
    if errors is not None:
        result["errors"] = errors
    return result


class DurableCoverageTests(unittest.TestCase):
    def test_durable_union_preserves_absent_and_updates_rename_by_node_id(self):
        old = observation("old/name", node_id="R_1")
        renamed = observation(
            "new/name", node_id="R_1", observed_at=NOW + timedelta(minutes=1)
        )
        absent = observation("still/known", node_id="R_2")
        union = durable_union((old, absent), (renamed,))
        self.assertEqual(
            {(item.repo_node_id, item.repo_full_name) for item in union},
            {("R_1", "new/name"), ("R_2", "still/known")},
        )

    def test_durable_union_promotes_name_only_observation_to_node_identity(self):
        name_only = observation("acme/tool")
        enriched = observation(
            "acme/tool", node_id="R_1", observed_at=NOW + timedelta(minutes=1)
        )
        union = durable_union((name_only,), (enriched,))
        self.assertEqual(len(union), 1)
        self.assertEqual(union[0].repo_node_id, "R_1")

    def test_epoch_requires_each_fresh_complete_source_before_retirement(self):
        rules = (
            CoverageEpochRule("sourcegraph", timedelta(days=7)),
            CoverageEpochRule("github-code-search", timedelta(days=28)),
        )
        good = assess_coverage_epoch(
            (
                certificate("sourcegraph", NOW - timedelta(days=1)),
                certificate("github-code-search", NOW - timedelta(days=20)),
            ),
            library_id="cublas",
            now=NOW,
            rules=rules,
        )
        self.assertTrue(good.complete)
        self.assertTrue(
            can_retire_candidate(
                good,
                metadata_resolved=True,
                current_tree_resolved=True,
                current_tree_has_evidence=False,
            )
        )
        stale = assess_coverage_epoch(
            (
                certificate("sourcegraph", NOW - timedelta(days=8)),
                certificate("github-code-search", NOW - timedelta(days=20)),
            ),
            library_id="cublas",
            now=NOW,
            rules=rules,
        )
        self.assertEqual(stale.stale_sources, ("sourcegraph",))
        self.assertFalse(
            can_retire_candidate(
                stale,
                metadata_resolved=True,
                current_tree_resolved=True,
                current_tree_has_evidence=False,
            )
        )

    def test_composite_quarantines_all_lanes_when_one_source_is_incomplete(self):
        good_certificate = certificate("sourcegraph", NOW)
        bad_certificate = certificate("github-code-search", NOW, complete=False)
        good = type("Result", (), {})()
        good.certificate = good_certificate
        good.observations = (observation("acme/good", source="sourcegraph"),)
        good.quarantined_observations = ()
        bad = type("Result", (), {})()
        bad.certificate = bad_certificate
        bad.observations = ()
        bad.quarantined_observations = (
            observation("acme/partial", source="github-code-search"),
        )
        combined = combine_discovery_results(
            (),
            (good, bad),
            required_sources=("sourcegraph", "github-code-search"),
        )
        self.assertFalse(combined.complete)
        self.assertEqual(combined.observations, ())
        self.assertEqual(
            {item.repo_full_name for item in combined.quarantined_observations},
            {"acme/good", "acme/partial"},
        )
        with self.assertRaises(IncompleteCoverageError):
            combined.require_complete()

    def test_incomplete_advisory_lane_cannot_contaminate_required_results(self):
        github = type("Result", (), {})()
        github.certificate = certificate("github-code-search", NOW)
        github.observations = (
            observation("acme/authority", source="github-code-search"),
        )
        github.quarantined_observations = ()
        sourcegraph = type("Result", (), {})()
        sourcegraph.certificate = certificate(
            "sourcegraph", NOW, complete=False
        )
        sourcegraph.observations = ()
        sourcegraph.quarantined_observations = (
            observation("acme/partial", source="sourcegraph"),
        )
        combined = combine_discovery_results(
            (),
            (sourcegraph, github),
            required_sources=("github-code-search",),
            advisory_sources=("sourcegraph",),
        )
        self.assertTrue(combined.complete)
        self.assertEqual(
            ("acme/authority",),
            tuple(
                item.repo_full_name
                for item in combined.require_complete()
            ),
        )
        self.assertEqual(combined.quarantined_observations, ())
        self.assertEqual(2, len(combined.certificates))


class SourcegraphTests(unittest.TestCase):
    def test_expired_deadline_makes_incomplete_certificate_without_transport(self):
        calls = []
        result = SourcegraphDiscovery(
            lambda _query: calls.append(_query),
            monotonic=lambda: 10.0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query='"cublas_v2.h"',
            deadline_monotonic=9.0,
        )
        self.assertEqual(calls, [])
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "deadline_exhausted",
            {gap.code for gap in result.certificate.gaps},
        )

    @staticmethod
    def clock():
        values = iter((NOW, NOW + timedelta(seconds=2)))
        return lambda: next(values)

    def test_complete_stream_retains_path_commit_and_source_lag(self):
        captured: list[str] = []
        stream = """
event: matches
data: [{"type":"content","repository":"github.com/acme/tool","path":"src/use.cu","commit":"abc123","repoLastFetched":"2026-07-27T11:55:00Z"}]

event: progress
data: {"done":true,"matchCount":1,"repositoriesCount":1,"durationMs":42,"skipped":[{"reason":"excluded-forks"},{"reason":"excluded-archives"}]}

event: done
data: {}

"""

        def transport(query):
            captured.append(query)
            return stream

        result = SourcegraphDiscovery(
            transport, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query='content:"#include <cublas_v2.h>"',
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(len(result.require_complete()), 1)
        item = result.observations[0]
        self.assertEqual(item.repo_full_name, "acme/tool")
        self.assertEqual(item.matched_path, "src/use.cu")
        self.assertEqual(item.matched_commit, "abc123")
        self.assertEqual(item.source_lag_seconds, 300)
        self.assertIn("patternType:keyword", captured[0])
        self.assertIn(r"repo:^github\.com/", captured[0])
        self.assertIn("visibility:public", captured[0])
        self.assertIn("select:file", captured[0])
        self.assertIn("count:50000", captured[0])
        self.assertIn("timeout:1m", captured[0])
        self.assertIn("fork:no", captured[0])
        self.assertIn("archived:no", captured[0])
        self.assertEqual(
            result.certificate.intentional_skips,
            ("excluded-archives", "excluded-forks"),
        )
        self.assertEqual(result.certificate.to_dict()["source"], "sourcegraph")

    def test_numeric_result_ceiling_is_an_incomplete_certificate(self):
        stream = """
event: progress
data: {"done":true,"matchCount":50000,"repositoriesCount":42}

event: done
data: {}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "result_limit_reached",
            {gap.code for gap in result.certificate.gaps},
        )

    def test_server_timeout_boundary_is_incomplete_even_without_skip(self):
        stream = """
event: progress
data: {"done":true,"matchCount":2,"repositoriesCount":2,"durationMs":60012}

event: done
data: {}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="dali",
            signal_id="import",
            query='"import nvidia.dali"',
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "server_timeout_boundary",
            {gap.code for gap in result.certificate.gaps},
        )

    def test_count_all_is_rejected_as_an_unsafe_live_policy(self):
        stream = """
event: progress
data: {"done":true,"matchCount":0,"repositoriesCount":0}

event: done
data: {}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h count:all",
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "unsafe_count_policy",
            {gap.code for gap in result.certificate.gaps},
        )

    def test_missing_done_quarantines_otherwise_valid_matches(self):
        stream = """
event: matches
data: [{"repository":"github.com/acme/tool","path":"src/use.cu","commit":"abc123"}]

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        self.assertFalse(result.certificate.complete)
        self.assertEqual(result.observations, ())
        self.assertEqual(len(result.quarantined_observations), 1)
        self.assertIn(
            "missing_terminal_done",
            {gap.code for gap in result.certificate.gaps},
        )
        with self.assertRaises(IncompleteCoverageError):
            result.require_complete()

    def test_unexpected_skip_and_nonterminal_done_are_incomplete(self):
        stream = """
event: progress
data: {"done":true,"skipped":[{"reason":"shard-timeout"}]}

event: done
data: {}

event: filters
data: []

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        codes = {gap.code for gap in result.certificate.gaps}
        self.assertIn("unexpected_skip", codes)
        self.assertIn("nonterminal_done", codes)
        self.assertFalse(result.certificate.complete)

    def test_malformed_match_quarantines_stream(self):
        stream = """
event: matches
data: [{"repository":"github.com/acme/tool","path":"src/use.cu"}]

event: progress
data: {"done":true}

event: done
data: {}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        self.assertIn(
            "malformed_match", {gap.code for gap in result.certificate.gaps}
        )
        self.assertFalse(result.certificate.complete)

    def test_progress_done_without_final_done_is_incomplete(self):
        stream = """
event: progress
data: {"done":true}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        codes = {gap.code for gap in result.certificate.gaps}
        self.assertIn("missing_terminal_done", codes)
        self.assertFalse(result.certificate.complete)

    def test_final_done_without_progress_done_is_incomplete(self):
        stream = """
event: done
data: {}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        codes = {gap.code for gap in result.certificate.gaps}
        self.assertIn("missing_progress_done", codes)
        self.assertFalse(result.certificate.complete)

    def test_final_done_requires_empty_object_payload(self):
        stream = """
event: progress
data: {"done":true}

event: done
data: {"unexpected":true}

"""
        result = SourcegraphDiscovery(
            lambda _query: stream, clock=self.clock()
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
        )
        codes = {gap.code for gap in result.certificate.gaps}
        self.assertIn("malformed_terminal_done", codes)
        self.assertFalse(result.certificate.complete)

    def test_sse_parser_rejects_unnamed_event(self):
        with self.assertRaises(ValueError):
            parse_sse("data: {}\n\n")


class GitHubSearchTests(unittest.TestCase):
    def test_expired_deadline_makes_incomplete_certificate_without_transport(self):
        calls = []
        result = GitHubCodeSearch(
            lambda **kwargs: calls.append(kwargs),
            min_interval=0,
            monotonic=lambda: 10.0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query='"cublas_v2.h"',
            deadline_monotonic=9.0,
        )
        self.assertEqual(calls, [])
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "deadline_exhausted",
            {gap.code for gap in result.certificate.gaps},
        )

    def test_single_page_requires_explicit_public_visibility(self):
        calls: list[tuple[str, int]] = []
        payload = search_payload(
            3,
            [
                public_item("acme/public", "a.cu", "a"),
                public_item("secret/repo", "b.cu", "b", private=True),
                public_item("unknown/repo", "c.cu", "c", private=None),
            ],
        )

        def transport(*, query, page, per_page):
            calls.append((query, page))
            self.assertEqual(per_page, 4)
            return payload

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=4,
            result_cap=10,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="cublas_v2.h",
            extensions=("cu",),
        )
        self.assertFalse(result.certificate.complete)
        self.assertEqual(
            result.observations,
            (),
        )
        self.assertEqual(
            result.certificate.metrics["excluded_non_public_or_unverified"], 1
        )
        self.assertEqual(
            result.certificate.metrics["excluded_explicit_private"], 1
        )
        self.assertIn(
            "unverified_visibility",
            {gap.code for gap in result.certificate.gaps},
        )
        self.assertEqual([page for _query, page in calls], [1])

    def test_member_query_decomposition_unions_complete_logical_pack(self):
        calls = []
        responses = {
            '"import warp"': search_payload(
                1,
                [public_item("acme/importer", "use.py", "a")],
            ),
            '"from warp"': search_payload(
                1,
                [public_item("acme/from-user", "other.py", "b")],
            ),
        }

        def transport(*, query, page, per_page):
            calls.append((query, page, per_page))
            return responses[query]

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=10,
            result_cap=10,
        ).search(
            library_id="warp",
            signal_id="import-pack-00",
            query='"import warp" OR "from warp"',
            member_queries=('"import warp"', '"from warp"'),
            member_signal_ids=("import-00-import", "import-00-from"),
        )

        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {item.repo_full_name for item in result.require_complete()},
            {"acme/importer", "acme/from-user"},
        )
        self.assertEqual(
            [query for query, _page, _per_page in calls],
            ['"import warp"', '"from warp"'],
        )
        self.assertNotIn(
            '"import warp" OR "from warp"',
            [query for query, _page, _per_page in calls],
        )
        self.assertEqual(
            {
                partition.key.split(";", 1)[0]
                for partition in result.certificate.partitions
            },
            {
                "member=import-00-import",
                "member=import-00-from",
            },
        )
        self.assertEqual(
            result.certificate.metrics["execution_query_count"], 2
        )
        self.assertTrue(
            result.certificate.metrics["logical_query_decomposed"]
        )

    def test_incomplete_member_quarantines_the_entire_logical_pack(self):
        responses = {
            '"import warp"': search_payload(
                1,
                [public_item("acme/importer", "use.py", "a")],
            ),
            '"from warp"': search_payload(0, [], incomplete=True),
        }

        result = GitHubCodeSearch(
            lambda *, query, page, per_page: responses[query],
            min_interval=0,
            per_page=10,
            result_cap=10,
        ).search(
            library_id="warp",
            signal_id="import-pack-00",
            query='"import warp" OR "from warp"',
            member_queries=('"import warp"', '"from warp"'),
            member_signal_ids=("import-00-import", "import-00-from"),
        )

        self.assertFalse(result.certificate.complete)
        self.assertEqual(result.observations, ())
        self.assertEqual(
            {item.repo_full_name for item in result.quarantined_observations},
            {"acme/importer"},
        )
        self.assertIn(
            "incomplete_results",
            {gap.code for gap in result.certificate.gaps},
        )

    def test_member_query_decomposition_must_exactly_match_logical_pack(self):
        calls = []
        with self.assertRaisesRegex(ValueError, "exactly decompose"):
            GitHubCodeSearch(
                lambda **kwargs: calls.append(kwargs),
                min_interval=0,
            ).search(
                library_id="warp",
                signal_id="import-pack-00",
                query='"import warp" OR "from warp"',
                member_queries=('"import warp"',),
                member_signal_ids=("import-00-import",),
            )
        self.assertEqual(calls, [])

    def test_recursively_splits_capped_extension_by_nonoverlapping_sizes(self):
        calls: list[str] = []
        responses = {
            "TOKEN": search_payload(
                4,
                [
                    public_item("ignored/base", "parent.cu", "p"),
                    public_item("ignored/base2", "parent2.cu", "q"),
                ],
            ),
            "TOKEN extension:cu": search_payload(
                4,
                [
                    public_item("ignored/parent", "parent.cu", "p"),
                    public_item("ignored/parent2", "parent2.cu", "q"),
                ],
            ),
            "TOKEN extension:cu size:0..1": search_payload(
                2,
                [
                    public_item("acme/one", "one.cu", "1"),
                    public_item("acme/two", "two.cu", "2"),
                ],
            ),
            "TOKEN extension:cu size:2..3": search_payload(
                1, [public_item("acme/three", "three.cu", "3")]
            ),
        }

        def transport(*, query, page, per_page):
            calls.append(query)
            self.assertEqual(page, 1)
            return responses[query]

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=3,
            result_cap=3,
            max_file_size=3,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
            extensions=("cu",),
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {item.repo_full_name for item in result.observations},
            {"acme/one", "acme/two", "acme/three"},
        )
        self.assertEqual(calls, list(responses))
        self.assertTrue(result.certificate.partitions[0].capped)

    def test_uncapped_base_avoids_extension_fanout_and_filters_file_class(self):
        calls = []

        def transport(*, query, page, per_page):
            calls.append(query)
            return search_payload(
                2,
                [
                    public_item("acme/code", "src/use.cu", "1"),
                    public_item("acme/docs", "README.md", "2"),
                ],
            )

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
        ).search(
            library_id="cublas",
            signal_id="header-pack-00",
            query='"cublas.h" OR "cublas_v2.h"',
            extensions=("cu", "cpp", "h"),
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            ["acme/code"],
            [item.repo_full_name for item in result.observations],
        )
        self.assertEqual(
            ['"cublas.h" OR "cublas_v2.h"'],
            calls,
        )
        self.assertEqual(1, result.certificate.metrics["request_count"])
        self.assertEqual(
            1,
            result.certificate.metrics[
                "excluded_outside_declared_extensions"
            ],
        )

    def test_unsplittable_single_page_leaf_fails_epoch(self):
        result = GitHubCodeSearch(
            lambda **_kwargs: search_payload(
                2, [public_item("acme/one", "one.cu", "1")]
            ),
            min_interval=0,
            per_page=1,
            result_cap=1,
            max_file_size=0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "unsplittable_page", {gap.code for gap in result.certificate.gaps}
        )

    def test_exact_size_leaf_accepts_only_after_explicit_empty_page(self):
        calls = []
        pages = {
            1: search_payload(
                3,
                [
                    public_item("acme/one", "same.lock", "1"),
                    public_item("acme/two", "same.lock", "2"),
                ],
            ),
            2: search_payload(
                3,
                [public_item("acme/three", "same.lock", "3")],
            ),
            3: search_payload(3, []),
        }

        def transport(*, query, page, per_page):
            calls.append((query, page))
            return pages[page]

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=2,
            result_cap=10,
            max_file_size=0,
        ).search(
            library_id="nvpl",
            signal_id="broad",
            query='"nvpl"',
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {"acme/one", "acme/two", "acme/three"},
            {item.repo_full_name for item in result.observations},
        )
        self.assertEqual(
            [('"nvpl"', 1), ('"nvpl"', 2), ('"nvpl"', 3)],
            calls,
        )
        leaf = result.certificate.partitions[-1]
        self.assertEqual(3, leaf.page_count)
        self.assertEqual(3, leaf.fetched_count)
        self.assertEqual(1, result.certificate.metrics["paginated_leaf_count"])
        self.assertEqual(
            2, result.certificate.metrics["pagination_request_count"]
        )

    def test_exact_size_leaf_retries_a_whole_inconsistent_page_walk(self):
        calls = []
        first = public_item("acme/one", "same.lock", "1")
        second = public_item("acme/two", "same.lock", "2")
        third = public_item("acme/three", "same.lock", "3")
        sweep = 0

        def transport(*, query, page, per_page):
            nonlocal sweep
            calls.append((query, page))
            if page == 1:
                sweep += 1
                return search_payload(3, [first, second])
            if page == 2:
                return search_payload(
                    3, [second] if sweep == 1 else [third]
                )
            return search_payload(3, [])

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=2,
            result_cap=10,
            max_file_size=0,
        ).search(
            library_id="nvpl",
            signal_id="header-prefix",
            query='"nvpl_"',
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {"acme/one", "acme/two", "acme/three"},
            {item.repo_full_name for item in result.observations},
        )
        self.assertEqual(
            [
                ('"nvpl_"', 1),
                ('"nvpl_"', 2),
                ('"nvpl_"', 3),
                ('"nvpl_"', 1),
                ('"nvpl_"', 2),
                ('"nvpl_"', 3),
            ],
            calls,
        )
        self.assertEqual(
            2, result.certificate.metrics["pagination_sweep_count"]
        )
        self.assertEqual(
            1, result.certificate.metrics["pagination_retry_count"]
        )

    def test_exact_size_pagination_rejects_duplicate_hidden_remainder(self):
        duplicate = public_item("acme/one", "same.lock", "1")

        def transport(*, query, page, per_page):
            if "path:" in query or "-path:" in query:
                return search_payload(3, [duplicate, duplicate])
            if page == 1:
                return search_payload(3, [duplicate, duplicate])
            return search_payload(3, [])

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=2,
            result_cap=4,
            max_file_size=0,
            max_path_splits=2,
        ).search(
            library_id="nvpl",
            signal_id="broad",
            query='"nvpl"',
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "unsplittable_page",
            {gap.code for gap in result.certificate.gaps},
        )
        self.assertGreaterEqual(
            result.certificate.metrics["pagination_fallback_count"], 1
        )

    def test_incomplete_response_quarantines_epoch(self):
        result = GitHubCodeSearch(
            lambda **_kwargs: search_payload(
                1,
                [public_item("acme/one", "one.cu", "1")],
                incomplete=True,
            ),
            min_interval=0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "incomplete_results", {gap.code for gap in result.certificate.gaps}
        )
        self.assertEqual(result.observations, ())

    def test_short_page_with_reported_hidden_remainder_fails_if_unsplittable(self):
        result = GitHubCodeSearch(
            lambda **_kwargs: search_payload(
                2,
                [
                    public_item("acme/one", "one.cu", "1"),
                ],
            ),
            min_interval=0,
            max_file_size=0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertIn(
            "unsplittable_page",
            {gap.code for gap in result.certificate.gaps},
        )
        self.assertFalse(result.certificate.complete)

    def test_short_terminal_page_accepts_underreported_count(self):
        result = GitHubCodeSearch(
            lambda **_kwargs: search_payload(
                1,
                [
                    public_item("acme/one", "one.cu", "1"),
                    public_item("acme/two", "two.cu", "2"),
                ],
            ),
            min_interval=0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(2, len(result.observations))
        self.assertEqual(
            1,
            result.certificate.metrics["reported_count_mismatches"],
        )

    def test_short_page_with_next_link_is_not_accepted(self):
        result = GitHubCodeSearch(
            lambda **_kwargs: (
                search_payload(
                    1,
                    [public_item("acme/one", "one.cu", "1")],
                ),
                {
                    "Link": (
                        '<https://api.github.com/search/code?page=2>; '
                        'rel="next"'
                    )
                },
            ),
            min_interval=0,
            max_file_size=0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertFalse(result.certificate.complete)
        self.assertIn(
            "unsplittable_page",
            {gap.code for gap in result.certificate.gaps},
        )

    def test_multi_page_query_is_partitioned_before_acceptance(self):
        calls: list[tuple[str, int]] = []
        responses = {
            "TOKEN": search_payload(
                4,
                [
                    public_item("ignored/base", "base.cu", "a"),
                    public_item("ignored/base2", "base2.cu", "b"),
                ],
            ),
            "TOKEN size:0..0": search_payload(
                2,
                [
                    public_item("acme/one", "one.cu", "1"),
                    public_item("acme/two", "two.cu", "2"),
                ],
            ),
            "TOKEN size:1..1": search_payload(
                1,
                [public_item("acme/three", "three.cu", "3")],
            ),
        }

        def transport(*, query, page, per_page):
            calls.append((query, page))
            self.assertEqual(per_page, 3)
            return responses[query]

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=3,
            result_cap=10,
            max_file_size=1,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {item.repo_full_name for item in result.observations},
            {"acme/one", "acme/two", "acme/three"},
        )
        self.assertEqual(
            [
                ("TOKEN", 1),
                ("TOKEN size:0..0", 1),
                ("TOKEN size:1..1", 1),
            ],
            calls,
        )

    def test_exact_size_tie_uses_complementary_path_partitions(self):
        calls: list[tuple[str, int]] = []
        responses = {
            "TOKEN": search_payload(
                4,
                [
                    public_item("ignored/base", "vendor/a.cu", "a"),
                    public_item("ignored/base2", "src/b.cu", "b"),
                ],
            ),
            'TOKEN path:"a.cu"': search_payload(
                1,
                [public_item("acme/one", "vendor/a.cu", "1")],
            ),
            'TOKEN -path:"a.cu"': search_payload(
                2,
                [
                    public_item("acme/two", "src/b.cu", "2"),
                    public_item("acme/three", "other/c.cu", "3"),
                ],
            ),
        }

        def transport(*, query, page, per_page):
            calls.append((query, page))
            self.assertEqual(per_page, 3)
            return responses[query]

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=3,
            result_cap=10,
            max_file_size=0,
        ).search(
            library_id="cublas",
            signal_id="header",
            query="TOKEN",
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {item.repo_full_name for item in result.observations},
            {"acme/one", "acme/two", "acme/three"},
        )
        self.assertEqual(
            [
                *(("TOKEN", page)
                  for _sweep in range(3)
                  for page in (1, 2, 3)),
                ('TOKEN path:"a.cu"', 1),
                ('TOKEN -path:"a.cu"', 1),
            ],
            calls,
        )

    def test_exact_size_tie_peels_repeated_repository_membership(self):
        calls: list[tuple[str, int]] = []
        responses = {
            "TOKEN": search_payload(
                4,
                [
                    public_item("acme/many", "a.cu", "a"),
                    public_item("acme/many", "b.cu", "b"),
                    public_item("acme/many", "c.cu", "c"),
                ],
            ),
            "TOKEN -repo:acme/many": search_payload(
                1,
                [public_item("acme/other", "d.cu", "d")],
            ),
        }

        def transport(*, query, page, per_page):
            calls.append((query, page))
            self.assertEqual(per_page, 3)
            return responses[query]

        result = GitHubCodeSearch(
            transport,
            min_interval=0,
            per_page=3,
            result_cap=10,
            max_file_size=0,
        ).search(
            library_id="dali",
            signal_id="broad",
            query="TOKEN",
        )
        self.assertTrue(result.certificate.complete)
        self.assertEqual(
            {item.repo_full_name for item in result.observations},
            {"acme/many", "acme/other"},
        )
        self.assertEqual(
            [
                *(("TOKEN", page)
                  for _sweep in range(3)
                  for page in (1, 2, 3)),
                ("TOKEN -repo:acme/many", 1),
            ],
            calls,
        )


class GraphQLClientTests(unittest.TestCase):
    def test_expired_deadline_stops_before_transport(self):
        calls = []
        client = GitHubGraphQLClient(
            lambda **kwargs: calls.append(kwargs),
            min_interval=0,
            monotonic=lambda: 10.0,
        )
        with self.assertRaisesRegex(GitHubBudgetError, "deadline"):
            client.resolve(
                names=("public/project",),
                deadline_monotonic=9.0,
            )
        self.assertEqual(calls, [])

    def test_display_metadata_survives_batched_resolution(self):
        payload = graphql_repo("public/project")
        payload.update({
            "diskUsage": 1234,
            "description": "A public CUDA project",
            "stargazerCount": 42,
            "forkCount": 7,
            "primaryLanguage": {"name": "CUDA"},
            "createdAt": "2020-01-01T00:00:00Z",
            "pushedAt": "2026-07-27T00:00:00Z",
        })
        result = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response({"r0": payload}),
            min_interval=0,
        ).resolve(names=("public/project",))
        repo = result.repositories[0]
        self.assertEqual(repo.disk_usage_kb, 1234)
        self.assertEqual(repo.stars, 42)
        self.assertEqual(repo.forks, 7)
        self.assertEqual(repo.language, "CUDA")
        self.assertEqual(repo.to_dict()["display"]["description"], payload["description"])

    def test_batches_ids_and_names_and_returns_explicit_repository_state(self):
        captured: list[tuple[str, dict]] = []

        def transport(*, query, variables):
            captured.append((query, variables))
            return graphql_response(
                {
                    "r0": graphql_repo("new/project", node_id="R_1"),
                    "r1": graphql_repo(
                        "new/name",
                        node_id="R_2",
                        fork=True,
                        archived=False,
                        branch="trunk",
                        head="c" * 40,
                    ),
                }
            )

        result = GitHubGraphQLClient(
            transport,
            batch_size=2,
            min_interval=0,
        ).resolve(
            node_ids=("R_1",),
            names=("old/name",),
        )
        self.assertEqual(result.request_count, 1)
        self.assertEqual(result.points_used, 1)
        first, second = result.repositories
        self.assertTrue(first.explicitly_public)
        self.assertTrue(first.publishable)
        self.assertEqual(first.default_branch, "main")
        self.assertEqual(first.head_oid, "b" * 40)
        self.assertTrue(second.renamed)
        self.assertEqual(second.full_name, "new/name")
        self.assertEqual(second.default_branch, "trunk")
        self.assertFalse(second.publishable)
        self.assertIn("node(id:", captured[0][0])
        self.assertIn("repository(owner:", captured[0][0])
        self.assertIn("rateLimit", captured[0][0])
        self.assertIn("__typename", captured[0][0])
        self.assertNotIn("repositoryTopics", captured[0][0])
        self.assertNotIn("licenseInfo", captured[0][0])
        self.assertNotIn("owner { __typename }", captured[0][0])

    def test_node_id_lookup_can_carry_prior_name_for_rename_detection(self):
        client = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {"r0": graphql_repo("new/name", node_id="R_1")}
            ),
            min_interval=0,
        )
        result = client.resolve(
            lookups=(RepositoryLookup(node_id="R_1", full_name="old/name"),)
        )
        self.assertTrue(result.repositories[0].renamed)
        self.assertEqual(result.repositories[0].requested_full_name, "old/name")
        self.assertEqual(result.repositories[0].full_name, "new/name")

    def test_private_and_missing_visibility_never_become_publishable(self):
        def transport(**_kwargs):
            return graphql_response(
                {
                    "r0": graphql_repo(
                        "secret/repo", visibility="PRIVATE", private=True
                    ),
                    "r1": graphql_repo(
                        "unknown/repo", visibility=None, private=None
                    ),
                }
            )

        result = GitHubGraphQLClient(
            transport, batch_size=2, min_interval=0
        ).resolve(names=("secret/repo", "unknown/repo"))
        private, unknown = result.repositories
        self.assertEqual(private.status, "private")
        self.assertFalse(private.publishable)
        self.assertEqual(unknown.status, "unverified_visibility")
        self.assertFalse(unknown.explicitly_public)
        self.assertFalse(unknown.publishable)
        self.assertFalse(result.complete)

    def test_empty_rest_fallback_contract_makes_no_normal_request(self):
        metadata = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {"r0": graphql_repo("public/project")}
            ),
            min_interval=0,
        ).resolve(names=("public/project",)).repositories[0]

        def forbidden(**_kwargs):
            raise AssertionError("REST must not be called for complete GraphQL")

        self.assertEqual(REST_FALLBACK_FIELDS, ())
        result = GitHubRESTFallbackClient(forbidden).resolve(metadata)
        self.assertEqual(result.status, "not_required")
        self.assertEqual(result.request_count, 0)
        self.assertEqual(result.fields, {})

    def test_rest_fallback_uses_fresh_and_conditional_cached_values(self):
        metadata = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {"r0": graphql_repo("public/project")}
            ),
            min_interval=0,
        ).resolve(names=("public/project",)).repositories[0]
        responses = iter(
            (
                (
                    200,
                    {"homepage": "https://example.test/project"},
                    {"ETag": '"v1"'},
                ),
                (304, None, {"ETag": '"v1"'}),
            )
        )
        calls = []

        def transport(**kwargs):
            calls.append(kwargs)
            return next(responses)

        fallback = GitHubRESTFallbackClient(
            transport, fields=("homepage",)
        )
        fresh = fallback.resolve(metadata)
        cached = fallback.resolve(
            metadata,
            etag=fresh.etag,
            cached_fields=fresh.fields,
        )

        self.assertEqual(fresh.status, "updated")
        self.assertEqual(
            fresh.fields, {"homepage": "https://example.test/project"}
        )
        self.assertEqual(cached.status, "not_modified")
        self.assertEqual(cached.fields, fresh.fields)
        self.assertEqual(calls[1]["etag"], '"v1"')

    def test_rest_fallback_never_probes_non_public_graphql_results(self):
        result = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {
                    "r0": graphql_repo(
                        "secret/repo",
                        visibility="PRIVATE",
                        private=True,
                    ),
                    "r1": graphql_repo(
                        "unknown/repo",
                        visibility=None,
                        private=None,
                    ),
                }
            ),
            batch_size=2,
            min_interval=0,
        ).resolve(names=("secret/repo", "unknown/repo"))
        calls = []
        fallback = GitHubRESTFallbackClient(
            lambda **kwargs: calls.append(kwargs),
            fields=("homepage",),
        )

        for metadata in result.repositories:
            with self.subTest(status=metadata.status):
                with self.assertRaisesRegex(
                    GitHubGraphQLError, "explicitly public"
                ):
                    fallback.resolve(metadata)
        self.assertEqual(calls, [])

    def test_partial_errors_are_bound_to_the_affected_lookup(self):
        def transport(**_kwargs):
            return graphql_response(
                {
                    "r0": graphql_repo("acme/good", node_id="R_1"),
                    "r1": graphql_repo("acme/partial", node_id="R_2"),
                },
                errors=[
                    {
                        "message": "branch lookup failed",
                        "path": ["r1", "defaultBranchRef"],
                        "extensions": {"type": "SERVICE_UNAVAILABLE"},
                    }
                ],
            )

        result = GitHubGraphQLClient(
            transport, batch_size=2, min_interval=0
        ).resolve(names=("acme/good", "acme/partial"))
        self.assertEqual(result.repositories[0].status, "ok")
        self.assertEqual(result.repositories[1].status, "partial_error")
        self.assertEqual(result.errors[0].request_key, "name:acme/partial")
        self.assertFalse(result.complete)

    def test_alias_not_found_is_terminal_missing_not_partial_error(self):
        result = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {"r0": None},
                errors=[{
                    "message": (
                        "Could not resolve to a Repository with the "
                        "name 'gone/repo'."
                    ),
                    "path": ["r0"],
                    "type": "NOT_FOUND",
                }],
            ),
            batch_size=1,
            min_interval=0,
        ).resolve(names=("gone/repo",))
        self.assertTrue(result.complete)
        self.assertEqual((), result.errors)
        self.assertEqual("missing", result.repositories[0].status)
        self.assertIsNone(result.repositories[0].visibility)
        self.assertFalse(result.repositories[0].publishable)

    def test_429_honors_retry_after(self):
        responses = iter(
            (
                (429, {}, {"Retry-After": "3"}),
                graphql_response({"r0": graphql_repo("acme/good")}),
            )
        )
        sleeps: list[float] = []
        client = GitHubGraphQLClient(
            lambda **_kwargs: next(responses),
            min_interval=0,
            sleep=sleeps.append,
        )
        result = client.resolve(names=("acme/good",))
        self.assertEqual(result.request_count, 1)
        self.assertIn(3.0, sleeps)

    def test_remaining_floor_stops_before_next_batch(self):
        calls = 0

        def transport(**_kwargs):
            nonlocal calls
            calls += 1
            return graphql_response(
                {"r0": graphql_repo("acme/%d" % calls)},
                remaining=2_500,
            )

        client = GitHubGraphQLClient(
            transport,
            batch_size=1,
            minimum_remaining=2_500,
            min_interval=0,
        )
        with self.assertRaises(GitHubBudgetError):
            client.resolve(names=("acme/one", "acme/two"))
        self.assertEqual(calls, 1)

    def test_point_cost_ceiling_fails_closed(self):
        client = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {"r0": graphql_repo("acme/good")}, cost=101
            ),
            maximum_points_per_batch=100,
            min_interval=0,
        )
        with self.assertRaises(GitHubBudgetError):
            client.resolve(names=("acme/good",))
        self.assertEqual(client.points_spent, 101)

    def test_point_budget_is_cumulative_across_resolve_calls(self):
        client = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {"r0": graphql_repo("acme/good")}, cost=1
            ),
            point_budget=1,
            minimum_remaining=0,
            maximum_points_per_batch=1,
            min_interval=0,
        )
        client.resolve(names=("acme/one",))
        with self.assertRaises(GitHubBudgetError):
            client.resolve(names=("acme/two",))
        self.assertEqual(client.points_spent, 1)

    def test_restored_same_run_budget_prevents_replay_overspend(self):
        calls = []
        client = GitHubGraphQLClient(
            lambda **kwargs: calls.append(kwargs),
            point_budget=1,
            minimum_remaining=0,
            maximum_points_per_batch=1,
            min_interval=0,
        )
        client.restore_run_budget(
            points_spent=1,
            remaining=4_999,
            reset_at="2026-07-27T17:00:00Z",
        )
        with self.assertRaises(GitHubBudgetError):
            client.resolve(names=("acme/two",))
        self.assertEqual([], calls)
        self.assertEqual(1, client.points_spent)
        self.assertEqual(4_999, client.remaining)

    def test_empty_and_missing_repositories_are_explicit(self):
        result = GitHubGraphQLClient(
            lambda **_kwargs: graphql_response(
                {
                    "r0": graphql_repo("acme/empty", branch=None),
                    "r1": None,
                }
            ),
            batch_size=2,
            min_interval=0,
        ).resolve(
            lookups=(
                RepositoryLookup(full_name="acme/empty"),
                RepositoryLookup(full_name="acme/gone"),
            )
        )
        self.assertEqual(result.repositories[0].status, "empty")
        self.assertIsNone(result.repositories[0].head_oid)
        self.assertEqual(result.repositories[1].status, "missing")
        self.assertFalse(result.repositories[1].publishable)

    def test_malformed_or_option_like_head_oid_fails_closed(self):
        for oid in ("--upload-pack=malicious", "not-a-commit", "a" * 39):
            raw = graphql_repo("acme/public")
            raw["defaultBranchRef"]["target"]["oid"] = oid
            result = GitHubGraphQLClient(
                lambda **_kwargs: graphql_response({"r0": raw}),
                min_interval=0,
            ).resolve(names=("acme/public",))
            repository = result.repositories[0]
            self.assertEqual(repository.status, "partial_error")
            self.assertIsNone(repository.head_oid)
            self.assertFalse(repository.publishable)


if __name__ == "__main__":
    unittest.main(verbosity=2)
