"""Fixture-only tests for the REQ-14 citation cache pipeline."""

from __future__ import annotations

import datetime
import io
import json
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from collector import citation_extract as citations
from collector import config, openalex_api
from collector.catalog import (
    REQ14_CITATION_METADATA,
    REQ14_DIRECT_LIBRARY_CANDIDATES,
)
from collector.citation_pipeline import (
    CitationPipeline,
    CitationQueryResult,
    OpenAlexCitationSource,
    RepositoryCFF,
    citation_query_fingerprint,
    parse_cff_references,
)
from collector.state import StateDB


NOW = datetime.datetime(2026, 7, 27, 12, 0, tzinfo=datetime.timezone.utc)


def work(work_id, title, doi, cited=1, repository_urls=()):
    return {
        "id": "https://openalex.org/" + work_id,
        "title": title,
        "doi": "https://doi.org/" + doi,
        "type": "article",
        "publication_year": 2025,
        "publication_date": "2025-05-01",
        "cited_by_count": cited,
        "authorships": [],
        "primary_location": {"source": {"display_name": "Fixture Journal"}},
        "open_access": {"oa_url": "https://example.test/paper"},
        "repository_urls": list(repository_urls),
    }


LIBRARIES = (
    {
        "id": "cublas",
        "name": "cuBLAS",
        "citation_query": '"cuBLAS"',
        "citation_tier": "A",
        "citation_confidence": "high",
        "released_on": "2007-06",
    },
    {
        "id": "cudnn",
        "name": "cuDNN",
        "citation_query": '"cuDNN"',
        "citation_tier": "A",
        "citation_confidence": "high",
        "released_on": "2014-07",
    },
)


class FixtureSource:
    name = "FixtureAlex"

    def __init__(self, results, resolutions=None, extractions=None):
        self.results = results
        self.resolutions = resolutions or {}
        self.extractions = extractions
        self.query_calls = []
        self.resolve_calls = []
        self.extract_calls = []

    def query(self, library, query_fp, max_works):
        self.query_calls.append((library["id"], query_fp, max_works))
        result = self.results[library["id"]]
        if isinstance(result, Exception):
            raise result
        return result

    def resolve_reference(self, reference):
        self.resolve_calls.append(reference)
        result = self.resolutions.get(reference)
        if isinstance(result, Exception):
            raise result
        return result

    def extract_repository_urls(self, citation_work):
        self.extract_calls.append(citation_work["id"])
        if self.extractions is None:
            return ()
        result = self.extractions.get(citation_work["id"], ())
        if isinstance(result, Exception):
            raise result
        return result


def fingerprints(char):
    return {
        "discovery": char * 64,
        "detector": char * 64,
        "citation": char * 64,
        "dating": char * 64,
        "aggregation": char * 64,
        "presentation": char * 64,
        "release": char * 64,
    }


def seed(db):
    for index, library in enumerate(LIBRARIES):
        db.upsert_library(
            library["id"],
            catalog={"name": library["name"]},
            fingerprints=fingerprints(chr(ord("a") + index)),
        )
    db.upsert_repository(
        {
            "node_id": "R1",
            "full_name": "acme/research",
            "visibility": "PUBLIC",
            "default_branch": "main",
            "head_sha": "H1",
        }
    )


class CitationPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state = StateDB(Path(self.temporary.name) / "state.sqlite3")
        seed(self.state)
        self.cff = (
            RepositoryCFF(
                repository_id="R1",
                full_name="acme/research",
                head_sha="H1",
                text=(
                    "cff-version: 1.2.0\n"
                    "doi: 10.1234/shared.paper\n"
                    "identifiers:\n  - value: arXiv: 2401.01234v2\n"
                ),
            ),
        )
        self.confirmed = {
            "cublas": ("R1",),
            "cudnn": ("acme/research",),
        }

    def tearDown(self):
        self.state.close()
        self.temporary.cleanup()

    def test_openalex_query_collects_exact_seven_calendar_day_count(self):
        source = OpenAlexCitationSource(clock=lambda: NOW)
        counts = [10, 2, 4, 3, 7, 6]
        with (
            mock.patch.object(openalex_api, "count", side_effect=counts) as count,
            mock.patch.object(
                openalex_api,
                "works",
                return_value=([work("W1", "cuBLAS", "10.1234/cublas")], 10, False),
            ),
        ):
            result = source.query(LIBRARIES[0], "fixture", 400)

        self.assertEqual(2, result.new_7d)
        base_filters = count.call_args_list[0].args[0]
        self.assertIn("from_publication_date:2007-06-01", base_filters)
        seven_day_filters = count.call_args_list[1].args[0]
        self.assertIn("from_publication_date:2026-07-21", seven_day_filters)
        self.assertIn("to_publication_date:2026-07-27", seven_day_filters)
        self.assertEqual(
            1,
            sum(value.startswith("from_publication_date:") for value in seven_day_filters),
        )

    def test_pre_release_query_and_cff_works_are_rejected(self):
        old_query = work("W0", "Impossible cuBLAS paper", "10.1234/old")
        old_query["publication_year"] = 1935
        old_query["publication_date"] = "1935-01-01"
        current = work("W1", "Current cuBLAS paper", "10.1234/current")
        old_cff = work("W2", "Old CFF paper", "10.1234/shared.paper")
        old_cff["publication_year"] = 1999
        old_cff["publication_date"] = "1999-01-01"
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(old_query, current),
                    total=2,
                    complete=True,
                    as_of="2026-07-27T11:00:00Z",
                )
            },
            {"10.1234/shared.paper": old_cff},
        )
        result = CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            (LIBRARIES[0],),
            repository_cff=self.cff,
            confirmed_repositories={"cublas": ("R1",)},
            force=True,
        )
        papers = result.document["libraries"]["cublas"]["papers"]
        self.assertEqual(["Current cuBLAS paper"], [paper["title"] for paper in papers])

    def test_local_cff_is_parsed_once_per_head_and_resolved_once(self):
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(work("W1", "cuBLAS Study", "10.1234/cublas"),),
                    total=1,
                    complete=True,
                    as_of="2026-07-27T11:00:00Z",
                    new_7d=1,
                ),
                "cudnn": CitationQueryResult(
                    works=(work("W2", "cuDNN Study", "10.1234/cudnn"),),
                    total=1,
                    complete=True,
                    capped=True,
                    as_of="2026-07-27T11:00:00Z",
                    errors=("result cap reached",),
                ),
            },
            {
                "10.1234/shared.paper": work(
                    "W3", "Shared CFF Paper", "10.1234/shared.paper", cited=9
                ),
                "10.48550/arxiv.2401.01234": work(
                    "W4", "arXiv CFF Paper", "10.48550/arxiv.2401.01234"
                ),
            },
        )
        result = CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            LIBRARIES,
            repository_cff=self.cff,
            confirmed_repositories=self.confirmed,
        )

        self.assertTrue(result.publishable)
        self.assertFalse(result.all_failed)
        self.assertEqual(1, result.metrics["cff_parses"])
        self.assertEqual(1, result.metrics["cff_heads"])
        # Each reference is resolved globally once, not once per library.
        self.assertEqual(
            ["10.1234/shared.paper", "10.48550/arxiv.2401.01234"],
            sorted(source.resolve_calls),
        )
        for library_id in ("cublas", "cudnn"):
            papers = result.document["libraries"][library_id]["papers"]
            self.assertTrue(any(row["repo"] == "acme/research" for row in papers))
            self.assertEqual(
                "2026-07-27T11:00:00Z",
                result.document["libraries"][library_id]["as_of"],
            )
        self.assertEqual(1, result.document["libraries"]["cublas"]["new_7d"])
        cudnn = result.document["libraries"]["cudnn"]
        self.assertTrue(cudnn["papers_capped"])
        self.assertEqual(["result cap reached"], cudnn["errors"])
        self.assertGreater(
            self.state.connection.execute(
                "SELECT COUNT(*) FROM citation_cache"
            ).fetchone()[0],
            2,
        )

    def test_one_paper_preserves_every_confirmed_adopter_relation(self):
        self.state.upsert_repository(
            {
                "node_id": "R2",
                "full_name": "acme/second",
                "visibility": "PUBLIC",
                "default_branch": "main",
                "head_sha": "H2",
            }
        )
        cff = self.cff + (
            RepositoryCFF(
                repository_id="R2",
                full_name="acme/second",
                head_sha="H2",
                text="cff-version: 1.2.0\ndoi: 10.1234/shared.paper\n",
            ),
        )
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(),
                    total=0,
                    complete=True,
                    as_of="2026-07-27T11:00:00Z",
                ),
                "cudnn": CitationQueryResult(
                    works=(),
                    total=0,
                    complete=True,
                    as_of="2026-07-27T11:00:00Z",
                ),
            },
            {
                "10.1234/shared.paper": work(
                    "W3", "Shared CFF Paper", "10.1234/shared.paper"
                )
            },
        )
        result = CitationPipeline(
            self.state, source, clock=lambda: NOW
        ).refresh(
            LIBRARIES,
            repository_cff=cff,
            confirmed_repositories={
                "cublas": ("R1", "R2"),
                "cudnn": (),
            },
        )
        record = result.document["libraries"]["cublas"]
        shared = next(
            row
            for row in record["papers"]
            if row["doi"] == "10.1234/shared.paper"
        )
        self.assertEqual(
            shared["repos"], ["acme/research", "acme/second"]
        )
        self.assertEqual(
            set(record["repo_papers"]),
            {"acme/research", "acme/second"},
        )

    def test_no_change_refresh_is_cache_dominant_and_never_calls_source(self):
        initial = FixtureSource(
            {
                library["id"]: CitationQueryResult(
                    works=(work("W-" + library["id"], library["name"], "10.1234/" + library["id"]),),
                    total=1,
                    complete=True,
                    as_of="2026-07-27T11:00:00Z",
                )
                for library in LIBRARIES
            }
        )
        first = CitationPipeline(self.state, initial, clock=lambda: NOW)
        first.refresh(
            LIBRARIES,
            repository_cff=self.cff,
            confirmed_repositories=self.confirmed,
        )

        fail_if_called = FixtureSource(
            {library["id"]: AssertionError("source must not be called") for library in LIBRARIES}
        )
        second = CitationPipeline(
            self.state,
            fail_if_called,
            clock=lambda: NOW + datetime.timedelta(hours=1),
        ).refresh(
            LIBRARIES,
            confirmed_repositories=self.confirmed,
        )
        self.assertEqual([], fail_if_called.query_calls)
        self.assertEqual(2, second.metrics["query_cache_hits"])
        self.assertGreaterEqual(second.metrics["work_cache_hits"], 2)
        self.assertEqual(1, second.metrics["cff_cache_hits"])
        self.assertEqual(0, second.metrics["cff_parses"])

    def test_crash_after_completed_library_resumes_from_durable_query_cache(self):
        class CrashAfterFirst(FixtureSource):
            def query(self, library, query_fp, max_works):
                if library["id"] == "cudnn":
                    self.query_calls.append(
                        (library["id"], query_fp, max_works)
                    )
                    raise KeyboardInterrupt("synthetic process loss")
                return super().query(library, query_fp, max_works)

        crashing = CrashAfterFirst(
            {
                "cublas": CitationQueryResult(
                    works=(
                        work(
                            "W-cublas",
                            "cuBLAS",
                            "10.1234/cublas",
                        ),
                    ),
                    total=1,
                    complete=True,
                ),
                "cudnn": CitationQueryResult(works=(), total=0),
            }
        )
        with self.assertRaisesRegex(
            KeyboardInterrupt, "synthetic process loss"
        ):
            CitationPipeline(
                self.state, crashing, clock=lambda: NOW
            ).refresh(LIBRARIES)
        self.assertEqual(
            ["cublas", "cudnn"],
            [call[0] for call in crashing.query_calls],
        )

        resumed_source = FixtureSource(
            {
                "cublas": AssertionError(
                    "completed library query must be reused"
                ),
                "cudnn": CitationQueryResult(
                    works=(
                        work(
                            "W-cudnn",
                            "cuDNN",
                            "10.1234/cudnn",
                        ),
                    ),
                    total=1,
                    complete=True,
                ),
            }
        )
        resumed = CitationPipeline(
            self.state,
            resumed_source,
            clock=lambda: NOW + datetime.timedelta(minutes=1),
        ).refresh(LIBRARIES)
        self.assertEqual(
            ["cudnn"],
            [call[0] for call in resumed_source.query_calls],
        )
        self.assertEqual(1, resumed.metrics["query_cache_hits"])
        self.assertEqual(
            {"cublas", "cudnn"},
            set(resumed.document["libraries"]),
        )

    def test_unchanged_payload_is_a_cache_hit_and_changed_payload_replaces(self):
        first_work = work("W1", "Stable", "10.1234/stable", cited=1)
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(works=(first_work,), total=1),
                "cudnn": CitationQueryResult(works=(), total=0),
            }
        )
        pipeline = CitationPipeline(self.state, source, clock=lambda: NOW)
        pipeline.refresh(LIBRARIES, force=True)
        unchanged = pipeline.refresh(LIBRARIES, force=True)
        self.assertGreaterEqual(unchanged.metrics["work_cache_hits"], 1)
        self.assertEqual(0, unchanged.metrics["work_cache_writes"])

        source.results["cublas"] = CitationQueryResult(
            works=(work("W1", "Stable", "10.1234/stable", cited=12),),
            total=1,
        )
        changed = pipeline.refresh(LIBRARIES, force=True)
        self.assertEqual(1, changed.metrics["work_cache_writes"])
        cached = self.state.connection.execute(
            """
            SELECT payload_json FROM citation_cache
            WHERE library_id='cublas' AND work_id='W1'
            """
        ).fetchone()[0]
        self.assertIn('"cited_by_count":12', cached)

    def test_local_cff_change_relinks_cached_work_without_query_call(self):
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(work("W1", "Linked Later", "10.1234/linked"),),
                    total=1,
                    complete=True,
                ),
                "cudnn": CitationQueryResult(works=(), total=0, complete=True),
            }
        )
        CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            LIBRARIES, confirmed_repositories=self.confirmed
        )
        fail_if_called = FixtureSource(
            {library["id"]: AssertionError("query must be cached") for library in LIBRARIES}
        )
        changed_cff = (
            RepositoryCFF(
                repository_id="R1",
                full_name="acme/research",
                head_sha="H1",
                text="doi: 10.1234/linked\n",
            ),
        )
        result = CitationPipeline(
            self.state,
            fail_if_called,
            clock=lambda: NOW + datetime.timedelta(hours=1),
        ).refresh(
            LIBRARIES,
            repository_cff=changed_cff,
            confirmed_repositories=self.confirmed,
        )
        self.assertEqual([], fail_if_called.query_calls)
        linked = result.document["libraries"]["cublas"]["papers"][0]
        self.assertEqual("acme/research", linked["repo"])
        self.assertEqual(2, result.metrics["query_cache_hits"])

    def test_repository_url_extraction_is_cached_by_work_payload(self):
        paper = work("W1", "Source Link", "10.1234/source-link")
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(works=(paper,), total=1),
                "cudnn": CitationQueryResult(works=(), total=0),
            },
            extractions={
                "https://openalex.org/W1": ("https://github.com/acme/research",)
            },
        )
        pipeline = CitationPipeline(self.state, source, clock=lambda: NOW)
        first = pipeline.refresh(
            LIBRARIES,
            repository_cff=self.cff,
            confirmed_repositories=self.confirmed,
            force=True,
        )
        self.assertEqual(["https://openalex.org/W1"], source.extract_calls)
        self.assertEqual(
            "acme/research",
            first.document["libraries"]["cublas"]["papers"][0]["repo"],
        )
        source.extract_calls.clear()
        second = pipeline.refresh(
            LIBRARIES,
            repository_cff=self.cff,
            confirmed_repositories=self.confirmed,
            force=True,
        )
        self.assertEqual([], source.extract_calls)
        self.assertGreaterEqual(second.metrics["source_extract_cache_hits"], 1)

    def test_structured_source_extraction_fallback_semantics(self):
        paper = work("W1", "Fallbacks", "10.1234/fallbacks")
        paper["ids"] = {"arxiv": "https://arxiv.org/abs/2607.00001"}

        with (
            mock.patch.object(
                citations,
                "_fetch",
                side_effect=[RuntimeError("arxiv offline"), b"pdf"],
            ),
            mock.patch.object(
                citations,
                "_repos_from_pdf",
                return_value={"acme/research"},
            ),
        ):
            result = citations.extract_repo_urls(paper)
        self.assertEqual("complete", result.status)
        self.assertTrue(result.source_available)
        self.assertEqual(("arxiv", "pdf"), result.attempted_sources)
        self.assertEqual(("pdf",), result.successful_sources)
        self.assertEqual(("acme/research",), result.urls)
        self.assertEqual(1, len(result.errors))

        with (
            mock.patch.object(
                citations,
                "_fetch",
                side_effect=[b"source", b"pdf"],
            ),
            mock.patch.object(
                citations,
                "_repos_from_tar",
                return_value=set(),
            ),
            mock.patch.object(
                citations,
                "_repos_from_pdf",
                side_effect=ValueError("PDF parse failed"),
            ),
        ):
            result = citations.extract_repo_urls(paper)
        self.assertEqual("complete", result.status)
        self.assertEqual(("arxiv", "pdf"), result.attempted_sources)
        self.assertEqual(("arxiv",), result.successful_sources)
        self.assertEqual(1, len(result.errors))

        with mock.patch.object(
            citations,
            "_fetch",
            side_effect=[
                RuntimeError("arxiv offline"),
                RuntimeError("pdf offline"),
            ],
        ):
            result = citations.extract_repo_urls(paper)
        self.assertEqual("failed", result.status)
        self.assertTrue(result.source_available)
        self.assertEqual(2, len(result.errors))
        self.assertEqual((), result.successful_sources)

        no_source = dict(paper)
        no_source["ids"] = {}
        no_source["open_access"] = {}
        no_source["primary_location"] = {}
        result = citations.extract_repo_urls(no_source)
        self.assertEqual("not_available", result.status)
        self.assertFalse(result.source_available)
        self.assertEqual((), result.attempted_sources)
        self.assertEqual((), result.errors)

    def test_failed_structured_extraction_is_stale_redacted_and_retried(self):
        paper = work("W1", "Retry Source", "10.1234/retry-source")
        secret = "source-extraction-secret"
        failed = citations.RepositoryURLExtraction(
            urls=(),
            attempted_sources=("arxiv",),
            successful_sources=(),
            errors=("api_key=" + secret,),
            status="failed",
            source_available=True,
        )
        succeeded = citations.RepositoryURLExtraction(
            urls=("https://github.com/acme/research",),
            attempted_sources=("pdf",),
            successful_sources=("pdf",),
            errors=(),
            status="complete",
            source_available=True,
        )
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(paper,), total=1, complete=True
                )
            },
            extractions={"https://openalex.org/W1": failed},
        )
        pipeline = CitationPipeline(self.state, source, clock=lambda: NOW)
        first = pipeline.refresh(
            (LIBRARIES[0],),
            confirmed_repositories={"cublas": ("acme/research",)},
            force=True,
        )
        coverage = first.document["libraries"]["cublas"]["coverage"]
        self.assertFalse(coverage["complete"])
        self.assertTrue(coverage["stale"])
        self.assertFalse(coverage["local_enrichment_complete"])
        serialized = (
            json.dumps(first.document)
            + self.state.checkpoint_bytes().decode()
        )
        self.assertNotIn(secret, serialized)

        source.extractions["https://openalex.org/W1"] = succeeded
        source.extract_calls.clear()
        second = pipeline.refresh(
            (LIBRARIES[0],),
            confirmed_repositories={"cublas": ("acme/research",)},
            force=True,
        )
        self.assertEqual(
            ["https://openalex.org/W1"], source.extract_calls
        )
        self.assertTrue(
            second.document["libraries"]["cublas"]["coverage"]["complete"]
        )
        self.assertEqual(
            "acme/research",
            second.document["libraries"]["cublas"]["papers"][0]["repo"],
        )

        source.extract_calls.clear()
        third = pipeline.refresh(
            (LIBRARIES[0],),
            confirmed_repositories={"cublas": ("acme/research",)},
            force=True,
        )
        self.assertEqual([], source.extract_calls)
        self.assertEqual(1, third.metrics["source_extract_cache_hits"])
        cached_sources = json.loads(
            self.state.connection.execute(
                """
                SELECT source_json FROM citation_cache
                WHERE library_id='cublas' AND work_id='W1'
                """
            ).fetchone()[0]
        )
        self.assertEqual("complete", cached_sources["extraction_status"])
        self.assertTrue(cached_sources["source_available"])

    def test_not_available_structured_extraction_is_non_staling(self):
        paper = work("W1", "No Public Source", "10.1234/no-public-source")
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(paper,), total=1, complete=True
                )
            },
            extractions={
                "https://openalex.org/W1": (
                    citations.RepositoryURLExtraction(
                        urls=(),
                        attempted_sources=(),
                        successful_sources=(),
                        errors=(),
                        status="not_available",
                        source_available=False,
                    )
                )
            },
        )
        result = CitationPipeline(
            self.state, source, clock=lambda: NOW
        ).refresh((LIBRARIES[0],), force=True)
        coverage = result.document["libraries"]["cublas"]["coverage"]
        self.assertTrue(coverage["complete"])
        self.assertFalse(coverage["stale"])
        self.assertFalse(coverage["source_available"])
        self.assertEqual(1, coverage["source_unavailable_count"])

    def test_query_change_failure_carries_prior_fingerprint_last_good(self):
        good = FixtureSource(
            {
                library["id"]: CitationQueryResult(
                    works=(
                        work(
                            "W-" + library["id"],
                            library["name"],
                            "10.1234/" + library["id"],
                        ),
                    ),
                    total=1,
                )
                for library in LIBRARIES
            }
        )
        CitationPipeline(self.state, good, clock=lambda: NOW).refresh(LIBRARIES)
        changed = tuple(
            {
                **library,
                "citation_query": library["citation_query"] + ' AND "API"',
            }
            for library in LIBRARIES
        )
        failing = FixtureSource(
            {library["id"]: RuntimeError("new query failed") for library in changed}
        )
        result = CitationPipeline(
            self.state,
            failing,
            clock=lambda: NOW + datetime.timedelta(days=1),
        ).refresh(changed, force=True)
        self.assertTrue(result.used_last_good)
        self.assertTrue(result.all_failed)
        self.assertEqual({"cublas", "cudnn"}, set(result.document["libraries"]))

    def test_unadmitted_repository_cff_and_links_fail_closed(self):
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(
                        work(
                            "W-private",
                            "Private Link",
                            "10.1234/private",
                            repository_urls=("https://github.com/secret/private",),
                        ),
                    ),
                    total=1,
                ),
                "cudnn": CitationQueryResult(works=(), total=0),
            }
        )
        result = CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            LIBRARIES,
            repository_cff=(
                RepositoryCFF(
                    repository_id="R-private",
                    full_name="secret/private",
                    head_sha="H-private",
                    text="doi: 10.1234/private",
                ),
            ),
            confirmed_repositories={"cublas": ("secret/private",)},
        )
        paper = result.document["libraries"]["cublas"]["papers"][0]
        self.assertIsNone(paper["repo"])
        self.assertEqual(1, result.metrics["cff_state_rejections"])
        self.assertNotIn("secret/private", str(result.document))
        self.assertNotIn("secret/private", self.state.checkpoint_bytes().decode())

    def test_all_failed_refresh_carries_last_good_with_explicit_quality(self):
        good_source = FixtureSource(
            {
                library["id"]: CitationQueryResult(
                    works=(work("W-" + library["id"], library["name"], "10.1234/" + library["id"]),),
                    total=1,
                    complete=True,
                    as_of="2026-07-20T00:00:00Z",
                )
                for library in LIBRARIES
            }
        )
        CitationPipeline(self.state, good_source, clock=lambda: NOW).refresh(LIBRARIES)
        failing = FixtureSource(
            {library["id"]: RuntimeError("OpenAlex unavailable") for library in LIBRARIES}
        )
        result = CitationPipeline(
            self.state,
            failing,
            clock=lambda: NOW + datetime.timedelta(days=7),
        ).refresh(LIBRARIES, force=True)

        self.assertTrue(result.publishable)
        self.assertTrue(result.all_failed)
        self.assertTrue(result.used_last_good)
        self.assertEqual({"cublas", "cudnn"}, set(result.document["libraries"]))
        for record in result.document["libraries"].values():
            self.assertTrue(record["stale"])
            self.assertTrue(record["coverage"]["carried_forward"])
            self.assertIn("OpenAlex unavailable", record["errors"][0])

    def test_all_failed_without_prior_is_not_publishable(self):
        source = FixtureSource(
            {library["id"]: RuntimeError("offline") for library in LIBRARIES}
        )
        result = CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            LIBRARIES, force=True
        )
        self.assertFalse(result.publishable)
        self.assertTrue(result.all_failed)
        self.assertFalse(result.used_last_good)
        self.assertEqual({}, result.document["libraries"])
        self.assertEqual({"cublas", "cudnn"}, set(result.document["errors"]))
        self.assertTrue(result.document["stale"])

    def test_fingerprint_ignores_display_name_but_changes_with_query(self):
        base = dict(LIBRARIES[0])
        renamed = {**base, "name": "Renamed cuBLAS"}
        changed = {**base, "citation_query": '"cuBLAS API"'}
        changed_release = {**base, "released_on": "2008-01"}
        self.assertEqual(
            citation_query_fingerprint(base), citation_query_fingerprint(renamed)
        )
        self.assertNotEqual(
            citation_query_fingerprint(base), citation_query_fingerprint(changed)
        )
        self.assertNotEqual(
            citation_query_fingerprint(base),
            citation_query_fingerprint(changed_release),
        )

    def test_cff_parser_normalizes_doi_and_arxiv(self):
        self.assertEqual(
            (
                "10.1234/example",
                "10.48550/arxiv.2401.01234",
            ),
            parse_cff_references(
                "doi: https://doi.org/10.1234/Example.\n"
                "repository-code: https://arxiv.org/abs/2401.01234v3\n"
            ),
        )

    def test_capped_query_uses_source_total_as_labeled_headline(self):
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(work("W1", "One displayed paper", "10.1234/one"),),
                    total=137,
                    complete=False,
                    capped=True,
                    errors=("result cap reached",),
                )
            }
        )
        result = CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            (LIBRARIES[0],), force=True
        )
        record = result.document["libraries"]["cublas"]
        self.assertEqual(137, record["total"])
        self.assertEqual(1, record["displayed_papers_count"])
        self.assertEqual(1, len(record["papers"]))
        self.assertTrue(record["monthly_capped"])
        self.assertEqual(
            "source_total", record["coverage"]["headline_total_basis"]
        )

    def test_request_and_source_extraction_budgets_are_hard(self):
        source = FixtureSource(
            {
                "cublas": CitationQueryResult(
                    works=(work("W1", "Budgeted", "10.1234/budgeted"),),
                    total=1,
                ),
                "cudnn": CitationQueryResult(works=(), total=0),
            }
        )
        result = CitationPipeline(self.state, source, clock=lambda: NOW).refresh(
            LIBRARIES,
            max_openalex_requests=1,
            max_source_extractions=0,
            force=True,
        )
        self.assertEqual(["cublas"], [call[0] for call in source.query_calls])
        self.assertEqual([], source.extract_calls)
        self.assertEqual(1, result.metrics["openalex_requests"])
        self.assertEqual(1, result.metrics["source_extract_budget_skips"])
        self.assertIn("cudnn", result.document["errors"])
        cublas_coverage = result.document["libraries"]["cublas"]["coverage"]
        self.assertTrue(cublas_coverage["source_extraction_budget_exhausted"])
        self.assertEqual(
            {"used": 1, "limit": 1},
            result.document["budget"]["openalex_requests"],
        )

    def test_openalex_http_budget_counts_retries_before_network(self):
        budget = openalex_api.RequestBudget(2)
        error = __import__("urllib.error").error.URLError("offline")
        with (
            mock.patch(
                "collector.openalex_api.urllib.request.urlopen",
                side_effect=error,
            ) as request,
            mock.patch("collector.openalex_api.time.sleep"),
        ):
            with self.assertRaises(openalex_api.RequestBudgetExceeded):
                openalex_api._get("/works", {}, retries=4, budget=budget)
        self.assertEqual(2, budget.used)
        self.assertEqual(2, request.call_count)

    def test_openalex_errors_cannot_echo_keys_or_query_urls(self):
        secret = "openalex-secret-value"
        echoed_url = (
            "https://api.openalex.org/works?filter=cuDNN"
            "&api_key=" + secret
        )
        http_error = urllib.error.HTTPError(
            echoed_url,
            400,
            "bad request",
            {},
            io.BytesIO(("failed URL " + echoed_url).encode()),
        )
        with (
            mock.patch.object(openalex_api, "_KEY", secret),
            mock.patch.object(openalex_api, "_MIN_INTERVAL", 0),
            mock.patch(
                "collector.openalex_api.urllib.request.urlopen",
                side_effect=http_error,
            ),
        ):
            result = openalex_api._get("/works", {}, retries=1)
        encoded = json.dumps(result)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("filter=cuDNN", encoded)
        self.assertIn("[REDACTED", encoded)

        network_error = urllib.error.URLError(
            "Bearer " + secret + " requesting " + echoed_url
        )
        with (
            mock.patch.object(openalex_api, "_KEY", secret),
            mock.patch.object(openalex_api, "_MIN_INTERVAL", 0),
            mock.patch(
                "collector.openalex_api.urllib.request.urlopen",
                side_effect=network_error,
            ),
        ):
            result = openalex_api._get("/works", {}, retries=1)
        encoded = json.dumps(result)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("filter=cuDNN", encoded)

    def test_citation_source_exceptions_are_redacted_before_state(self):
        secret = "citation-secret-value"
        source = FixtureSource(
            {
                "cublas": RuntimeError(
                    "api_key=" + secret
                    + " https://api.openalex.org/works?api_key="
                    + secret
                )
            }
        )
        result = CitationPipeline(
            self.state, source, clock=lambda: NOW
        ).refresh((LIBRARIES[0],), force=True)
        serialized = (
            json.dumps(result.document)
            + self.state.checkpoint_bytes().decode()
        )
        self.assertNotIn(secret, serialized)
        self.assertNotIn("api.openalex.org/works?", serialized)

    def test_openalex_absolute_deadline_bounds_open_and_body_read(self):
        class Response:
            def __init__(self):
                self.calls = 0
                self.closed = False

            def read(self, _size):
                self.calls += 1
                if self.calls > 1 or self.closed:
                    return b""
                time.sleep(0.158)
                return b"{}"

            def close(self):
                self.closed = True

        scenarios = {
            "open": lambda _request, *, timeout: (
                time.sleep(0.158) or Response()
            ),
            "body": lambda _request, *, timeout: Response(),
        }
        for phase, opener in scenarios.items():
            with self.subTest(phase=phase), mock.patch.object(
                openalex_api, "_MIN_INTERVAL", 0
            ), mock.patch(
                "collector.openalex_api.urllib.request.urlopen",
                side_effect=opener,
            ):
                budget = openalex_api.RequestBudget(
                    1, deadline_monotonic=time.monotonic() + 0.020
                )
                started = time.monotonic()
                with self.assertRaisesRegex(
                    openalex_api.RequestBudgetExceeded, "deadline"
                ):
                    openalex_api._get(
                        "/works", {}, retries=1, budget=budget
                    )
                self.assertLess(time.monotonic() - started, 0.100)

    def test_openalex_absolute_attempt_timeout_preserves_retries(self):
        attempts = []
        real_sleep = time.sleep

        def blocking_open(_request, *, timeout):
            attempts.append(timeout)
            real_sleep(0.030)
            raise urllib.error.URLError("offline")

        with mock.patch.object(
            openalex_api, "_MIN_INTERVAL", 0
        ), mock.patch.object(
            openalex_api, "REQUEST_TIMEOUT_SECONDS", 0.010
        ), mock.patch(
            "collector.openalex_api.urllib.request.urlopen",
            side_effect=blocking_open,
        ), mock.patch(
            "collector.openalex_api.time.sleep"
        ):
            result = openalex_api._get("/works", {}, retries=2)
        self.assertEqual(result["_http_error"], "network")
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(timeout == 0.010 for timeout in attempts))

    def test_citation_absolute_deadline_bounds_dns_connect_and_reads(self):
        parsed_target = (
            urllib.parse.urlsplit("http://example.com/paper"),
            80,
            ("93.184.216.34",),
        )

        def public_answer(*_args, **_kwargs):
            time.sleep(0.158)
            return [
                (
                    __import__("socket").AF_INET,
                    __import__("socket").SOCK_STREAM,
                    6,
                    "",
                    ("93.184.216.34", 80),
                )
            ]

        started = time.monotonic()
        with mock.patch(
            "collector.citation_extract.socket.getaddrinfo",
            side_effect=public_answer,
        ):
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                citations._fetch(
                    "http://example.com/paper",
                    deadline_monotonic=time.monotonic() + 0.020,
                )
        self.assertLess(time.monotonic() - started, 0.100)

        class Response:
            status = 200
            headers = {}

            def __init__(self, delay, chunks):
                self.delay = delay
                self.chunks = chunks
                self.closed = False

            def read(self, _size):
                if self.closed or self.chunks <= 0:
                    return b""
                time.sleep(self.delay)
                self.chunks -= 1
                return b"x"

            def close(self):
                self.closed = True

        class Connection:
            sock = None

            def __init__(self, response, request_delay=0):
                self.response = response
                self.request_delay = request_delay

            def request(self, *_args, **_kwargs):
                time.sleep(self.request_delay)

            def getresponse(self):
                return self.response

            def close(self):
                self.response.close()

        scenarios = {
            "connect": Connection(Response(0, 0), request_delay=0.158),
            "body": Connection(Response(0.158, 1)),
            "slow-drip": Connection(Response(0.012, 20)),
        }
        for phase, connection in scenarios.items():
            with self.subTest(phase=phase), mock.patch.object(
                citations,
                "_validated_public_target",
                return_value=parsed_target,
            ), mock.patch(
                "collector.citation_extract.http.client.HTTPConnection",
                return_value=connection,
            ):
                started = time.monotonic()
                with self.assertRaisesRegex(TimeoutError, "deadline"):
                    citations._fetch(
                        "http://example.com/paper",
                        deadline_monotonic=time.monotonic() + 0.020,
                    )
                self.assertLess(time.monotonic() - started, 0.100)

    def test_citation_source_fetch_rejects_local_urls_and_oversized_body(self):
        for url in (
            "file:///etc/passwd",
            "http://127.0.0.1/private",
            "http://[::1]/private",
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "public|non-public"):
                    citations._validate_public_http_url(url)

        class Response:
            status = 200
            headers = {"Content-Length": "11"}

            def read(self, _size):
                return b""

        connection = mock.Mock()
        connection.getresponse.return_value = Response()
        connection.sock = None
        with (
            mock.patch.object(
                citations,
                "_validated_public_target",
                return_value=(
                    urllib.parse.urlsplit(
                        "http://example.com/paper.pdf"
                    ),
                    80,
                    ("93.184.216.34",),
                ),
            ),
            mock.patch(
                "collector.citation_extract.http.client.HTTPConnection",
                return_value=connection,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "byte limit"):
                citations._fetch(
                    "http://example.com/paper.pdf",
                    max_bytes=10,
                )

    def test_citation_fetch_pins_validated_ip_and_revalidates_redirect(self):
        class Response:
            status = 200
            headers = {}

            def read(self, _size):
                return b""

        connection = mock.Mock()
        connection.getresponse.return_value = Response()
        connection.sock = None
        answers = [
            [
                (
                    __import__("socket").AF_INET,
                    __import__("socket").SOCK_STREAM,
                    6,
                    "",
                    ("93.184.216.34", 80),
                )
            ],
            [
                (
                    __import__("socket").AF_INET,
                    __import__("socket").SOCK_STREAM,
                    6,
                    "",
                    ("127.0.0.1", 80),
                )
            ],
        ]
        with (
            mock.patch(
                "collector.citation_extract.socket.getaddrinfo",
                side_effect=answers,
            ) as resolver,
            mock.patch(
                "collector.citation_extract.http.client.HTTPConnection",
                return_value=connection,
            ) as constructor,
        ):
            self.assertEqual(
                citations._fetch("http://example.com/paper"),
                b"",
            )
        self.assertEqual(resolver.call_count, 1)
        constructor.assert_called_once_with(
            "93.184.216.34", port=80, timeout=30.0
        )

        redirect = mock.Mock()
        redirect.status = 302
        redirect.headers = {}
        redirect.getheader.return_value = "http://127.0.0.1/private"
        first = mock.Mock()
        first.getresponse.return_value = redirect
        with (
            mock.patch.object(
                citations,
                "_validated_public_target",
                side_effect=[
                    (
                        urllib.parse.urlsplit("http://example.com/start"),
                        80,
                        ("93.184.216.34",),
                    ),
                    ValueError("source URL resolves to a non-public address"),
                ],
            ),
            mock.patch(
                "collector.citation_extract.http.client.HTTPConnection",
                return_value=first,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "non-public"):
                citations._fetch("http://example.com/start")

    def test_citation_source_tar_expansion_limit(self):
        class Member:
            isfile = lambda self: True
            name = "paper.tex"
            size = citations.MAX_TAR_UNCOMPRESSED_BYTES + 1

        archive = mock.MagicMock()
        archive.__enter__.return_value = archive
        archive.getmembers.return_value = [Member()]
        with mock.patch(
            "collector.citation_extract.tarfile.open",
            return_value=archive,
        ):
            with self.assertRaisesRegex(ValueError, "expansion limit"):
                citations._repos_from_tar(b"fixture")

    def test_every_direct_and_active_onboarded_library_has_citation_metadata(self):
        direct_ids = {
            library["id"]
            for library in REQ14_DIRECT_LIBRARY_CANDIDATES
        }
        self.assertEqual(direct_ids, set(REQ14_CITATION_METADATA))
        for library in REQ14_DIRECT_LIBRARY_CANDIDATES:
            self.assertTrue(library.get("citation_query"), library["id"])
            self.assertIn(library.get("citation_tier"), {"A", "B", "C"})
            self.assertIn(
                library.get("citation_confidence"), {"high", "medium"}
            )
        for library_id in ("cupqc", "ovrtx"):
            library = next(
                item for item in config.LIBRARIES if item["id"] == library_id
            )
            self.assertTrue(library.get("citation_query"))
        amgx = next(
            library for library in config.LIBRARIES
            if library["id"] == "amgx"
        )
        self.assertEqual('"NVIDIA AmgX"', amgx["citation_query"])


if __name__ == "__main__":
    unittest.main()
