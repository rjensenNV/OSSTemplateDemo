"""REQ-14 versioned portfolio and parent-family rollup tests."""
from __future__ import annotations

import copy
import unittest

from collector.catalog import (
    CATALOG,
    CATALOG_BASELINE_2026_07_27_IDS,
    CATALOG_EVENTS,
    CATALOG_VERSION,
    OFFICIAL_CUDA_X,
    validate_catalog_history,
)
from collector.portfolio import (
    OFFICIAL_CATEGORY_COUNTS,
    PortfolioError,
    REQUESTED_COMPONENT_ROLLUPS,
    build_portfolio,
    derive_family_rollups,
    validate_portfolio_catalog,
)
from collector.nvpl_rollup import apply_nvpl_additive_rollup

def card(identifier, confirmed, bundled=0, targeted=0, **extra):
    value = {
        "id": identifier,
        "name": identifier,
        "confirmed_count": confirmed,
        "bundled_count": bundled,
        "targeted_count": targeted,
        "headline_count": confirmed,
        "classification_coverage": {
            "confirmed": "evaluated",
            "bundled": "evaluated",
            "targeted": "evaluated",
        },
    }
    value.update(extra)
    return value


def entry(identifier, classification="confirmed", date="2025-01-01", commit=None):
    return {
        "library_id": identifier,
        "classification": classification,
        "first_integration": date,
        "first_integration_commit": commit or (identifier + "-sha"),
        "operators": [identifier],
    }


def repo(name, *entries):
    return {
        "full_name": name,
        "html_url": "https://github.com/" + name,
        "libraries": list(entries),
    }


class PortfolioTests(unittest.TestCase):
    def test_nvpl_parent_is_the_additive_sum_of_component_metrics_and_history(self):
        parent = card(
            "nvpl", 1, bundled=2, targeted=3,
            collection_status="collected",
            released_on="2023-11",
            released_confidence="high",
        )
        children = [
            card(
                "nvpl-blas", 3, bundled=4, targeted=5,
                headline_count=7,
                parent_id="nvpl",
                is_component=True,
                component_label="BLAS",
                collection_status="collected",
            ),
            card(
                "nvpl-fft", 2, bundled=1, targeted=6,
                headline_count=3,
                parent_id="nvpl",
                is_component=True,
                component_label="FFT",
                collection_status="collected",
            ),
        ]
        timeseries = {
            "nvpl-blas": {
                "points": [
                    {"month": "2026-07", "confirmed": 3, "bundled": 4,
                     "targeted": 5, "cumulative_ai": 1}
                ]
            },
            "nvpl-fft": {
                "points": [
                    {"month": "2026-07", "confirmed": 2, "bundled": 1,
                     "targeted": 6, "cumulative_ai": 0}
                ]
            },
        }
        repositories = [
            repo(
                "public/nvpl-only-confirmed",
                {**entry("nvpl", date="2026-07-01"), "operators": []},
            ),
            repo(
                "public/nvpl-only-backend",
                {**entry("nvpl", "bundled", "2026-07-02"), "operators": []},
            ),
            repo(
                "public/nvpl-only-targeted",
                {**entry("nvpl", "targeted", "2026-07-03"), "operators": []},
            ),
        ]
        current = {
            "generated_at": "2026-08-03T00:00:00Z",
            "libraries": [parent, *children],
        }

        self.assertTrue(
            apply_nvpl_additive_rollup(current, timeseries, repositories)
        )
        self.assertEqual("additive", parent["component_rollup_mode"])
        self.assertEqual(
            "children_plus_unmapped_parent",
            parent["component_rollup_contract"],
        )
        self.assertEqual(["nvpl-blas", "nvpl-fft"], parent["component_ids"])
        self.assertEqual(
            {"confirmed": 1, "bundled": 1, "targeted": 1},
            parent["component_residual_counts"],
        )
        self.assertEqual(6, parent["confirmed_count"])
        self.assertEqual(6, parent["bundled_count"])
        self.assertEqual(12, parent["targeted_count"])
        self.assertEqual(12, parent["headline_count"])
        self.assertEqual(
            {"month": "2026-07", "confirmed": 6, "bundled": 6,
             "targeted": 12, "cumulative_ai": 1},
            timeseries["nvpl"]["points"][0],
        )
        self.assertEqual([24], parent["sparkline"])

    def test_versioned_49_entry_catalog_and_additive_invariants(self):
        self.assertTrue(validate_portfolio_catalog())
        self.assertEqual(49, len(OFFICIAL_CUDA_X))
        categories = {}
        for item in OFFICIAL_CUDA_X:
            categories[item["category"]] = categories.get(item["category"], 0) + 1
        self.assertEqual(OFFICIAL_CATEGORY_COUNTS, categories)
        by_id = {item["id"]: item for item in CATALOG}
        for component_id, parent_id in REQUESTED_COMPONENT_ROLLUPS.items():
            self.assertEqual("component", by_id[component_id]["kind"])
            self.assertEqual(parent_id, by_id[component_id]["rollup_to"])
        self.assertEqual("retained", by_id["nvpl"]["catalog_status"])
        self.assertEqual("retained", by_id["ovrtx"]["catalog_status"])
        self.assertEqual("preview", by_id["cusparsedx"]["catalog_status"])
        self.assertTrue(validate_catalog_history())
        self.assertEqual(len(CATALOG), len(CATALOG_EVENTS))
        self.assertEqual(
            {item["id"] for item in CATALOG},
            CATALOG_BASELINE_2026_07_27_IDS,
        )
        retained = {
            event["library_id"]: event
            for event in CATALOG_EVENTS
            if event["event"] == "retained"
        }
        self.assertEqual({"nvpl", "ovrtx"}, set(retained))
        self.assertTrue(
            all(event["effective_on"] is None for event in retained.values())
        )

        missing = copy.deepcopy(CATALOG[:-1])
        with self.assertRaisesRegex(
            PortfolioError, "cuSPARSEDx|required component|previously tracked"
        ):
            validate_portfolio_catalog(missing, OFFICIAL_CUDA_X)
        bad_official = copy.deepcopy(OFFICIAL_CUDA_X)
        bad_official[0]["category"] = "communication"
        with self.assertRaisesRegex(PortfolioError, "category census"):
            validate_portfolio_catalog(CATALOG, bad_official)

    def test_catalog_history_refuses_silent_deletion_and_accepts_terminal_event(self):
        reduced = [item for item in CATALOG if item["id"] != "ovrtx"]
        events = [
            event for event in CATALOG_EVENTS if event["library_id"] != "ovrtx"
        ]
        with self.assertRaisesRegex(ValueError, "disappeared without an event"):
            validate_catalog_history(
                reduced,
                events,
                previous_ids={item["id"] for item in CATALOG},
            )
        terminal = {
            **next(
                event
                for event in CATALOG_EVENTS
                if event["library_id"] == "ovrtx"
            ),
            "event": "disappeared",
            "catalog_status": "retired",
            "note": "Explicitly absent from the later source observation.",
        }
        self.assertTrue(
            validate_catalog_history(
                reduced,
                events + [terminal],
                previous_ids={item["id"] for item in CATALOG},
            )
        )

    def test_component_only_evidence_keeps_parent_unknown(self):
        repositories = [
            repo(
                "public/component-only",
                entry("cublasdx", date="2024-03-02", commit="dx-first"),
            )
        ]
        component_card = card(
            "cublasdx",
            1,
            sparkline=[0, 1],
            sparkline_months=["2024-02", "2024-03"],
        )
        output = build_portfolio([component_card], repositories)
        cards = {item["id"]: item for item in output["libraries"]}
        self.assertIsNone(cards["cublas"]["confirmed_count"])
        self.assertEqual("not_collected", cards["cublas"]["collection_status"])
        self.assertNotIn("family_rollup", cards["cublas"])
        self.assertEqual(1, cards["cublasdx"]["confirmed_count"])
        self.assertEqual([0, 1], cards["cublasdx"]["sparkline"])
        self.assertTrue(cards["cublasdx"]["is_component"])
        self.assertEqual("cublas", cards["cublasdx"]["parent_id"])
        self.assertEqual("cuBLASDx", cards["cublasdx"]["component_label"])
        self.assertFalse(cards["cublasdx"]["projected_from_parent"])
        self.assertEqual(repositories, output["repositories"])
        family = output["family_rollups"]["cublas"]
        self.assertEqual(1, len(family))
        self.assertFalse(family[0]["direct_parent_evidence"])
        self.assertEqual(["cublasdx"], family[0]["component_ids"])
        self.assertEqual("2024-03-02", family[0]["first_integration"])
        self.assertEqual("dx-first", family[0]["first_integration_commit"])

    def test_parent_and_component_same_repo_are_not_double_counted(self):
        repositories = [
            repo(
                "public/both",
                entry("cublas", date="2023-05-01", commit="parent-first"),
                entry("cublaslt", date="2024-01-01", commit="lt-later"),
            )
        ]
        output = build_portfolio(
            [card("cublas", 1), card("cublaslt", 1)], repositories
        )
        cards = {item["id"]: item for item in output["libraries"]}
        self.assertEqual(1, cards["cublas"]["confirmed_count"])
        self.assertNotIn("direct_confirmed_count", cards["cublas"])
        self.assertNotIn("family_coverage", cards["cublas"])
        family = output["family_rollups"]["cublas"]
        self.assertEqual(1, len(family))
        self.assertTrue(family[0]["direct_parent_evidence"])
        self.assertEqual(["cublaslt"], family[0]["component_ids"])
        self.assertEqual("2023-05-01", family[0]["first_integration"])
        self.assertEqual("parent-first", family[0]["first_integration_commit"])

    def test_multiple_components_roll_up_once_per_repository(self):
        repositories = [
            repo(
                "public/many-components",
                entry("cublasdx", date="2024-04-01"),
                entry("cublaslt", date="2023-09-01", commit="earliest"),
                entry("cublasxt", date="2024-02-01"),
            ),
            repo(
                "public/mp-only",
                entry("cublasmp", date="2025-01-01"),
            ),
        ]
        cards = [
            card("cublasdx", 1),
            card("cublaslt", 1),
            card("cublasxt", 1),
            card("cublasmp", 1),
        ]
        output = build_portfolio(cards, repositories)
        parent = next(item for item in output["libraries"] if item["id"] == "cublas")
        self.assertIsNone(parent["confirmed_count"])
        self.assertEqual("not_collected", parent["collection_status"])
        family = output["family_rollups"]["cublas"]
        self.assertEqual(
            ["cublasdx", "cublaslt", "cublasxt"],
            family[0]["component_ids"],
        )
        self.assertEqual("2023-09-01", family[0]["first_integration"])
        self.assertEqual("earliest", family[0]["first_integration_commit"])

    def test_portfolio_totals_count_unique_repositories_not_rows(self):
        repositories = [
            repo(
                "public/two-families",
                entry("cublasdx"),
                entry("cufftdx"),
            ),
            repo("public/second-blas", entry("cublaslt")),
            repo("public/target-only", entry("cufft", "targeted", None)),
        ]
        cards = [
            card("cublasdx", 1),
            card("cufftdx", 1),
            card("cublaslt", 1),
            card("cufft", 0, targeted=1),
        ]
        output = build_portfolio(cards, repositories)
        self.assertEqual(2, output["totals"]["confirmed_integrator_repos"])
        self.assertEqual(3, output["totals"]["confirmed_component_integrations"])
        # Components are independent cards and never fabricate a direct parent
        # integration.  Neither parent has direct confirmed evidence here.
        self.assertEqual(0, output["totals"]["confirmed_family_integrations"])
        self.assertEqual(2, len(output["family_rollups"]["cublas"]))
        self.assertEqual(1, len(output["family_rollups"]["cufft"]))

    def test_metric_contract_pending_cards_are_unknown_not_zero(self):
        output = build_portfolio([], [])
        cards = {item["id"]: item for item in output["libraries"]}
        for identifier in ("cuda-math-api", "alchemi", "earth2", "dask"):
            pending = cards[identifier]
            self.assertEqual("pending", pending["metric_contract_status"])
            self.assertEqual(
                {
                    "confirmed": "not_evaluated",
                    "bundled": "not_evaluated",
                    "targeted": "not_evaluated",
                },
                pending["classification_coverage"],
            )
            self.assertIsNone(pending["confirmed_count"])
            self.assertIsNone(pending["bundled_count"])
            self.assertIsNone(pending["targeted_count"])
            self.assertIsNone(pending["headline_count"])
            self.assertNotEqual("Metric contract pending.", pending["description"])
        # A detector-defined entity that has not been collected is also
        # unknown, but is distinct from a missing metric contract.
        self.assertEqual("defined", cards["cublas"]["metric_contract_status"])
        self.assertEqual("not_collected", cards["cublas"]["collection_status"])
        self.assertIsNone(cards["cublas"]["confirmed_count"])

    def test_nonconfirmed_component_never_promotes_parent(self):
        repositories = [
            repo(
                "public/not-direct",
                entry("cublasdx", "bundled", date="2024-01-01"),
            )
        ]
        output = build_portfolio([card("cublasdx", 0, bundled=1)], repositories)
        self.assertEqual([], output["family_rollups"]["cublas"])
        parent = next(item for item in output["libraries"] if item["id"] == "cublas")
        self.assertIsNone(parent["confirmed_count"])
        self.assertEqual(0, output["totals"]["confirmed_integrator_repos"])

    def test_stale_carried_forward_rows_are_retained_but_not_current(self):
        repositories = [
            repo(
                "public/historical-only",
                {
                    **entry("cublas", date="2020-01-01"),
                    "carried_forward": True,
                    "stale": True,
                    "as_of": "2026-07-15T00:00:00Z",
                },
            )
        ]
        output = build_portfolio([], repositories)
        cards = {item["id"]: item for item in output["libraries"]}
        self.assertEqual(
            "not_collected", cards["cublas"]["collection_status"]
        )
        self.assertIsNone(cards["cublas"]["confirmed_count"])
        self.assertEqual(0, output["totals"]["confirmed_integrator_repos"])
        self.assertEqual(
            repositories,
            output["repositories"],
        )

    def test_current_projected_component_cards_and_history_remain_intact(self):
        current = {
            "libraries": [
                card(
                    identifier,
                    index,
                    headline_count=index,
                    sparkline=[index - 1, index],
                    parent_id="nvpl",
                    is_component=True,
                    component_label=identifier.removeprefix("nvpl-").upper(),
                    name=f"Historical {identifier}",
                )
                for index, identifier in enumerate(
                    ("nvpl-blas", "nvpl-fft", "nvpl-tensor"), start=1
                )
            ],
            "repos": [],
        }
        original_repositories = copy.deepcopy(current["repos"])
        output = build_portfolio(current["libraries"], current["repos"])
        self.assertEqual(CATALOG_VERSION, output["catalog_version"])
        self.assertEqual(original_repositories, output["repositories"])
        cards = {item["id"]: item for item in output["libraries"]}
        # NVPL component rows are a historical projection from the parent
        # operator detail. They are retained even though no direct child entry
        # is stored in each repository.
        for identifier in ("nvpl-blas", "nvpl-fft", "nvpl-tensor"):
            old = next(item for item in current["libraries"] if item["id"] == identifier)
            self.assertEqual(old["confirmed_count"], cards[identifier]["confirmed_count"])
            self.assertEqual(old["headline_count"], cards[identifier]["headline_count"])
            self.assertEqual(old["sparkline"], cards[identifier]["sparkline"])
            self.assertEqual(old["component_label"], cards[identifier]["component_label"])
            self.assertNotEqual(old["name"], cards[identifier]["component_label"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
