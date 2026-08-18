"""Versioned CUDA-X portfolio cards and component-family evidence.

This layer is intentionally pure: it does not discover, scan, publish, or
write files.  It turns already-validated repository evidence into:

* one card for every versioned catalog entity,
* unchanged component repository rows,
* audit-only parent-family evidence for component families, and
* honest pending cards where no adoption metric contract exists.

The family evidence is separate from ``repositories`` so a cuBLASLt row never
gets rewritten into, replaces, or inflates its cuBLAS parent row.  Components
and parents have independent cards; NVPL's explicitly additive presentation
contract is applied separately after portfolio construction.
"""
from __future__ import annotations

import copy
import datetime as _datetime
from typing import Any, Mapping, Sequence

from .catalog import (
    CATALOG,
    CATALOG_OBSERVED_ON,
    CATALOG_SOURCE,
    CATALOG_VERSION,
    OFFICIAL_CUDA_X,
)


CLASSIFICATIONS = ("confirmed", "bundled", "targeted")
KINDS = {
    "product",
    "component",
    "framework",
    "service",
    "model_family",
    "technology",
}
TRACKABILITY = {
    "direct_code",
    "research_only",
    "needs_metric_contract",
    "retired",
}
CATALOG_STATUSES = {"active", "retained", "retired", "preview"}

OFFICIAL_CATEGORY_COUNTS = {
    "math": 10,
    "scientific": 4,
    "physics": 3,
    "quantum": 4,
    "deep-learning": 4,
    "parallel": 4,
    "data": 10,
    "image-video": 7,
    "communication": 3,
}
OFFICIAL_IDS_BY_CATEGORY = {
    "math": {
        "cublas", "cufft", "curand", "cusolver", "cusparse", "cutensor",
        "cudss", "cuda-math-api", "amgx", "nvmath",
    },
    "scientific": {"cuequivariance", "alchemi", "culitho", "cuest"},
    "physics": {"warp", "physicsnemo", "earth2"},
    "quantum": {"cuquantum", "cupqc", "cudaq-qec", "cudaq-solvers"},
    "deep-learning": {"cudnn", "tensorrt", "cutlass", "flashinfer"},
    "parallel": {"thrust", "cub", "cuda-compute", "cuda-parallel"},
    "data": {
        "cudf", "cuvs", "cuml", "cuopt", "cugraph", "nemo-curator",
        "morpheus", "nvcomp", "gds", "dask",
    },
    "image-video": {
        "nvimagecodec", "dali", "cvcuda", "cucim", "npp",
        "video-codec-sdk", "optical-flow-sdk",
    },
    "communication": {"nvshmem", "nccl", "nixl"},
}

REQUESTED_COMPONENT_ROLLUPS = {
    "cufftdx": "cufft",
    "cublasdx": "cublas",
    "cusolverdx": "cusolver",
    "curanddx": "curand",
    "nvcompdx": "nvcomp",
    "cufftmp": "cufft",
    "cublasmp": "cublas",
    "cusolvermp": "cusolver",
    "cufftxt": "cufft",
    "cublasxt": "cublas",
    "cublaslt": "cublas",
    "cusparselt": "cusparse",
    "tensorrt-llm": "tensorrt",
}
PREVIEW_COMPONENT_ROLLUPS = {"cusparsedx": "cusparse"}
RETAINED_ENTITY_IDS = {"nvpl", "ovrtx"}


class PortfolioError(ValueError):
    """The catalog or supplied aggregate evidence is internally inconsistent."""


def _iso_date(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise PortfolioError(f"{field} must be an ISO date string")
    try:
        _datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise PortfolioError(f"{field} must be an ISO date string") from exc


def validate_portfolio_catalog(
    catalog: Sequence[Mapping[str, Any]] = CATALOG,
    official: Sequence[Mapping[str, Any]] = OFFICIAL_CUDA_X,
    *,
    version: str = CATALOG_VERSION,
    observed_on: str = CATALOG_OBSERVED_ON,
) -> bool:
    """Validate portfolio identity, provenance, and the frozen official census."""
    if not isinstance(version, str) or not version.strip():
        raise PortfolioError("catalog version must be non-empty")
    _iso_date(observed_on, "catalog observed_on")
    if not version.startswith(observed_on + "."):
        raise PortfolioError("catalog version must be anchored to observed_on")
    if len(official) != 49:
        raise PortfolioError("official CUDA-X catalog must contain exactly 49 entries")

    official_ids = [item.get("id") for item in official]
    catalog_ids = [item.get("id") for item in catalog]
    if any(not isinstance(identifier, str) or not identifier for identifier in catalog_ids):
        raise PortfolioError("catalog IDs must be non-empty strings")
    if len(catalog_ids) != len(set(catalog_ids)):
        raise PortfolioError("catalog IDs must be unique")
    if len(official_ids) != len(set(official_ids)):
        raise PortfolioError("official catalog IDs must be unique")
    if not set(official_ids).issubset(catalog_ids):
        raise PortfolioError("every official entry must remain in the additive catalog")

    categories = {}
    actual_ids_by_category: dict[str, set[str]] = {}
    for item in official:
        categories[item.get("category")] = categories.get(item.get("category"), 0) + 1
        actual_ids_by_category.setdefault(item.get("category"), set()).add(item.get("id"))
        if item.get("provenance") != "official_cuda_x":
            raise PortfolioError("official entries require official_cuda_x provenance")
        if item.get("catalog_status") != "active":
            raise PortfolioError("official entries must remain active in this catalog version")
    if categories != OFFICIAL_CATEGORY_COUNTS:
        raise PortfolioError(
            "official category census differs from the versioned 49-entry snapshot"
        )
    if actual_ids_by_category != OFFICIAL_IDS_BY_CATEGORY:
        raise PortfolioError(
            "official identities/categories differ from the versioned 49-entry snapshot"
        )

    known = set(catalog_ids)
    by_id = {item["id"]: item for item in catalog}
    required_fields = {
        "id",
        "name",
        "category",
        "kind",
        "trackability",
        "catalog_status",
        "rollup_to",
        "provenance",
        "first_observed_on",
    }
    for item in catalog:
        missing = required_fields - set(item)
        if missing:
            raise PortfolioError(
                "catalog entry is missing required fields: " + ", ".join(sorted(missing))
            )
        if not isinstance(item["name"], str) or not item["name"]:
            raise PortfolioError("catalog names must be non-empty strings")
        if not isinstance(item["category"], str) or not item["category"]:
            raise PortfolioError("catalog categories must be non-empty strings")
        if item["kind"] not in KINDS:
            raise PortfolioError(f"unsupported catalog kind: {item['kind']}")
        if item["trackability"] not in TRACKABILITY:
            raise PortfolioError(
                f"unsupported trackability: {item['trackability']}"
            )
        if item["catalog_status"] not in CATALOG_STATUSES:
            raise PortfolioError(
                f"unsupported catalog status: {item['catalog_status']}"
            )
        _iso_date(item["first_observed_on"], "catalog first_observed_on")
        if item["first_observed_on"] > observed_on:
            raise PortfolioError("first_observed_on cannot be later than observed_on")
        parent = item["rollup_to"]
        if parent is not None:
            if parent == item["id"] or parent not in known:
                raise PortfolioError("rollup_to must name another catalog entity")
            if by_id[parent]["kind"] == "component":
                raise PortfolioError("component rollups cannot target another component")

    for component_id, parent_id in {
        **REQUESTED_COMPONENT_ROLLUPS,
        **PREVIEW_COMPONENT_ROLLUPS,
    }.items():
        item = by_id.get(component_id)
        if (
            not item
            or item.get("kind") != "component"
            or item.get("rollup_to") != parent_id
        ):
            raise PortfolioError(
                f"required component {component_id} must roll up to {parent_id}"
            )
    for retained_id in RETAINED_ENTITY_IDS:
        item = by_id.get(retained_id)
        if (
            not item
            or item.get("catalog_status") != "retained"
            or item.get("provenance") != "previously_tracked"
        ):
            raise PortfolioError(
                f"previously tracked entity {retained_id} must be retained"
            )
    if by_id["cusparsedx"]["catalog_status"] != "preview":
        raise PortfolioError("cuSPARSEDx must remain preview until released")
    return True


def _coverage(card: Mapping[str, Any] | None) -> dict[str, str]:
    if card is None:
        return {classification: "not_evaluated" for classification in CLASSIFICATIONS}
    supplied = card.get("classification_coverage")
    explicit_not_evaluated = set(card.get("not_evaluated_classes") or ())
    if supplied is None:
        evaluated = set(CLASSIFICATIONS) - explicit_not_evaluated
    elif isinstance(supplied, Mapping):
        result = {}
        for classification in CLASSIFICATIONS:
            value = supplied.get(classification, "not_evaluated")
            if value is True:
                value = "evaluated"
            elif value is False:
                value = "not_evaluated"
            if value not in ("evaluated", "not_evaluated"):
                raise PortfolioError("invalid classification coverage state")
            result[classification] = value
        return result
    elif isinstance(supplied, (list, tuple, set, frozenset)):
        evaluated = set(supplied)
    else:
        raise PortfolioError("classification_coverage must be a mapping or list")
    unknown = evaluated - set(CLASSIFICATIONS)
    if unknown:
        raise PortfolioError("classification_coverage contains an unknown band")
    return {
        classification: (
            "evaluated"
            if classification in evaluated
            and classification not in explicit_not_evaluated
            else "not_evaluated"
        )
        for classification in CLASSIFICATIONS
    }


def _repository_entries(
    repositories: Sequence[Mapping[str, Any]],
) -> tuple[
    dict[str, dict[str, int]],
    set[str],
]:
    counts: dict[str, dict[str, int]] = {}
    confirmed_repositories: set[str] = set()
    names: set[str] = set()
    for repo in repositories:
        name = repo.get("full_name")
        if not isinstance(name, str) or not name or name in names:
            raise PortfolioError("repositories require unique non-empty full_name")
        names.add(name)
        library_ids: set[str] = set()
        repo_entries = repo.get("libraries")
        if not isinstance(repo_entries, list):
            raise PortfolioError("repository libraries must be a list")
        for entry in repo_entries:
            if not isinstance(entry, Mapping):
                raise PortfolioError("repository library entries must be objects")
            library_id = entry.get("library_id")
            classification = entry.get("classification")
            if (
                not isinstance(library_id, str)
                or classification not in CLASSIFICATIONS
            ):
                raise PortfolioError(
                    "repository entries require a library_id and supported classification"
                )
            if library_id in library_ids:
                raise PortfolioError("a repository cannot repeat a library entry")
            library_ids.add(library_id)
            if entry.get("carried_forward") is True:
                if (
                    entry.get("stale") is not True
                    or not isinstance(entry.get("as_of"), str)
                    or not entry.get("as_of")
                ):
                    raise PortfolioError(
                        "carried-forward repository evidence requires stale "
                        "as-of provenance"
                    )
                # Retain the historical row for audit/export without treating
                # it as current Cohort A adoption or portfolio membership.
                continue
            counts.setdefault(
                library_id, {band: 0 for band in CLASSIFICATIONS}
            )[classification] += 1
            if classification == "confirmed":
                confirmed_repositories.add(name)
    return counts, confirmed_repositories


def _first_evidence(
    evidence: Sequence[tuple[str, Mapping[str, Any]]],
    parent_id: str,
) -> tuple[str | None, str | None]:
    """Choose the earliest dated evidence; prefer direct parent evidence on ties."""
    dated = [
        (str(entry.get("first_integration")), library_id, entry)
        for library_id, entry in evidence
        if entry.get("first_integration")
    ]
    if not dated:
        return None, None
    dated.sort(
        key=lambda item: (
            item[0],
            0 if item[1] == parent_id else 1,
            item[1],
        )
    )
    _date, _library_id, entry = dated[0]
    return entry.get("first_integration"), entry.get("first_integration_commit")


def derive_family_rollups(
    repositories: Sequence[Mapping[str, Any]],
    catalog: Sequence[Mapping[str, Any]] = CATALOG,
) -> dict[str, list[dict[str, Any]]]:
    """Return unique confirmed family evidence without modifying component rows."""
    components_by_parent: dict[str, set[str]] = {}
    for item in catalog:
        parent = item.get("rollup_to")
        if (
            parent
            and item.get("kind") == "component"
            and item.get("trackability") == "direct_code"
            and not item.get("projected_from_parent")
        ):
            components_by_parent.setdefault(parent, set()).add(item["id"])

    component_parent = {
        component_id: parent_id
        for parent_id, component_ids in components_by_parent.items()
        for component_id in component_ids
    }
    parents = set(components_by_parent)
    result: dict[str, list[dict[str, Any]]] = {
        parent_id: [] for parent_id in sorted(parents)
    }
    # One repository pass applies every family mapping. This remains O(evidence)
    # as additional component families are added.
    for repo in repositories:
        grouped: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
        for entry in repo.get("libraries", []):
            if (
                entry.get("classification") != "confirmed"
                or entry.get("carried_forward") is True
            ):
                continue
            library_id = entry.get("library_id")
            parent_id = (
                library_id
                if library_id in parents
                else component_parent.get(library_id)
            )
            if parent_id:
                grouped.setdefault(parent_id, []).append((library_id, entry))
        for parent_id, confirmed in grouped.items():
            component_ids = components_by_parent[parent_id]
            if not confirmed:
                continue
            confirmed_components = sorted(
                library_id
                for library_id, _entry in confirmed
                if library_id in component_ids
            )
            first_date, first_commit = _first_evidence(confirmed, parent_id)
            result[parent_id].append(
                {
                    "full_name": repo["full_name"],
                    "library_id": parent_id,
                    "classification": "confirmed",
                    "direct_parent_evidence": any(
                        library_id == parent_id for library_id, _entry in confirmed
                    ),
                    "component_ids": confirmed_components,
                    "first_integration": first_date,
                    "first_integration_commit": first_commit,
                    "evidence_library_ids": sorted(
                        {library_id for library_id, _entry in confirmed}
                    ),
                }
            )
    for rows in result.values():
        rows.sort(key=lambda row: row["full_name"].casefold())
    return result


def _existing_extra_catalog_record(card: Mapping[str, Any]) -> dict[str, Any]:
    """Keep an already-published entity even if the official catalog moved."""
    return {
        "id": card["id"],
        "name": card.get("name") or card["id"],
        "category": card.get("category") or "retained",
        "kind": "component" if card.get("parent_id") else "product",
        "trackability": "direct_code",
        "catalog_status": "retained",
        "rollup_to": card.get("parent_id"),
        "provenance": "previously_published_runtime",
        "first_observed_on": card.get("first_observed_on") or CATALOG_OBSERVED_ON,
        "projected_from_parent": bool(card.get("is_component")),
        "component_label": card.get("component_label"),
    }


def _card(
    item: Mapping[str, Any],
    existing: Mapping[str, Any] | None,
    measured: Mapping[str, int],
    *,
    family_count: int | None = None,
    family_confirmed_evaluated: bool = False,
    family_coverage: str | None = None,
) -> dict[str, Any]:
    card = copy.deepcopy(dict(existing or {}))
    card.update(
        {
            key: copy.deepcopy(item.get(key))
            for key in (
                "id",
                "name",
                "category",
                "kind",
                "trackability",
                "catalog_status",
                "rollup_to",
                "provenance",
                "first_observed_on",
            )
        }
    )
    if item.get("description") is not None:
        card["description"] = copy.deepcopy(item["description"])
    # Keep the established dashboard/publication component contract while the
    # catalog uses the clearer ``kind``/``rollup_to`` vocabulary internally.
    # Direct component evidence remains independent; only legacy projected
    # component cards set ``projected_from_parent``.
    card["parent_id"] = item.get("rollup_to")
    card["is_component"] = item.get("kind") == "component"
    card["component_label"] = (
        (item.get("component_label") or item.get("name"))
        if card["is_component"] else None
    )
    card["projected_from_parent"] = bool(item.get("projected_from_parent"))

    pending_contract = item.get("trackability") in {
        "needs_metric_contract",
        "research_only",
        "retired",
    }
    if pending_contract:
        if any(measured.values()):
            raise PortfolioError(
                "metric-contract-pending entities cannot carry adoption rows"
            )
        coverage = {
            classification: "not_evaluated"
            for classification in CLASSIFICATIONS
        }
        card["metric_contract_status"] = (
            "retired"
            if item.get("trackability") == "retired"
            else "pending"
        )
        card["collection_status"] = "not_applicable"
    elif existing is None:
        # A trackable catalog entry that has not participated in a complete
        # source epoch is unknown, not a measured zero.
        coverage = {
            classification: "not_evaluated"
            for classification in CLASSIFICATIONS
        }
        if family_confirmed_evaluated:
            coverage["confirmed"] = "evaluated"
        card["metric_contract_status"] = "defined"
        card["collection_status"] = "not_collected"
    else:
        coverage = _coverage(existing)
        card["metric_contract_status"] = "defined"
        card["collection_status"] = existing.get(
            "collection_status", "collected"
        )

    card["classification_coverage"] = coverage
    card["not_evaluated_classes"] = [
        classification
        for classification in CLASSIFICATIONS
        if coverage[classification] == "not_evaluated"
    ]
    for classification in CLASSIFICATIONS:
        field = f"{classification}_count"
        expected = (
            measured[classification]
            if coverage[classification] == "evaluated"
            else None
        )
        if existing is not None and coverage[classification] == "evaluated":
            source_count = existing.get(field)
            # Accept an older family-aware card as input while reconciling it
            # back to direct repository evidence.
            if (
                classification == "confirmed"
                and existing.get("family_rollup")
            ):
                source_count = existing.get("direct_confirmed_count")
            if item.get("projected_from_parent"):
                expected = source_count
            elif source_count != measured[classification]:
                raise PortfolioError(
                    f"{item['id']} {field} does not reconcile to repository rows"
                )
        card[field] = expected

    if family_count is not None:
        card["family_rollup"] = True
        card["family_coverage"] = family_coverage or "not_collected"
        card["direct_confirmed_count"] = measured["confirmed"]
        card["confirmed_count"] = (
            family_count
            if coverage["confirmed"] == "evaluated"
            else None
        )
    else:
        for key in (
            "direct_confirmed_count",
            "family_coverage",
            "family_rollup",
        ):
            card.pop(key, None)
    headline = card.get("confirmed_count")
    if (
        headline is not None
        and card.get("adoption_counts_build")
        and coverage["bundled"] == "evaluated"
    ):
        headline += (
            card.get("bundled_count") or 0
            if item.get("projected_from_parent")
            else measured["bundled"]
        )
    elif card.get("adoption_counts_build") and coverage["bundled"] != "evaluated":
        headline = None
    card["headline_count"] = headline
    return card


def build_portfolio(
    library_cards: Sequence[Mapping[str, Any]],
    repositories: Sequence[Mapping[str, Any]],
    *,
    catalog: Sequence[Mapping[str, Any]] = CATALOG,
    official: Sequence[Mapping[str, Any]] = OFFICIAL_CUDA_X,
    version: str = CATALOG_VERSION,
) -> dict[str, Any]:
    """Build catalog cards, preserved rows, rollups, and unique portfolio totals."""
    validate_portfolio_catalog(
        catalog, official, version=version, observed_on=CATALOG_OBSERVED_ON
    )
    source_cards: dict[str, Mapping[str, Any]] = {}
    for card in library_cards:
        identifier = card.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise PortfolioError("library cards require a non-empty id")
        if identifier in source_cards:
            raise PortfolioError("library card IDs must be unique")
        source_cards[identifier] = card

    measured, confirmed_repositories = _repository_entries(repositories)
    known_ids = {item["id"] for item in catalog}
    unknown_row_ids = set(measured) - known_ids - set(source_cards)
    if unknown_row_ids:
        raise PortfolioError("repository evidence references an unknown library")

    # Additive means previously published cards are retained even when a later
    # official page or catalog revision no longer contains them.
    expanded_catalog = [dict(item) for item in catalog]
    for identifier in source_cards:
        if identifier not in known_ids:
            expanded_catalog.append(
                _existing_extra_catalog_record(source_cards[identifier])
            )

    family_rollups = derive_family_rollups(repositories, expanded_catalog)
    cards = []
    for item in expanded_catalog:
        identifier = item["id"]
        card = _card(
            item,
            source_cards.get(identifier),
            measured.get(
                identifier, {classification: 0 for classification in CLASSIFICATIONS}
            ),
            family_count=None,
            family_confirmed_evaluated=False,
            family_coverage=None,
        )
        cards.append(card)

    top_level_ids = {
        item["id"]
        for item in expanded_catalog
        if item.get("rollup_to") is None
        and item.get("trackability") == "direct_code"
    }
    confirmed_family_integrations = sum(
        measured.get(identifier, {}).get("confirmed", 0)
        for identifier in top_level_ids
    )

    component_ids = {
        item["id"]
        for item in expanded_catalog
        if item.get("kind") == "component"
    }
    confirmed_component_integrations = sum(
        measured.get(identifier, {}).get("confirmed", 0)
        for identifier in component_ids
    )
    return {
        "catalog_version": version,
        "catalog_source": CATALOG_SOURCE,
        "catalog_observed_on": CATALOG_OBSERVED_ON,
        "official_entry_count": len(official),
        "libraries": cards,
        # A deep copy is intentional: callers can safely attach publication
        # metadata without ever rewriting their scan/history objects.
        "repositories": copy.deepcopy(list(repositories)),
        "family_rollups": family_rollups,
        "totals": {
            "confirmed_integrator_repos": len(confirmed_repositories),
            "confirmed_family_integrations": confirmed_family_integrations,
            "confirmed_component_integrations": confirmed_component_integrations,
        },
    }


# Fail at import time if a future edit silently changes the frozen official
# census or removes an additive entity.
validate_portfolio_catalog()
