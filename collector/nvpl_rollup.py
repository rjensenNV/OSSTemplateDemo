"""Additive NVPL component rollup for cards and adoption history.

NVPL is the one portfolio family whose parent metric is deliberately the sum
of component integrations. A repository using BLAS and FFT contributes once
to each component and twice to the parent integration total. Repository rows
remain a distinct-repository table so users can still inspect the underlying
projects without duplicate rows.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, Sequence


COUNT_FIELDS = (
    "confirmed_count",
    "bundled_count",
    "targeted_count",
    "integration_ai_count",
    "repo_ai_count",
    "trending_30d",
    "trending_90d",
    "delta_since_last",
)
GROWTH_FIELDS = ("growth_90d", "growth_365d")
POINT_FIELDS = ("confirmed", "bundled", "targeted", "cumulative_ai")


def _reference_day(current: Mapping[str, Any]) -> datetime.date:
    raw = str(current.get("generated_at") or "")[:10]
    try:
        return datetime.date.fromisoformat(raw)
    except ValueError:
        return datetime.date.today()


def _window_count(
    dates: Sequence[str], start: datetime.date, end: datetime.date
) -> int:
    return sum(
        1
        for raw in dates
        if raw and start.isoformat() < raw[:10] <= end.isoformat()
    )


def _growth(
    dates: Sequence[str], days: int, today: datetime.date, released_on: str
) -> dict[str, int] | None:
    prior_start = today - datetime.timedelta(days=2 * days)
    current_start = today - datetime.timedelta(days=days)
    if prior_start.isoformat()[:7] < released_on:
        return None
    return {
        "current": _window_count(dates, current_start, today),
        "prev": _window_count(dates, prior_start, current_start),
    }


def _nvpl_residual(
    repositories: Sequence[Mapping[str, Any]],
    children: Sequence[Mapping[str, Any]],
    current: Mapping[str, Any],
    released_on: str,
) -> dict[str, Any]:
    """Return parent evidence that names no tracked NVPL component.

    Component cards count component occurrences, while the parent repository
    table is distinct.  The additive parent therefore sums every child plus
    only the NVPL rows that cannot be assigned to a child.  Adding all parent
    rows would double count mapped evidence; ignoring these residual rows would
    undercount NVPL-only Backend/targeted adoption.
    """
    labels = {
        str(card.get("component_label"))
        for card in children
        if card.get("component_label")
    }
    rows: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {
        classification: []
        for classification in ("confirmed", "bundled", "targeted")
    }
    for repo in repositories:
        entry = next(
            (
                value
                for value in repo.get("libraries", ())
                if isinstance(value, Mapping)
                and value.get("library_id") == "nvpl"
            ),
            None,
        )
        if not isinstance(entry, Mapping):
            continue
        classification = entry.get("classification")
        if classification not in rows:
            continue
        operators = set(entry.get("operators") or ())
        if classification == "confirmed":
            detail = entry.get("component_detail")
            mapped = (
                labels & set(detail)
                if isinstance(detail, Mapping) and detail
                else labels & operators
            )
        else:
            mapped = labels & operators
        if not mapped:
            rows[classification].append((repo, entry))

    dates = {
        classification: [
            str(entry.get("first_integration"))
            for _repo, entry in entries
            if entry.get("first_integration")
        ]
        for classification, entries in rows.items()
    }
    confirmed_ai_dates = [
        str(entry.get("first_integration"))
        for _repo, entry in rows["confirmed"]
        if entry.get("first_integration")
        and entry.get("ai_on_integration_commit")
    ]
    today = _reference_day(current)
    headline_dates = dates["confirmed"] + dates["bundled"]
    return {
        "counts": {
            classification: len(entries)
            for classification, entries in rows.items()
        },
        "headline_count": len(rows["confirmed"]) + len(rows["bundled"]),
        "integration_ai_count": len(confirmed_ai_dates),
        "repo_ai_count": sum(
            1 for repo, _entry in rows["confirmed"] if repo.get("ai_assisted")
        ),
        "trending_30d": _window_count(
            dates["confirmed"], today - datetime.timedelta(days=30), today
        ),
        "trending_90d": _window_count(
            dates["confirmed"], today - datetime.timedelta(days=90), today
        ),
        "growth_90d": _growth(
            headline_dates, 90, today, released_on
        ),
        "growth_365d": _growth(
            headline_dates, 365, today, released_on
        ),
        "first_seen_earliest": (
            min(dates["confirmed"]) if dates["confirmed"] else None
        ),
        "dates": dates,
        "ai_dates": confirmed_ai_dates,
    }


def apply_nvpl_additive_rollup(
    current: dict[str, Any],
    timeseries: dict[str, Any],
    repositories: Sequence[Mapping[str, Any]] | None = None,
) -> bool:
    """Apply the explicit NVPL component-sum contract in place.

    Returns ``True`` when a complete, evaluated component set was rolled up.
    Incomplete or deferred data is left untouched rather than fabricating a
    partial parent total.
    """
    cards = {
        card.get("id"): card
        for card in current.get("libraries", ())
        if isinstance(card, dict) and isinstance(card.get("id"), str)
    }
    parent = cards.get("nvpl")
    children = sorted(
        (
            card
            for card in cards.values()
            if card.get("parent_id") == "nvpl" and card.get("is_component") is True
        ),
        key=lambda card: card["id"],
    )
    if not isinstance(parent, dict) or not children:
        return False
    if any(card.get("collection_status") != "collected" for card in children):
        return False
    if any(
        (card.get("classification_coverage") or {}).get(classification)
        != "evaluated"
        for card in children
        for classification in ("confirmed", "bundled", "targeted")
    ):
        return False
    if any(
        not isinstance(card.get(field), int)
        for card in children
        for field in ("confirmed_count", "bundled_count", "targeted_count", "headline_count")
    ):
        return False

    residual = _nvpl_residual(
        repositories or (),
        children,
        current,
        str(parent.get("released_on") or ""),
    )
    parent["component_rollup_mode"] = "additive"
    parent["component_rollup_contract"] = "children_plus_unmapped_parent"
    parent["component_ids"] = [card["id"] for card in children]
    parent["component_residual_counts"] = dict(residual["counts"])
    parent["component_residual_headline_count"] = residual[
        "headline_count"
    ]
    for field in COUNT_FIELDS:
        values = [card.get(field) for card in children]
        if all(isinstance(value, int) for value in values):
            parent[field] = sum(values) + int(residual.get(field) or 0)
    for classification in ("confirmed", "bundled", "targeted"):
        field = f"{classification}_count"
        parent[field] = sum(int(card[field]) for card in children) + int(
            residual["counts"][classification]
        )
    parent["headline_count"] = sum(
        int(card["headline_count"]) for card in children
    ) + int(residual["headline_count"])
    for field in GROWTH_FIELDS:
        values = [card.get(field) for card in children]
        if all(
            isinstance(value, Mapping)
            and isinstance(value.get("current"), int)
            and isinstance(value.get("prev"), int)
            for value in values
        ):
            residual_growth = residual.get(field)
            parent[field] = {
                "current": sum(value["current"] for value in values),
                "prev": sum(value["prev"] for value in values),
            }
            if isinstance(residual_growth, Mapping):
                parent[field]["current"] += int(
                    residual_growth.get("current") or 0
                )
                parent[field]["prev"] += int(
                    residual_growth.get("prev") or 0
                )
        else:
            parent[field] = None
    first_seen = [
        card.get("first_seen_earliest")
        for card in children
        if card.get("first_seen_earliest")
    ]
    if residual.get("first_seen_earliest"):
        first_seen.append(residual["first_seen_earliest"])
    parent["first_seen_earliest"] = min(first_seen) if first_seen else None

    child_series = [
        timeseries.get(card["id"])
        for card in children
        if isinstance(timeseries.get(card["id"]), Mapping)
    ]
    by_child: list[dict[str, Mapping[str, Any]]] = []
    months: set[str] = set()
    for series in child_series:
        indexed = {
            point["month"]: point
            for point in series.get("points", ())
            if isinstance(point, Mapping) and isinstance(point.get("month"), str)
        }
        by_child.append(indexed)
        months.update(indexed)
    if months:
        points = []
        for month in sorted(months):
            point = {"month": month}
            for field in POINT_FIELDS:
                point[field] = sum(
                    int(indexed.get(month, {}).get(field) or 0)
                    for indexed in by_child
                )
            point["confirmed"] += sum(
                1
                for date in residual["dates"]["confirmed"]
                if date[:7] <= month
            )
            point["bundled"] += sum(
                1
                for date in residual["dates"]["bundled"]
                if date[:7] <= month
            )
            point["targeted"] += sum(
                1
                for date in residual["dates"]["targeted"]
                if date[:7] <= month
            )
            point["cumulative_ai"] += sum(
                1 for date in residual["ai_dates"] if date[:7] <= month
            )
            points.append(point)
        as_of = max(
            (
                str(series.get("as_of"))
                for series in child_series
                if series.get("as_of")
            ),
            default=None,
        )
        parent_series = {
            "released_on": parent.get("released_on"),
            "released_confidence": parent.get("released_confidence"),
            "points": points,
        }
        if as_of:
            parent_series["as_of"] = as_of
        timeseries["nvpl"] = parent_series
        parent["sparkline"] = [
            point["confirmed"] + point["bundled"] + point["targeted"]
            for point in points
        ]
        parent["sparkline_months"] = [point["month"] for point in points]
    return True
