"""REQ-14 composite discovery contracts and source adapters."""

from .base import (
    DEFAULT_COVERAGE_RULES,
    PUBLIC,
    CoverageCertificate,
    CompositeDiscoveryResult,
    CoverageEpochAssessment,
    CoverageEpochRule,
    CoverageGap,
    CoveragePartition,
    DiscoveryObservation,
    DiscoveryResult,
    IncompleteCoverageError,
    assess_coverage_epoch,
    can_retire_candidate,
    combine_discovery_results,
    durable_union,
)
from .github_search import GitHubCodeSearch
from .query_plan import (
    DiscoveryQueryPack,
    SignalSpec,
    github_query_fingerprint,
    query_packs,
    signal_specs,
    sourcegraph_query_fingerprint,
)
from .sourcegraph import SourcegraphDiscovery, SourcegraphStreamError, parse_sse

__all__ = [
    "DEFAULT_COVERAGE_RULES",
    "PUBLIC",
    "CoverageCertificate",
    "CompositeDiscoveryResult",
    "CoverageEpochAssessment",
    "CoverageEpochRule",
    "CoverageGap",
    "CoveragePartition",
    "DiscoveryObservation",
    "DiscoveryResult",
    "IncompleteCoverageError",
    "GitHubCodeSearch",
    "DiscoveryQueryPack",
    "SignalSpec",
    "SourcegraphDiscovery",
    "SourcegraphStreamError",
    "assess_coverage_epoch",
    "can_retire_candidate",
    "combine_discovery_results",
    "durable_union",
    "github_query_fingerprint",
    "parse_sse",
    "query_packs",
    "signal_specs",
    "sourcegraph_query_fingerprint",
]
