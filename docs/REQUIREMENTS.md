# CUDA-X Developer Intelligence — Requirements

> This file is a **point-in-time, host-agnostic mirror** of the project
> requirements. Private source documents, access paths, and internal-only links
> are intentionally omitted from the public repository. Last mirrored:
> 2026-07-22.
>
> Deeper engineering breakdown (tech-debt items, per-phase build notes) lives in
> `docs/PROJECT-CONTEXT.md`, not here. Requirement intent is preserved; private
> endpoints and owner-specific operational details are generalized for public use.

## Summary
In order to focus on customer needs, we need as much data as possible about how developers adopt and use our libraries. Automatic, continuous collection gathers and organizes that data with no manual effort, making it useful across product, engineering, and developer-experience orgs. The result is a single, auditable source of truth, focused on the community and research adoption that otherwise goes untracked.

## Goal
- Single source of truth for library usage, related metadata.
- Aggregator and interface of tools that gather data.
- Customers: PM, EM, engineering, and DX orgs.
- Analysis on collected data — intersectional analysis, frequency analysis.
- Trustworthy — key numbers linked or traceable to their source (commit, file, or link).

## Non-goal
- Not tracking devrel/major accounts, covered by other tools.
- Not a replacement or fork of existing dashboards: it links to and/or integrates with them.

## Design approach
- Start with low-hanging fruit; get real use cases that drive requirements and scope (ask library teams — PM, EM, engineering — for the questions they want answered, and build on those).
- Start with publicly available data (community GitHub adoption and research citations); evaluate any additional approved data sources separately and keep them outside the public-data boundary.
- Aggregate and link, don't rebuild: where a tool or dataset already exists, integrate or link to it rather than re-implementing it.

## ID-scheme note (source document ↔ tracking)
The source document numbers Phase 2's tail and Phase 3 as `REQ-26/27` and
`REQ-30…38`. An earlier tracking note uses a phase-encoded scheme
(`REQ-3-1…3-14`) with finer granularity
(e.g. it splits the combined additional-sources row into per-source rows and adds a Q&A
sentiment item). The two are equivalent in content; this file follows the
**source document's** IDs.

---

## Phase 0 — Finalizing/fixing the POC: GitHub adoption, research usage, issues

| ID | Name | Description | Priority |
| :-- | :-- | :-- | :-- |
| REQ-01 | Link to adoption commit | Each confirmed integration links to the GitHub commit where the library was first adopted, shown as a clickable URL alongside the adoption date. | P0 |
| REQ-02 | Time axis on the landing page charts | The landing page adoption charts show a labeled time axis (by year) so date is legible without opening the detail page. | P2 |
| REQ-03 | Download raw data | Users can download the underlying dataset in a JSON and CSV format for review and easy ingestion by other tools/agents. | P0 |
| REQ-04 | Functionality / operator column | For each confirmed library integration, show which library operators the project uses, detected from the project's own source. Especially important: `Function<>`, then libraries can describe what they want. | P1 |
| REQ-05 | Confirmed integrations as the headline metric | Top-level number on landing page and in reports should be confirmed integrations only; "bundled" (ships a copy of the library) and "targetted" (mentions library in docs/build but doesn't use) are kept for completion but reported separately from total integrations. | P0 |
| REQ-06 | Reduce false-positives (and bug fixes) | Exclude known false positives from the counts: repos vendoring the whole MathDx package (or equivalent math library package) but only using some libraries; copies of existing NVIDIA-owned repos; environment dumps containing the libraries' installed files. Fix bugs. | P0 |
| REQ-07 | Project citation/usage tracker | Track mentions and citations of each library in research papers, surfaced per-library as a count with links to sources, via external APIs (investigating OpenAlex, SemanticScholar, Crossref). Classify how the paper used the library when code is available. | P0 |

## Phase 1 — Onboard all CUDA-X, scale-up CI/CD

| ID | Name | Description | Priority |
| :-- | :-- | :-- | :-- |
| REQ-11 | Scale-up automatic discovery research spike | Evaluate bulk repository-discovery methods (GitHub Archive / BigQuery and alternatives) to replace per-query GitHub code search, which is rate-limited (about 10 searches/min, 1,000 results/query) and is the bottleneck for scaling beyond the pilot libraries. | P0 |
| REQ-12 | Move data collection to the CUDA-X team's CI/CD | Move the automated collector, schedule, data publish, and hosting off the current single-machine setup onto the CUDA-X team's CI/CD, operated by that team. Implemented when a full collection runs on the team's CI/CD on a weekly schedule and the previous local runner is retired. More detailed platform requirements are still needed. | P0 |
| REQ-13 | Onboard all CUDA-X libraries | Extend coverage to all CUDA-X libraries, onboarded in batches: finish Dx, Mp, Xt, Lt libraries; newer/lower-adoption core libraries (cuDSS, cuEquivariance…); big core libraries (cuBLAS, cuFFT…). Implemented once all libraries discoverable from this page are tracked across GitHub and Research and accuracy validated to the spec defined in Phase 0. | P0 |
| REQ-14 | Scale within GitHub rate limits | Implement whatever the solution discovered in REQ-11 is. Implemented when a full all-libraries refresh completes on schedule without exceeding the rate limits or the CI job budget. | P0 |
| REQ-15 | Add version tracking | Track library versions being used by other projects to understand most commonly used skews. | — |

## Phase 2 — API consumption intelligence and interoperability

| ID | Name | Description | Priority |
| :-- | :-- | :-- | :-- |
| REQ-21 | API usage profile per project | For each tracked project, generate a profile of the library APIs it calls, including the set of functions/operators used per library, across all libraries (string-matching). Implemented when each "integration" project (and research when possible) shows the list of library APIs/functions it uses, sourced from the project's own code. | P0 |
| REQ-22 | Cross-reference download reporting | Integrate NVIDIA download data alongside adoption, staged: link to the approved download view per library; pull and show the latest download count; overlay downloads on the adoption chart; and surface "virtual downloads" from adopters that obtain a library through another project. | P1 |
| REQ-23 | Links to/from the CUDA Dependency Map | Cross-link the dashboard with the CUDA Dependency Map in both directions, so a user can move between the two views of the same library. | P2 |
| REQ-24 | Links to/from library pages | Cross-link with each library's approved documentation and source pages in both directions, and link to public release pages. | P2 |
| REQ-25 | API deprecation / breakage impact | How many and which projects would be affected by changing or deprecating a given API. Implemented when, for a given API, the view lists the impacted projects with a link to where each one uses it. | P0 |
| REQ-26 | Downstream interoperability | Let approved downstream tools pull partial, per-project updates and/or embed the project's presentation. Implemented when the agreed public interoperability contract works. | P2 |
| REQ-27 | Programmatic access (CLI / MCP) | Expose the full dataset through a programmatic interface like a CLI and/or an MCP server so an agent or script can query adoption, usage, and developer-signal data directly without opening the dashboard. Extends the raw-data output (REQ-03) with query/filter access rather than a static dump. | P0 |

## Phase 3 — Dev signal aggregation and analysis, final productization

| ID | Name | Description | Priority |
| :-- | :-- | :-- | :-- |
| REQ-30 | LLM Stage | Stand up the shared LLM stage the Phase 3 intelligence features depend on: JTBD extraction, paper-exposure classification, and labeling developer signal. | P0 |
| REQ-31 | Data source: GitHub Issues (external) | Scan GitHub issues in the integrating projects and in NVIDIA's own sample repos (e.g. cuda-samples) for mentions of a tracked library, and surface the pain points, questions, and feature requests around it. Depends on REQ-34. | P0 |
| REQ-32 | Data source: External Forums | Same scan-and-surface method, against external forums and conversation spaces. Need to evaluate what forums are accessible in this manner. Consider Discord bot access. Implemented when, per library, forum threads mentioning the library surface with links. Depends on REQ-34. | P0 |
| REQ-33 | Additional approved signal sources | Apply the same method to any additional data sources that receive separate privacy, access, and publication approval. Such data must not cross the public repository boundary without explicit authorization. | P2 |
| REQ-34 | Interface for signal-analysis results | Integrate an approved backend that runs developer-signal scans (REQ-31 to REQ-32), refreshes them on schedule, and surfaces the results through the same interface. | P0 |
| REQ-35 | Library JTBD | Present each library's jobs-to-be-done in the same interface, generated based on the real community/adoption signals picked up across GitHub/Research/discussions. Implemented when projects carry JTBD labels viewable in the dashboard. | P0 |
| REQ-36 | Upstream dependencies | For each tracked project, show its upstream dependencies and whether it is standalone or part of a larger software effort. Implemented when each project shows its direct dependencies. Note: confirm traversal depth (±2?) and direction (depends-on and/or depended-on-by). | P1 |
| REQ-37 | Citation: classify paper exposure | Classify how a paper used the library (benchmark vs. integration vs. mention vs…). Tiered: when the paper's code is available, derive it from the actual repo usage for high confidence with no LLM; when there's no code (the majority of papers), infer from the paper text via the LLM stage, labeled lower-confidence. Layers on the Phase-0 usage tracker. | P1 |
| REQ-38 | Proactive flags and notifications | Stakeholders can configure notifications for when a signal changes, such as a new major adopter or a sentiment shift. A basic new-adopter digest can ship early; threshold-based sentiment flags depend on the dev-signal aggregation. | P2 |

---

## Implementation notes / concerns
- GitHub rate limits are the primary scaling constraint (REQ-11/REQ-14).
