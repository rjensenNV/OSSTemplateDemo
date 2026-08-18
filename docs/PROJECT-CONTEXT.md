# CUDA-X Developer Intelligence — Project Context

Planning, live state, operating model, and hard-won lessons. `AGENTS.md` is the operational
contract; `docs/REQUIREMENTS.md` is the host-agnostic point-in-time requirements mirror. This file
records why the architecture exists and where production actually stands.

## What this is

CUDA-X Developer Intelligence is a Python 3.12 collector and static dashboard for external
community and research adoption of NVIDIA CUDA-X libraries. It identifies public third-party
repositories with auditable direct-use evidence, dates first adoption, preserves weaker evidence
as separate bands, enriches repository history for visible AI/agent markers, and connects OpenAlex
research mentions to confirmed public adopters.

- Local dashboard: follow the preview instructions in `README.md`.
- Maintainer: see `MAINTAINERS.md`.
- Collector host: a maintainer-controlled Mac checkout.

The public repository stores source code and validation fixtures only.
Generated adoption, citation, checkpoint, export, and dashboard artifacts are
ignored and excluded from source releases. GitHub Actions tests the source and
never collects.

## Honest live state

The project is active and in preview. The source snapshot includes the
versioned 65-entity portfolio, 56 active detector definitions, state engine,
collector, publisher, dashboard, and deterministic validation fixtures. It
does not include a generated result set, so the repository makes no current
adoption, citation, or full-portfolio count claim. The browser is V2-only and
has no runtime fallback to V1.

REQ-14's state engine, composite discovery, GraphQL metadata, bounded
scanner/cache, citation cache, portfolio/catalog, V2 publication, universal
validation, CLI safety, migration parity, failure fixtures, browser acceptance,
and public-repository capacity benchmark are locally validated. Full-catalog
runtime, recall, cache-hit, API-use, disk, and adoption results must not be
inferred from the source snapshot. No host-specific automated collection
schedule is published or armed.

## REQ-14 scope decision

The portfolio has 65 versioned entities: 49 first-party NVIDIA entries observed on the official
CUDA-X page on 2026-07-27, 14 component rows (13 active plus preview cuSPARSEDx), and two retained
products. Partner libraries are excluded. The catalog is additive:

- requested Dx/Mp/Xt/Lt and TensorRT-LLM components are first-class entries;
- preview cuSPARSEDx remains pending until released;
- previously tracked NVPL, ovrtx, and existing projected component history are retained;
- disappearance from a future marketing page becomes reviewed retained/retired state, never
  silent deletion; and
- products/frameworks/services without an honest direct-code metric show metric-contract pending,
  not zero.

The metric decision is also settled for this phase:

- 56 active detectors comprise 12 mature and 44 reviewed REQ-14 direct-lane declarations;
- `cuda.compute` and `cuda.parallel` remain official catalog rows but are inactive,
  all-`not_evaluated`, and out of collection scope by owner decision;
- mature libraries retain confirmed/bundled/targeted history;
- all high-volume/XXL additions measure confirmed direct own-source integration;
- the reviewed Phase 8 contract additionally enables exact declared/bundled evidence for 19
  Python-distributed libraries and exact targeted CMake/link evidence for 15 libraries;
- every other lower band is explicitly `not_evaluated`/`null`; and
- framework-mediated and transitive adoption is deferred to later work.

Confirmed component evidence contributes to a unique-repository parent family rollup without
rewriting the component row. One repository using several cuBLAS components counts once on the
cuBLAS parent and once in the portfolio repository total.

## Why the architecture changed

Historical Mac runs exposed a multiplicative pipeline:

- the June 29 ten-library full scan took about 35 hours;
- July incrementals still took roughly 22–25 hours;
- the July 20 run stalled after 1,980 of 2,169 selected scans;
- 5,755 candidates implied 11,510 REST metadata/HEAD calls;
- disposable clones and dozens of per-library Git subprocesses repeated unchanged work; and
- the monolithic `current.json` was already about 3.8 MB.

Scaling that loop to the full CUDA-X catalog would remain multi-day and eventually exceed static
artifact limits. The answer was not a larger timeout. REQ-14 makes work proportional to
new/changed/invalidation evidence and gives every stage a correctness and budget contract.

## REQ-14 architecture

### Plan before network

`collector.cli plan` compares canonical fingerprints for discovery, each detector, dating,
aggregation, citation queries, catalog, and publication. A weekly plan that exceeds its budget or
requires cold state refuses to collect and prints the attended reconcile decision. Routine
refreshes cannot silently become full scans.

### Composite discovery and public metadata

Sourcegraph streaming search is advisory broad recall for full/onboard runs. It uses explicit V3
keyword semantics, public-GitHub scope, `select:file`, a rejected-on-saturation numeric ceiling,
and a rejected server-time boundary. Complete lanes may add candidates; incomplete observations
remain quarantined and cannot assert a clean zero. GitHub code search is the required
GitHub-native coverage and retirement authority on partitioned reconciliation lanes and across
every detector in a full reconcile. Coverage certificates record terminal completion, partitions,
caps, lag, skips, and errors. Required incomplete coverage blocks publication. A weekly run
without a due GitHub authority lane still fails on incomplete Sourcegraph recall.
At exact byte-size leaves below GitHub's 1,000-row window, a bounded page walk is accepted only
after an explicit empty page and unique-item/count consistency checks; otherwise complementary
path/repository partitioning continues or the epoch fails closed. Page-order churn may retry the
entire exact-size walk up to three times; partial walks are never combined, and an accepted retry
must independently pass the same proof.

GitHub code-search requests are serialized at a seven-second floor. A successful zero-remaining
response waits proactively until reset. `Retry-After` takes precedence, primary exhaustion waits
until reset, and positive-remaining secondary throttling backs off for 60/120/240 seconds when
GitHub does not supply a delay. Responses reporting at least 900 matches proactively escalate the
request floor through 15/60/120 seconds; secondary events use the same escalation. Twenty
consecutive successful unsaturated searches lower the floor one level. A server-directed delay may
consume up to the configured mode-specific transport total; every wait also remains bounded by the
run wall deadline. Fresh HTTP attempts are journaled per discovery-task attempt so failed retries
survive coordinator restarts and count against the same run budget.
The attended 36-hour reconcile may honor up to two cumulative hours of GitHub code-search retry
waits; the weekly path retains its 600-second ceiling. Request counts and the run wall remain the
hard outer limits in both modes.

Multi-signal GitHub packs execute as exact member queries whose complete public observations are
unioned under the unchanged logical-OR fingerprint. Member-prefixed coverage partitions preserve
the proof boundary, and one incomplete member quarantines the entire pack. This avoids the API's
compound-query secondary throttle without weakening discovery or classification semantics.

GitHub GraphQL batches stable node ID, rename, explicit visibility, fork/archive state, default
branch, HEAD, and required display metadata. Public visibility is required independently of token
scope. After staging validates, a second node-ID-only pass covers exactly the would-be published
set. Every repository must still be explicitly public, non-private, non-fork, and non-archived.
The set hash, conservative start/completion timestamps, points, remaining quota, and task counts
are journaled; unresolved, stale, partial, private, gone, budget, reserve, or lease outcomes block
installation and leave the last-good manifest live.

This substantially improves current-public direct-integration recall and eliminates silent 1,000
result truncation. It does not claim literal completeness of every historical repository. An
integration removed before any free index observed it can remain undiscovered; removed historical
use is not the primary product goal.

### Durable state and bounded scanning

Mac-local SQLite under ignored `.state/` is the transactional operational truth. It holds durable
repository identities/HEADs, catalog and granular fingerprints, candidate source/path/ref
evidence, scan results/raw dates, repository-wide AI/CFF analysis, tasks/leases, source coverage,
citations, runs/stages/budgets, releases, audited successor lineage, and per-attempt network usage.

The Git cache starts with treeless depth-one bare repositories under per-repository locks. Only
new, changed, or invalidated work is fetched/scanned. The primary direct-negative path inventories
bare trees with `ls-tree` and one persistent checkout-filter-aware `cat-file` stream. Isolated
worktrees remain for mature/positive work and older-Git or correctness-sensitive filter fallback.
Mature detectors hydrate ordinary-size current blobs once, retain sparse large own-source files up
to the triage bound, and prune still-promised large assets from only the ephemeral index before
whole-index classification. Clean rejects skip history; positives alone fetch blobless commit/tree
history for rename-aware adoption dating and repository-wide enrichment.
Completed results are committed after each repository and reused by a compatible retry/new run.

Normal default concurrency is six workers. Attended reconciliation uses fourteen. A frozen
credential-free 105-public-repository corpus measured 2,521.62 repositories/hour at six workers
and 2,811.26/hour at fourteen on the exact final collector source, with peak RSS of 6.52 and
7.80 GiB respectively. The conservative 2,500/hour normal and 2,800/hour reconcile planner floors
project 30,000 scanner tasks to 12.00 and 10.71 hours respectively, leaving modeled headroom inside
the 24-hour target. These are bounded scanner results, not a production runtime or recall
measurement. Cache target is 200 GiB and hard stop is 250 GiB. The reproducible protocol and
limitations are in `docs/REQ14-BENCHMARK.md`.

### Cached research enrichment

OpenAlex remains the free research source. `collector.citation_pipeline` is the supported cached
stage; `collector.citation_extract` performs bounded public arXiv/PDF repository-link extraction
without GitHub credentials or publication capability; `collector.citations` is a refusal
tombstone. Query snapshots are cached by library query fingerprint, works/source extraction by
payload fingerprint, and CFF/DOI analysis by repository HEAD. Completeness, caps, `as_of`,
stale/carry-forward status, and errors are per library. Adoption can publish with explicitly stale
last-good citations; research gaps cannot masquerade as an uncapped census.

### V2 publication

The home page loads a small manifest instead of the whole corpus. Library adoption and citation
rows are content-addressed, deterministic, per-library lazy shards. Repository exports are
separate indexed JSONL/CSV parts. A normal library page initially loads only its own index and
first repository shard; the research tab triggers its citation shards.

The manifest maximum is 250 KiB. Every non-manifest artifact must remain strictly below 4,000,000
exact encoded bytes and below the universal 5 MiB ceiling. The release gate covers discovery
coverage; staging validation
covers schema, paths, byte counts, hashes, row counts, privacy, duplicates, and aggregate
reconciliation. Immutable artifacts are installed first and the manifest is replaced last,
preserving the last-good release on failure.

Final visibility batches are capped at 50, and each new release attempt starts a fresh task epoch.
A compatible crash retry may resume or reuse only the exact stable-ID set and task plan while its
conservative epoch-start remains under 120 minutes; completed batches are not repeated. A failed,
stale, or mismatched gate first repeats authoritative metadata so stale public state cannot poison
rematerialization, then starts a new final epoch. GraphQL spend is cumulative across same-run
epochs and survives sanitized checkpoint round trips; quota `remaining` is reused only while its
reset window is active. The planner includes both passes: 30k candidates project to 1,200 GraphQL
requests and 60k to 2,400, and budget/reserve/age breaches are refused before network work.

The first successful genuine reconciliation will create a deterministic, public-only,
content-addressed state checkpoint under `data/state-checkpoint/`; it is intentionally absent
today. Seeding one from V1 would invent node IDs, public-visibility attestations, HEADs,
fingerprints, and coverage. Local Git objects remain disposable.

## Runtime targets and configured limits

These are goals and code budgets, not production outcomes:

| Operation | Target | Default incident/ceiling |
|---|---:|---:|
| Warm no-change weekly | 30 minutes | 1 hour |
| Normal weekly | 2 hours | 4 hours |
| Targeted onboarding | 4 hours | 4-hour default; 8 only by reviewed override |
| Full ~30k reconciliation | 24 hours | 36 hours |
| Stress ~60k | 48-hour resumable design goal | explicit override; default is 36 hours |

Normal operation targets at least 90% scan-result reuse and less than 16 GiB RSS. Weekly defaults
cap scans/fetches at 2,000; reconcile caps them at 60,000. Both retain half of a standard 5,000-point
GraphQL quota through a 2,500-point minimum reserve. Sourcegraph, GitHub search, wall time,
repository timeout, workers, and cache size have independent limits.

## Supported operating contract

```bash
# No network/no production writes:
python3.12 -m collector.cli plan --json

# Bounded weekly:
python3.12 -m collector.cli refresh

# Targeted, complete-portfolio materialization:
python3.12 -m collector.cli onboard --libraries ID...

# Fixture-only detector comparison and local release validation:
python3.12 -m collector.cli compare
python3.12 -m collector.cli validate

# Explicit attended full:
python3.12 -m collector.cli plan --mode reconcile --json
python3.12 -m collector.cli reconcile --confirm-full
```

`refresh.sh` is the only weekly collection driver. It requires a clean `main`, fast-forwards
`origin/main`, obtains the GitHub token from `gh`, verifies Homebrew Python 3.12, runs the bounded
refresh, and validates local V2 output. Generated output remains ignored and is never committed or
pushed by this source repository.

The old `collector.run` and `onboard_merge.py` commands are retired compatibility tombstones.
`collector.cli onboard` uses the shared state engine and cannot replace the portfolio with only the
selected libraries.

## Phase 8 Cohort A cutover complete

The owner accepted the partial-portfolio boundary and authorized V2 release
`2ccb121ad90b2624dbdf`. It retains all 19 previously live V1 cards, publishes current results for
the 28 selected Cohort A libraries, keeps Cohort B cards explicitly uncollected, and contains 217
artifacts plus 2,930 reconciled paper rows. All 214 surviving V1 NVPL repositories retain their
exact V1 subtype membership, while V2 classifications remain authoritative; no other V1 label or
row is merged. The 318 owner-deferred repositories remain recorded as future work. The owner
explicitly waived a fresh final-visibility/privacy re-attestation for this release after static
privacy, closure, semantic parity, UI, and publication tests passed. Launchd remains unarmed.

The owner approved a product-boundary pivot and then stopped Warp before its required GitHub lane
certified. The interrupted all-library run is explicitly abandoned, and an audited successor
carries exactly the 28 fully discovery-certified pre-Warp libraries through the downstream
reconciliation. Warp is excluded in full: its two charged attempts remain in the lineage/budget,
but none of its partial task state, observations, partitions, or coverage can be inherited. This is
an explicitly partial portfolio release, not global REQ-14 closure. Warp and the other remaining
active libraries become Cohort B work.

The attended control path is:

```bash
./refresh.sh --check
python3.12 -m collector.cli run-cohort-successor \
  --predecessor-run-id RUN_ID \
  --predecessor-source-ref COMMIT \
  --reason phase8_cohort_a_owner_stop_before_warp_complete \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id SUCCESSOR_RUN_ID \
  --confirm-cohort
python3.12 -m collector.cli validate
```

The owner must attend and review coverage, budgets, scan errors, catalog/card semantics,
parent/component parity, citation quality, existing-library regressions, sizes, and checkpoint
privacy before any commit/push. Cohort A cards are current; skipped active cards are explicitly
`not_collected`/`not_evaluated` with null counts. Revalidated V1 evidence at the skipped boundary
is stale/carried-forward/as-of history, never current visibility or count authority. Detailed
acceptance and rollback commands are in
`docs/Documentation.md`.

Only after that release is accepted may scheduler credential behavior be tested from its
non-interactive context and arming be discussed. No scheduler definition is
installed or bootstrapped by this repository.

The active checkpoint continuation uses 14 normal workers and durable per-repository commits. Its
38,358-repository production queue demonstrated that the original 36-hour wall was a sizing miss,
not an evidence failure. The owner authorized a run-local seven-day ceiling. The supported
`run-wall-extend` control can be applied only after the live coordinator releases its lock; it
charges the elapsed segment, changes only `max_wall_seconds` among budgets, proves
discovery/metadata AST equivalence, leaves the 60,000 dispatch/fetch, 20,000 GitHub, GraphQL reserve, disk, RSS,
per-repository, OpenAlex, and citation limits exact, and preserves every compatible task.
At the same safe boundary it may apply the separate owner-approved, fingerprinted exact
`.buildozer/` directory-segment exclusion. That monotonic filter drops generated Buildozer output
from materialization and all classification bands while retaining `buildozer.spec`, lookalikes,
and authored source outside the directory. Its certificate proves no completed result depends on
the excluded path and permits a reset of only the failed `Silian1234/shootAnalyzer` task.
The owner granted standing approval for equivalent narrow generated-output incidents when the
same exact-boundary, false-evidence, regression, compatibility, and single-task-retry proof is
available; that approval does not permit broad ignore patterns or unrelated resets.

Failures are handled outside the untouched queue. New work continues at 14 workers; previously
attempted tasks run later in a two-worker issue lane. Fully accounted typed transient failures may
receive a bounded targeted reset under the unchanged dispatch/materialization budgets. Each exact
token-negative malformed-notebook blob has a frozen public identity/HEAD/path/OID/SHA-256 contract and a live
proof that none of all 169 CUDA-X retention literals occurs in authored surfaces (including JSON
escape-aware checks and output/base64 exclusion). Only those exact tasks may receive the certified
fast-negative treatment, at one worker; every other malformed notebook remains fail-closed, and
publication verifies the proof/result hashes. Missing current-tree objects are typed as retryable
cache-integrity incidents rather than detector verdicts. No compatible completion is invalidated
or replayed by these controls.
Exact macOS `errno=1` worktree-read incidents receive a separate proof: current public identity and
HEAD, exact small non-LFS Git blob, and no checkout filter or working-tree encoding. Only those
paths may read the local Git blob during their one-worker retries; publication verifies the
certificate and recovered result hashes.

The later audited scanner-source migration has its own one-time retry control. It requeues only
the four exact failed identities whose durable diagnostics are corrected by the reviewed
`.virtual_documents/`, internal manifest-symlink, non-regular LFS index-mode, and raw
NUL-delimited tree-path changes. It proves the migrated 38,321-task universe, complete attempt
usage, unchanged compatible completions, unchanged hard budgets, and a control-plane-only source
delta before granting one additional attempt per identity. Malformed TOML, generated checkout
paths, `.lfsconfig`, public-visibility incidents, and LFS hard-limit failures stay fail-closed.
The same control uses ordinary compatible-resume semantics to close the exact stale
`DeNA/DeClang` coordinator attempt as usage-unknown/never-zero without granting another attempt,
and the all-task re-key certificate keeps already approved buildozer and typed-issue retries
durable across that recovery.

Two later resume defects are control-plane-only. A closed interrupted attempt whose usage is
explicitly unknown remains charged and may consume only its existing retry, while terminal failed
tasks stay publication blockers and are never sent back through the lease path ahead of durable
pending work. Because the second correction changes the reviewed pipeline source hash, the
one-time `run-scanner-resume-control` certificate is required before the same run can continue.
It binds the exact three-commit source chain and changed-path set, keeps the original scanner
migration certificate intact, and hashes all tasks, attempts, scan results, pre-existing stages,
fingerprints, and budgets before and after changing only the run plan's source identity. It resets
zero tasks, changes zero results, preserves the exact 38,321-task status distribution, requires no
running leases, and cannot authorize a detector, evidence, privacy, or budget change.

The owner later stopped the bounded retry tail at the exact durable boundary of 37,987 completed,
278 failed, 55 pending, and one expired running scan among 38,321 tasks. The last successful
checkpoint was `steleman/llvm-21.1.8`; the coordinator then exited during attempt 2/2 of
`Abdulwadoodd/llvm-apex`. The incident-only scan-tail control closes that attempt as
usage-unknown, preserves every result and attempt identity, converts only the unresolved task set
to terminal deferred failures, and writes an ignored future-work repository note. No deferred
repository can contribute a current count or clean rejection. The resulting Cohort A candidate is
explicitly incomplete by 334 owner-deferred repositories, even when all downstream OpenAlex,
visibility, privacy, artifact, and semantic V1/V2 reconciliation gates pass. The owner later
accepted that partial boundary for release `2ccb121ad90b2624dbdf`; automated collection stays unarmed.

The first downstream resume then failed before OpenAlex because the quarantine helper required
every deferred repository to remain present with a current grouped-library set no broader than its
immutable task payload. That assumption is not stable: current public metadata may already omit a
deferred repository, and compatible completed scans may add cross-library groupings. The narrowly
chained `run-scan-tail-resume-control` changes only this grouping compatibility rule. Exact task,
repository, node-ID, and pinned-HEAD proofs remain fail-closed; every currently grouped library for
the deferred repository is removed wholesale. The failed resume had also reopened 55 certified
deferred tasks through the generic interrupted-attempt disposition. The same narrow certificate
re-terminalizes only those exact pending members, then makes every future resume preserve the
whole deferred set. The 37,987 completed tasks and all attempts, results, pre-existing stages,
fingerprints, and budgets remain unchanged, with zero scan work authorized.

That controlled resume completed aggregation and the OpenAlex refresh, then universal staging
failed before installation on three exact publication-semantics defects. Confirmed component
evidence had correctly raised 9 cuBLAS, 16 cuFFT, and 14 cuSPARSE repositories into their unique
parent-family cards, but an existing weaker targeted parent row still won in the emitted shard.
The materializer now applies the documented one-classification precedence rule and promotes that
parent row to confirmed while preserving its former classification as audit provenance. Public
discovery quality now contains only terminal complete certificates; incomplete advisory
Sourcegraph observations remain durable internal discovery/stage diagnostics and never appear as
coverage authority. The validator also treats an owner-deferred tail as incomplete even when no
large source file was skipped. The first pass also exposed a generic replanning defect: removing
the 334 quarantined repositories from the active grouping caused `supersede_tasks` to overwrite
their terminal failures with completion markers. The follow-up fix preserves the certified
immutable scan universe whenever a tail-deferral certificate is active. The incident-only
`run-downstream-resume-control` binds the exact two-commit source delta and, using an independent
read-only pre-supersession snapshot, proves identical scan identities, attempts, results, and
deferral evidence before restoring only those 334 failure documents. It then binds the repaired
37,987/334 partition, refreshed citation cache, unchanged fingerprints/budgets, and zero new
network or scan authorization before the same run may resume staging and the offline V1/V2 audit.

The first complete final-visibility pass then found exactly one formerly public stable node was
now `missing`; the task journal retained no repository name or private metadata and publication
failed before installation. The normal failed-visibility resume is supposed to force current
metadata, but the immutable preseeded-metadata certificate incorrectly took precedence and reused
all 774 historical batches. The visibility-resume correction makes the failure-triggered refresh
authoritative, creates a new `fresh:` metadata epoch, and makes later crash recovery select only
the newest fresh epoch rather than combining it with historical complete tasks. Its incident-only
control binds the sanitized missing-node hash and exact 199-complete/92-pending visibility batch
partition while preserving every scan, citation, fingerprint, and budget row.

The first fresh epoch stopped at 654 complete and 121 pending batches because the conservative
GraphQL ledger counted the same 774 preseeded calls both in immutable task documents and in
`historical_graphql_usage`. The GraphQL resume control hashes that exact embedded result universe,
deduplicates only that accounting representation, and resumes the same 16-character fresh epoch.
Raw accounting was 2,401 points; reconciled durable usage was 1,627, leaving the pending metadata
and a full visibility epoch within the unchanged 2,500-point ceiling.

The completed fresh epoch then removed 34 no-longer-public identities, cascading 18 completed and
16 deferred scan tasks by privacy design. Of 38,287 surviving scan tasks, 1,499 had newer current
heads and 16 had public renames. The privacy reconciliation control proves those exact deltas from
the independent pre-refresh state, retains the remaining 37,969/318 scan partition, and pins
surviving evidence to its scanned head with zero new scan authorization.

After the owner stopped further retries, eight genuinely new public candidates introduced by the
fresh epoch were deferred without creating scan tasks or changing the immutable universe. The
next downstream pass completed aggregation and OpenAlex, but correctly found that the older
partially completed final-visibility epoch described the pre-privacy candidate set. A generic
resume-selection defect treated the completed fresh *initial* metadata epoch as permission to
reuse that incompatible failed final epoch. The incident-only visibility-set control binds the
exact 775-batch fresh metadata epoch, the prior 199-complete/92-pending visibility epoch, the full
post-citation durable state, and a one-commit source correction. It changes no task, citation,
scan result, attempt, fingerprint, or budget. The resumed pipeline plans a new final attestation
from the privacy-reconciled candidate set and supersedes the old epoch through normal journaled
task semantics before the V1/V2 and owner gates.

That replacement epoch then found one further availability change: one stable node returned the
sanitized `missing` result after the completed fresh metadata epoch. Because the earlier
missing-node certificate precedes the later GraphQL, privacy,
fresh-candidate, and visibility-set controls, it cannot be replayed or inserted into that immutable
source chain. The post-supersession visibility-rejection control binds only the newest
44-complete/247-pending epoch, hashes the single missing stable node, and authorizes a new fresh
metadata epoch while proving zero scan, citation, fingerprint, or budget changes. Historical
visibility epochs remain durable but are excluded from the incident partition.

The first forced refresh then exposed a second precedence edge: the older GraphQL partial-epoch
certificate supplied its already-completed 16-character epoch to what must be a new refresh. The
changed lookup plan enqueued 775 collision-pending tasks under that old epoch and failed before
leasing any task or making any request. The visibility-refresh control binds the exact 775 prior
complete/775 collision-pending partition and hashes the new task set. Its source correction makes
forced refresh authoritative over prior partial-epoch recovery, preserving all collision tasks
until the normal new-epoch plan supersedes them.

The unchanged GraphQL journal then held 1,792 of 2,500 points. Repeating 775 metadata requests and
291 final-visibility requests could not complete within that cap. The chained visibility-budget
control therefore uses the GraphQL client's existing 100-lookup maximum only for this reviewed
cohort: the exact refresh becomes 388 requests and the unchanged final attestation remains 291,
for a projected unit-cost journal total of 2,471. The control changes no budget, task result,
scan evidence, or citation cache, and real response costs remain subject to the same fail-closed
2,500-point gate.

The first retry invocation exposed one more selection edge: forced refresh planned a replacement
epoch rather than resuming the current certified epoch. It was stopped after 10 successful
redundant calls and one interrupted call. The epoch-recovery control compares the live task rows
to the retained pre-retry state, restores only the original 199 pending rows, retains all 10
replacement results, reserves the interrupted point, and explicitly selects the original epoch.
The complete projected charge is 2,483/2,500.

The completed recovered epoch then proved one additional formerly public scanned repository was
now missing. Public-only persistence correctly removed its repository, three candidates, three
scan results, two analysis rows, and completed scan task before the scan-bound count guard stopped
the coordinator. The post-refresh privacy control compares that state to the retained pre-refresh
database, binds the missing response and every purged evidence hash, proves all 38,286 surviving
scan tasks semantically identical, separately binds the expected resume-time timestamp refresh on
the 318 owner-deferred tasks, records 1,538 head pins plus 16 scan-bound renames, and binds all
eight stopped fresh-candidate task keys to their proof-era heads from the immutable pre-refresh
reference. This last proof prevents later public HEAD movement from turning an authorized deferral
into new scan work or from depending on incidental historical scan rows. It grants no metadata
request or scan attempt.

At fresh-metadata batch 189, GitHub returned malformed JSON. The journal retained that exact task
as pending at attempt 1/3, but the response could not prove its rate-limit cost. The chained
transport-retry control therefore reserves one conservative point for that single unobserved
response before replay. The projected completion total becomes 2,472/2,500; scans, citations,
completed metadata, and the hard budget remain unchanged.

### Cohort A candidate-identity and scanner recovery

The first Cohort A scan plan was rejected before publication. Certified discovery held 37,644
unique repositories, but only 10,115 reached the scan queue because GitHub's older base64
repository node-ID strings in discovery did not string-compare equal to the newer opaque node IDs
returned by the successful metadata epoch. The old admission code took the node lookup
exclusively and never fell back through the already-resolved repository name. This was an
illegitimate completeness loss, not filtering.

The corrected contract treats current public GitHub metadata as canonical identity, permits an old
node-ID observation to fall back through its exact requested/canonical name, preserves rename
aliases, and fails closed on every name/node/alias collision. The audited 28-library derivation is
now 155,861 observations, 37,644 unique discovery repositories, 38,698 exact metadata
lookups/results, 38,383 publishable metadata repositories, 38,358 admitted candidates, and 57,267
repository/library pairs before scanning. The 465 completed predecessor scans legitimately added
86 cross-library pairs on repositories already in the certified set, so the reviewed successor
contains 57,353 pairs while the repository count remains 38,358. The immediately preceding
fingerprint epoch had 805 reusable pairs and 38,142 predicted repository scans. The content
remediation below invalidates every old detector verdict, so the reviewed successor must reuse zero
predecessor scans and plan 38,358 unique repository scans. With 517 predecessor dispatches charged,
the lineage total is 38,875 against the frozen 60,000 scan/dispatch limit, enforced in both
successor preflight and runtime.

The stopped predecessors exposed generic `scan_error` rows, history-heavy timeouts, and four
content failures after 465 completed scans. Worker failures now retain bounded typed diagnostics;
retryable transport/cache/timeout failures get one evidence-safe retry, while detector, content,
and resource defects fail without blind replay. Every scan lease has an immutable attempt row with
complete timing/network/materialization accounting; attempts remain monotonic across retry. A
closed retryable coordinator interruption is charged explicitly as usage-unknown and may use only
its existing compatible retry; other incomplete usage blocks recovery instead of being counted as
zero. These changes plus the
shared content parser intentionally change every detector fingerprint, so none of the 465 completed
scans is eligible for inheritance.
Compatible resume sends only durable pending tasks to workers. Terminal failed tasks remain
unresolved publication blockers while independent pending retries continue; they are not blindly
redispatched through the lease path.

The successor nevertheless charges every predecessor dispatch. The immutable historical contract
contains 517 attempts: 503 exact result rows and 14 interrupted pre-v5 attempts. Exact usage records
45,373,367,985 materialized bytes; public metadata plus exact-HEAD cache receipts provide a
23,398,196,224-byte conservative upper bound for the unknown attempts. The successor therefore
starts with 68,771,564,209 bytes and all 517 dispatches already charged. Unknown timing, Git,
clone, and fetch counts remain labeled unknown. No predecessor verdict or attempt row is copied.

The supported `run-cohort-recovery-successor` path inherits and revalidates the exact 134
discovery tasks and 774 complete metadata batches, reconstructs coverage only from the current
28-library task universe, charges all lineage usage, refuses scan reuse, and rechecks the frozen
metadata task/result/input-context hashes at runtime. The predecessor must be backed up and
explicitly abandoned first. The attended run then uses `cohort-reconcile` and still stops at the
V1/V2 review and explicit owner-acceptance gate. Candidate `data/` is not committed or pushed, and
automated collection stays unarmed.

The first content-remediation successor was abandoned before network work because its displayed
fetch preflight omitted the 517 historical attempts even though its immutable runtime contract
retained them. The supported `--preflight-budget-remediation` mode chains through that abandoned
no-scan successor, preserves unchanged fingerprints and certified tasks, and fail-closes unless
the preflight reports and enforces all 38,875 lineage dispatches.

The first identity-recovery successor exposed a missing `re` import in the immutable
preseed-contract validator before it acquired the network lock or created scan work. The supported
recovery command therefore has a narrow `--control-plane-remediation` mode: it proves the source
change is import-only, refuses any predecessor with completed scans, preserves the frozen detector
fingerprints, charges the complete chained lineage, and seeds a fresh immutable successor instead
of editing the failed run in place.

The first scan batch then found that a public repository's irrelevant 53 MB executable was tracked
through Git LFS and its owner had exhausted the LFS quota. Later scans exposed LFS pointers on
potential detector surfaces plus two standards-recoverable notebook cases. The reviewed
`evidence-content-and-attempt-diagnostics` successor keeps discovery/metadata execution exact and
inherits those certified tasks without network replay. It uses one fail-closed notebook parser
across current/history paths, establishes LFS relevance from the requested libraries and certified
classification bands, and permits only exact bounded unauthenticated objects from the canonical
public GitHub origin. SHA-256 and size are verified. A hydrated negative may complete; a hydrated
positive remains `repository_content_unavailable` because historical LFS bytes cannot yet support
first-adoption proof. Unrelated pointers and exact timestamped copied clone snapshots cannot block
or establish adoption. Valid LF/CRLF pointers are recognized; effective local/worktree endpoint,
transfer, URL-rewrite, and auth overrides are refused. LFS relevance is derived from the exact
classifier surface, decoded notebook cells cannot hide terms behind JSON escapes, and admitted
`environment*.yml`/`.yaml` variants are parsed consistently with discovery.

The next attended scan exposed two narrower production-corpus defects and was stopped after 37
exact completions rather than allowed to accumulate unusable work. One valid UTF-8 notebook had a
single trailing comma inside ignored metadata; two other valid JSON notebooks contained literal
escaped control/replacement characters in authored strings that the parser incorrectly treated as
decode damage. The replacement contract is deliberately not JSON5: only trailing commas inside
metadata/output descendants are repaired, with length-preserving whitespace, followed by a full
strict parse; root/cell/source syntax remains fail-closed. Strictly decoded authored characters are
preserved exactly, while actual tolerant-decode damage in authored content remains fatal. A
separate exact-timeout failure proved that the scanner deadline's `TimeoutError` could be caught as
an `OSError` during the LFS probe and mislabeled as a detector defect; the probe now propagates that
deadline so the existing single bounded retry policy applies. The audited
`strict-notebook-recovery-and-deadline-propagation` successor changes every detector fingerprint,
inherits no scan verdict, and can reuse only the already certified discovery/metadata documents.
Its first successor is currently blocked before any network restart: the abandoned predecessor
contains 49 exactly closed scan attempts and 14 active attempts whose identity and abandonment are
durable but whose worker-local Git/materialization high-water usage is not. Later cache receipts
are demonstrably insufficient (including a zero-byte receipt beside a 477,391,366-byte bare cache
and one missing cache), and this predecessor can hydrate bounded public LFS. Counting those attempts
as zero or treating GitHub `diskUsage`/current cache size as a cumulative ceiling would weaken the
frozen budget contract, so the supported gate refuses to create the successor pending an
owner-approved, validated recovery policy. No collection is running.

The bounded production-corpus checks now behave as intended: the malformed 16.5 MB notebook
recovers only authored cells and contains no cuTENSOR signal; the Python-shebang `.ipynb` is parsed
as valid Python and its actual cuQuantum declaration remains available elsewhere; and five exact
public LFS Python objects in `lumc01/Lumvorax` hydrate with verified certificates yet produce no
current cuQuantum/cuBLAS/cuRAND/cuTENSOR classification. These are validation probes, not a
collection run.

## Scheduling and ownership

- The maintainer's Mac is the sole collector host because it can reliably clone github.com and reach the
  free discovery/research sources.
- Prior non-canonical collection hosts and CI collection schedules were removed
  after transport failures risked undercounts. CI runs source validation only.
- No host-specific scheduler definition is published or armed.
- GitHub credentials are not a capability blocker, but public-only fail-closed behavior remains
  mandatory even when the Mac credential has broad scopes.

## Hard-won lessons

- **Current Phase 8 checkpoint continuation.** The owner-approved successor preserves 134
  certified discovery tasks, 774 metadata tasks, and all 37 compatible completed scans. The
  completed-scan certificate covers 237 result rows, 421 candidate postimages, 14 analysis rows,
  and exact old/current parser equivalence for 181 eligible notebook blobs. It records 14 prior
  interrupted attempts as usage-unknown, never zero; known bytes and all 580 historical dispatch
  identities remain charged. That recovery set was attempted first; the current production scan
  now checkpoints each additional compatible repository while the untouched queue continues at
  14 workers. Typed failures are isolated for bounded later remediation instead of stopping or
  slowing independent first attempts. The final V1/V2 audit and owner-acceptance gate closed for
  release `2ccb121ad90b2624dbdf`; automated collection remains unarmed.

- **Precision is the trust keystone.** Confirmed own-source evidence is the headline. Weaker or
  unevaluated signals must be labeled honestly.
- **Coverage failure is not zero.** A capped/incomplete/skipped source epoch blocks publication.
- **Search indexes vary.** Durable candidates and independent coverage sources absorb index churn;
  large unexplained membership changes still require review.
- **Global invalidation does not scale.** Per-library fingerprints separate detection work from
  release-date, aggregation, citation, and presentation changes.
- **Operational failure is not a clean reject.** Timeouts, clone corruption, and unresolved
  metadata remain retryable and cannot silently remove last-good evidence.
- **Public visibility must be explicit.** Credential scope is never used as evidence of
  publishability.
- **Partial publication is worse than no publication.** Stage, validate, content-address, and move
  the manifest last.
- **Citation freshness differs from adoption freshness.** Carry-forward is permitted only with
  explicit stale/coverage state.
- **Scheduling must have one owner and one host.** Never recreate CI collection or
  alternate-host scheduling, and never arm automated collection before the reviewed first reconcile.
- **Do not convert design targets into claimed results.** REQ-14 has offline
  code/fixture/browser acceptance and an accepted partial Cohort A production
  boundary; full-portfolio performance, recall, and adoption remain pending.
- **A final-visibility rejection remains a privacy boundary.** The Phase 8 continuation may purge
  one proof-bound newly missing stable node and preserve compatible completed attestation batches,
  but only through the incident-specific reviewed control. It cannot revive the repository, rerun
  stopped scan retries, or publish before owner acceptance.
- **Detector evidence is an approval artifact.** Keep
  `collector/req14_evidence_contract.json`, `docs/REQ14-PHASE8-READINESS.md`, and
  `ops/req14_detector_fingerprints.json` aligned; an ambiguous library/band remains
  `not_evaluated`.

## Other roadmap context

- **Future requirement candidate — investigate and validate V2 discovery-efficiency
  improvements.** Treat the production observations below as hypotheses, not committed
  implementation decisions. The complete incident ledger, research questions, failure matrix,
  and unattended acceptance gates are maintained in
  [`REQ14-V2-REVISION.md`](REQ14-V2-REVISION.md). Run a bounded research spike that measures current request/runtime
  concentration by library and query pack, then evaluates:
  (a) whether band-aware discovery can restrict broad anchors such as cuSPARSELt to the frozen
  qualifying source surfaces and exact signals without losing any positive or hard-negative
  coverage; (b) whether Sourcegraph and GitHub lanes, or independent GitHub work, can overlap
  safely under one centrally enforced pacing, quota, privacy, and fail-closed contract; and
  (c) whether independently complete, disjoint GitHub search partitions and their public-only
  observations can be checkpointed so a compatible retry avoids replaying the full lane. The spike
  must also (d) evaluate durable, low-noise intra-task progress observability so an attended run can
  distinguish useful progress, intentional pacing/backoff, and a stalled task without waiting for
  the task's terminal result. Candidate telemetry includes completed/total partitions, current
  source or phase, request-attempt counts, last useful activity, and active pacing/backoff state.
  It must be safe across restarts, expose no credentials or non-public payloads, add negligible
  request/runtime overhead, and never let partial-progress telemetry satisfy a completeness or
  publication gate. The overall spike
  must compare alternatives against the current implementation using production-shaped fixtures
  and bounded live probes, quantify runtime/request savings and recall/precision effects, and
  explicitly recommend adopt, modify, or reject for each idea. Any checkpoint prototype must never
  persist an incomplete pagination sweep or combine partial attempts; reuse must require the
  identical query/discovery fingerprint, execution contract, visibility rules, and bounded
  coverage epoch. No proposal may weaken the final zero-gap coverage certificate, public-only
  boundary, classification meanings, or publication gate.
- **REQ-14 follow-up evaluation — retain or retire Sourcegraph.** After the first accepted
  production reconciliation and enough weekly epochs to measure its behavior, compare
  Sourcegraph-only candidates that survive classification against its incomplete-epoch rate,
  latency, request volume, and maintenance complexity. GitHub remains the coverage and retirement
  authority during the evaluation. Keep Sourcegraph only if it contributes material unique,
  accurate recall at zero cost without weakening publication guarantees; otherwise remove the
  integration and its operational complexity.
- REQ-12 remains the future purpose-built CUDA-X collection-platform handoff. Shared runners are
  not that platform; the Mac remains authoritative until another host is proven.
- Framework/transitive adoption is deliberately deferred after direct integrations.
- REQ-15 version tracking is mirrored but not implemented.
- `origin/wip/targeted-genuine-reference` remains an unvalidated legacy NVSHMEM experiment. Do not
  merge it without a reviewed detector/fingerprint decision.
- Later phases cover API-consumption intelligence, dependency maps, download reporting/API/CLI/MCP
  consumers, issue/forum/internal signal aggregation, JTBD, and proactive change flags.

## Stakeholders

- CUDA-X library product and engineering teams
- Developer-experience teams
- Maintainers of approved downstream consumers
- Public contributors and users of the generated data
