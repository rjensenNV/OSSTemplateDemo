# CUDA-X Developer Intelligence — Mac Maintainer Documentation

This is the operating runbook for the maintainer-controlled Mac that serves as
the sole collector host. The project maintainer owns operation. `AGENTS.md`,
`docs/PROJECT-CONTEXT.md`, `docs/REQUIREMENTS.md`,
`README.md`, and `refresh.sh` are the companion sources of truth.

REQ-14 Phases 0–7 are implemented and validated through deterministic fixtures, failure injection,
offline V1-to-V2 migration parity, a real-browser lazy-loading check, and a bounded
credential-free public-repository benchmark. The public source snapshot contains no generated
adoption or citation result set. Do not infer full-catalog recall, runtime, cache efficiency, or
counts from the source. No host-specific scheduler is published or armed.

## Architecture and repository map

- `collector/cli.py` is the supported command surface.
- `collector/planner.py` and `fingerprints.py` compute local work, budgets, and granular
  invalidation before a network call.
- `collector/pipeline.py` coordinates discovery, metadata, persisted candidates, scanning,
  citations, portfolio materialization, validation, publication, and checkpoint export.
- `collector/catalog.py` defines 65 portfolio entities: the 2026-07-27 49-entry first-party CUDA-X
  catalog, 14 component rows (13 active plus preview cuSPARSEDx), and retained NVPL/ovrtx.
- `collector/portfolio.py` preserves component rows/history, emits honest metric-pending cards,
  and derives unique-repository parent-family rollups.
- `collector/discovery/` implements Sourcegraph streaming discovery and recursively partitioned
  GitHub code search. Each query/partition emits a coverage certificate.
- `collector/github_client.py` and `http_transport.py` batch GitHub GraphQL metadata/HEAD
  resolution, enforce explicit public visibility, retain quota reserve, and bound retries.
- `collector/state.py` owns the ignored `.state/collector.sqlite3` transactional database in WAL
  mode. It stores repositories, library fingerprints, candidates, results, repository analysis,
  tasks, coverage, citation cache, runs/stages, and releases.
- `collector/repo_cache.py`, `triage.py`, `scan.py`, and `scanner_v2.py` provide the bounded
  partial-clone cache; bare `ls-tree` plus batched checkout-filter-aware `cat-file` for the primary
  direct-negative path; isolated worktrees for mature/positive work and correctness-sensitive
  fallback; one-fetch mature hydration; blobless positive history/dating; AI/CFF enrichment; and
  deterministic worker assembly.
- `collector/citation_pipeline.py` is the supported cached OpenAlex/CFF stage.
  `collector/citation_extract.py` is its bounded public arXiv/PDF repository-link extractor,
  without GitHub credentials or publication capability. `collector/citations.py` is a refusal
  tombstone, not a runnable citation writer.
- `collector/publish_v2.py` builds content-addressed library/citation/export artifacts in staging
  and publishes the manifest last. `collector/validate_v2.py` validates every referenced schema,
  byte count, SHA-256, row count, privacy assertion, duplicate, and aggregate.
- Historical V1 migration/reference helpers remain for fixture-based offline comparison. Generated
  V1 snapshots and V2 output are excluded from the public source snapshot.
- `data/state-checkpoint/` is a deterministic, sharded reconstruction checkpoint created by a
  genuine local reconciliation. Like all generated `data/`, it is local and ignored. `.state/`
  and its Git cache are also local and ignored.
- Runnable V1 writers do not remain; the supported command surface is `collector.cli`.
- `.github/workflows/tests.yml` is the public source-validation path. It does not collect or
  validate a bundled result set.

## Mac prerequisites

- Clean collector checkout on `main`
- Homebrew Python 3.12:
  `/opt/homebrew/opt/python@3.12/libexec/bin/python3`
- `/opt/homebrew/bin/gh` authenticated to GitHub; `refresh.sh` obtains `gh auth token`
- `/usr/bin/git`, CA certificates, and access to GitHub API, github.com, Sourcegraph, and OpenAlex
- mode-600 `~/.config/openalex-api-key` or `OPENALEX_API_KEY`
- Credential-helper access that can fast-forward `origin/main`
- Sufficient local disk for the 200 GiB target / 250 GiB hard Git cache

There are no third-party Python package dependencies.

The GitHub credential may have broad scopes, but broad scope is not publication authority.
Discovery observations, GraphQL metadata, SQLite admission, scan materialization, checkpoint
export, and V2 validation all fail closed for private or unresolved visibility. Private names and
paths must not enter output, checkpoints, or diagnostics.

## Command contract

All global flags such as `--state`, `--cache`, and `--data` precede the subcommand.

### `plan`

```bash
python3.12 -m collector.cli plan --json
python3.12 -m collector.cli plan --mode reconcile --json
```

The planner reads local configuration, SQLite, and local generated data when present. It performs no network
calls and no production writes. It reports cold/warm state, fingerprints/invalidation reasons,
known repository counts, estimated scans/API work/wall time, and local disk. A refresh plan that
requires unbounded invalidation explicitly directs the operator to an attended reconcile.

### `refresh`

```bash
python3.12 -m collector.cli refresh
```

This is the bounded weekly incremental. It uses six scan workers by default and refuses work above
its wall/API/scan/fetch/quota/disk budgets. It never silently becomes full. `refresh.sh` wraps this
command with clean-main and fast-forward checks, GitHub credential acquisition, and local V2
validation. It never commits or pushes generated data.

### `reconcile`

```bash
python3.12 -m collector.cli reconcile --confirm-full
```

This is the only all-library cold/full path. It requires the explicit confirmation flag, defaults
to fourteen scan workers, applies attended reconciliation budgets, and holds a Mac `caffeinate`
assertion for the coordinator lifetime. It is not called by `refresh.sh` or an automated scheduler.

### `onboard`

```bash
python3.12 -m collector.cli onboard --libraries cublas cublaslt
```

Onboarding uses the same discovery, state, scan, aggregate, citation, portfolio, and publication
engine. Discovery and new scanning are limited to the named libraries, while output is
materialized from complete shared state, so unrelated libraries cannot be wiped. The entire
`collector.run` command and `onboard_merge.py` are retired compatibility tombstones; they must not
be used for REQ-14 work.

### `compare` and `validate`

```bash
python3.12 -m collector.cli compare
python3.12 -m collector.cli validate
```

`compare` currently runs deterministic scanner and portfolio fixtures only. Passing
`--repositories` is deliberately rejected; it does not imply network access. `validate` checks
the current `data/v2/` release without collecting.

### Reviewed discovery scope-reduction successor

`run-successor` is an incident-only, no-network control path for an explicitly abandoned
reconciliation whose approved discovery scope has become a strict subset:

```bash
python3.12 -m collector.cli run-successor \
  --predecessor-run-id RUN_ID \
  --scope-reduction-library LIBRARY_ID \
  --reason MACHINE_READABLE_REASON \
  --confirm
python3.12 -m collector.cli reconcile --confirm-full
```

It refuses scope expansion, unrelated fingerprint changes, a changed base release, changed hard
budgets, or a changed network-task executable hash. It creates a clean successor with recorded
lineage and inherits only exact completed task keys and canonical payloads whose documents pass
the current schema/query/public-only checks. Required GitHub results must be terminal, complete,
uncapped, gap-free, and unquarantined. Advisory Sourcegraph results must be terminal; retained
gaps and quarantine remain visible diagnostics. Every inherited task records its predecessor,
payload/result hashes, executable hash, source policy, and inherited request usage. Coverage is
reconstructed only from validated results in the successor task universe.

### Reviewed network-execution successor

When production exposes a transport or equivalent query-execution defect, never edit the network
path and resume under the old executable hash. Stop and explicitly abandon the predecessor,
implement and validate the remediation, commit it on clean `main`, then prepare an audited
same-universe successor:

```bash
python3.12 -m collector.cli run-transport-successor \
  --predecessor-run-id RUN_ID \
  --predecessor-source-ref COMMIT \
  --historical-github-request-attempts N \
  --reason MACHINE_READABLE_REASON \
  --confirm
python3.12 -m collector.cli reconcile --confirm-full
```

The source ref must reproduce the predecessor's recorded executable and be an ancestor of clean
current `HEAD`. The command permits only the reviewed remediation source surface; it requires an
identical discovery task universe, canonical payloads, library fingerprints, base release, and
hard budgets. It records both old/new full executable and transport-source hashes, re-runs
document/schema/query/public-only assertions, and preserves chained task provenance. Required
GitHub results remain terminal, complete, uncapped, gap-free, and unquarantined; advisory
Sourcegraph gaps remain visible diagnostics. A query-decomposition remediation additionally
records a deterministic proof that every exact member query reconstructs the unchanged logical
`OR` pack and its fingerprint.

Fresh HTTP attempts—including retries and failed attempts—are journaled per discovery-task
attempt and debited on restart before a new socket. Inherited certificate request counts and the
explicitly reviewed historical charge are each debited once, never summed again across lineage
hops.

### Reviewed Phase 8 partial-cohort successor

`run-cohort-successor` is the incident-only control path for the owner-approved Phase 8 product
boundary. Stop the all-library coordinator, back up state, and explicitly abandon that run. A
partially attempted product is excluded in full: its network attempts remain charged, while none
of its task result, observations, partitions, or coverage can be inherited. Commit the reviewed
cohort implementation on clean `main`, then derive and seed the successor:

```bash
python3.12 -m collector.cli run-cohort-successor \
  --predecessor-run-id RUN_ID \
  --predecessor-source-ref COMMIT \
  --reason phase8_cohort_a_owner_stop_before_warp_complete \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id SUCCESSOR_RUN_ID \
  --confirm-cohort
```

The command derives the cohort from exact current-plan tasks; library IDs are not manually
promoted. Every selected library must have terminal, public-only results for its entire task
universe. Required GitHub certificates must also be complete, uncapped, gap-free, and
unquarantined. The successor is a strict subset with no pending discovery work. It revalidates
documents, records chained task/result provenance, charges all predecessor attempts, reconstructs
coverage from selected tasks only, and proves that the discovery-task ASTs and all query/transport
sources stayed exact across the downstream partial-release change.

This began as a reviewed 36-hour attended reconciliation with the normal 60,000 scan/fetch, 20,000
GitHub-attempt, GraphQL reserve, cache/disk, RSS, OpenAlex, and citation-extraction gates. The
production-sized 38,358-repository queue proved that the 36-hour ceiling was too short. The owner
therefore authorized a bounded seven-day ceiling for this run only. `run-wall-extend` proves that
only `max_wall_seconds` changes among budgets, charges elapsed time before restarting the clock
boundary, preserves every completed task and attempt row, and requires an AST audit of exact
discovery/metadata execution. The one owner-approved detector exception may accompany that safe
boundary: an exact `.buildozer/` directory-segment exclusion, certified as a monotonic removal of
generated build output. Its contract proves that the shared filter is the only changed
fingerprint, that no completed positive result cites `.buildozer/`, and that the failed
`Silian1234/shootAnalyzer` tree contains the case-insensitive generated-path collision that caused
the incident. `buildozer.spec`, lookalike names, and authored source outside `.buildozer/` remain
eligible. The other safety budgets remain byte-for-byte equal to the reviewed reconcile defaults. Its
preflight records unique repositories, repository/library pairs, predicted scans after available
filtering/reuse, metadata requests, disk headroom, and every hard budget. The release is labeled
`Phase 8 Cohort A` and `partial-portfolio`; selected libraries are current, while excluded active
libraries are `not_collected` with `not_evaluated` bands and null counts. Revalidated V1 rows may
remain as stale, carried-forward, as-of evidence for audit and export, but never satisfy current
counts, rollups, retirement, citations, or visibility authority.

The running coordinator keeps its original in-memory deadline. Do not edit state or source under
it. At a clean coordinator boundary, commit the reviewed control change, then apply and resume:

```bash
python3.12 -m collector.cli run-wall-extend \
  --run-id RUN_ID \
  --predecessor-source-ref PRE_EXTENSION_COMMIT \
  --max-wall-hours 168 \
  --reason phase8_owner_wall_extension \
  --confirm
python3.12 -m collector.cli run-buildozer-issue \
  --run-id RUN_ID \
  --reason phase8_approved_buildozer_exclusion \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID \
  --confirm-cohort
```

Ordinary scanning stays at 14 workers. Previously attempted failures are deferred to a two-worker
issue lane so retries do not reduce the untouched queue's concurrency. `run-issue-retry` requeues
only fully accounted typed transient/cache/timeout failures, extends only their individual attempt
count, checks the unchanged 60,000-dispatch/materialization budgets, and never resets a detector or
content failure. Exact token-negative malformed-notebook incidents use `run-notebook-issues`: the command
re-attests public repository/head/path/blob identity, re-proves absence of all 169 configured
retention tokens after the shipped base64/JSON-escape rules, scans only those exact tasks with one
worker, and records a publication-gated proof. Every other malformed notebook remains fail-closed.
Neither control replays a compatible completed scan.
The buildozer control requeues exactly the certified `Silian1234/shootAnalyzer` task after the
filter migration; no other failed or completed scan is reset.

After the audited scanner-source migration, `run-scanner-source-issues` may requeue exactly four
production identities whose terminal diagnostics are fixed by that source and no other task:
`qompassai/PathFinders` for the exact generated `.virtual_documents/` notebook,
`albumentations-team/benchmark` for an authored in-repository dependency-manifest symlink,
`lchyeon0123/Kairos` for a pinned non-regular LFS index mode, and
`HackersCardgame/hacker-notes-s24m03` for quoted/backslash paths missed by formatted Git tree
output. The control requires the completed scanner-migration certificate, exact public repository,
HEAD, library, payload, attempt, diagnostic, and complete usage rows; proves that only its retry
control plane changed after the migration commit; preserves the 38,321-task universe and every
completed scan; changes no budget; and grants each identity exactly one further attempt. It does
not cover malformed TOML, generated checkout paths, `.lfsconfig`, visibility incidents, or any LFS
count/size/unavailable hard gate. If the preceding coordinator exited with the exact
`DeNA/DeClang` attempt still running, the control invokes normal compatible-resume recovery before
retry authorization: that one attempt becomes interrupted with usage explicitly unknown, never
zero, and receives no extra attempt after its existing maximum. The scanner migration's all-task
re-key certificate also preserves earlier buildozer and typed-issue retry markers whose attempt
rows correctly retain their pre-migration task keys.

```bash
python3.12 -m collector.cli run-scanner-source-issues \
  --run-id RUN_ID \
  --reason phase8_audited_scanner_source_issue_retry \
  --confirm
```

If a compatible resume encounters the reviewed interrupted-attempt lease guard and terminal-task
dispatch ordering defects, apply the source-only continuation at a clean coordinator/lock
boundary after committing the exact reviewed control lane:

```bash
python3.12 -m collector.cli run-scanner-resume-control \
  --run-id RUN_ID \
  --reason phase8_audited_scanner_resume_control \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID \
  --confirm-cohort
```

This is not a general source override. The certificate requires the exact predecessor and two
orchestration-fix commits plus one clean control commit, the frozen changed-path set, the original
scanner-migration contract hash, identical detector fingerprints, the 168-hour wall with every
other budget unchanged, zero running scan tasks, and exactly 38,321 scan identities. It streams
hash proofs over every task, scan attempt, scan-result row, and pre-existing stage before and after
updating only the execution contract's reviewed network source hash. Any task/result/status,
fingerprint, budget, prior certificate, source-path, or commit-chain difference rolls the change
back and fails closed.

The owner stopped the remaining Phase 8 retry tail after 37,987 of the exact 38,321 repository
tasks completed. The incident-only `run-scan-tail-stop` control closes the one expired coordinator
attempt as usage-unknown, converts only the remaining pending tasks to terminal deferred failures,
and records all 334 unresolved public repositories in an ignored `.state/` note. It creates no
scan attempt, changes no scan result or hard budget, and preserves every compatible completion.
The exact deferred task-key set and repository/head/library proof are embedded in the reviewed run
contract. The downstream candidate quarantines those repositories entirely: their absence is
reported as incomplete owner-deferred scan coverage and can never become a clean rejection or a
zero-adoption assertion. The universal V2 staging gate also runs the semantic V1/V2 reconciliation
before any manifest installation.

At the clean expired-lease boundary:

```bash
python3.12 -m collector.cli run-scan-tail-stop \
  --run-id RUN_ID \
  --reason phase8_owner_deferred_scan_retry_tail \
  --confirm
python3.12 -m collector.cli run-scan-tail-resume-control \
  --run-id RUN_ID \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID \
  --confirm-cohort
python3.12 -m collector.cli validate
```

The final attended boundary remains explicitly partial: 318 repository rows are owner-deferred
future work and cannot contribute a current count, clean rejection, or zero-adoption assertion.
The owner reviewed and accepted the OpenAlex output, V1/V2 deltas, artifact sizes, deferred-tail
boundary, and static privacy/publication validation for release `2ccb121ad90b2624dbdf`. The owner
also explicitly waived a fresh final-visibility/privacy re-attestation for this release; that
waiver is release-specific and does not relax the default pipeline gates.

The optional `run-scan-tail-resume-control` is needed only for the exact post-deferral grouping
compatibility incident encountered by this run. A deferred repository can already be absent from
current public metadata, or compatible completed scans can add cross-library candidate groupings
after the immutable scan-task payload was created. The owner decision quarantines the whole
repository, so the downstream filter removes every current grouping for its exact public
repository identity instead of requiring the current grouping to be a subset of the historical
payload. Current metadata, when present, must still match the task's node ID and pinned HEAD. The
first failed resume also applied the generic interrupted-attempt disposition to the certified tail
and reopened 55 of its tasks. The one-commit source certificate chains from the immutable
tail-deferral source, re-terminalizes exactly those certified pending tasks, and makes future
resume preserve the whole 334-task deferred set. It preserves the 37,987 completed tasks and every
attempt, result, pre-existing stage, fingerprint, and budget row, and authorizes no scan retry or
broader policy change.

The next controlled pass completed aggregation and OpenAlex, then staging failed before install.
The exact semantic reconciliation found 9 cuBLAS, 16 cuFFT, and 14 cuSPARSE repositories where
confirmed component evidence raised the unique parent-family card but an existing targeted parent
row remained in the shard. The corrected materializer applies confirmed precedence to that one
effective parent row and retains the prior parent classification as provenance. Publication now
exposes only terminal complete discovery certificates; incomplete advisory Sourcegraph results
remain in durable internal discovery/stage diagnostics. The scan validator also accepts the
explicitly incomplete owner-deferred tail when `skipped_large_files` is zero. After the reviewed
staging correction and the follow-up deferred-task preservation repair are tested and committed,
apply their exact no-work control. The read-only repair snapshot is required only because the
first failed pass incorrectly superseded the 334 certified deferred rows:

```bash
python3.12 -m collector.cli run-downstream-resume-control \
  --run-id RUN_ID \
  --repair-state .state/backups/PRE_SUPERSESSION_STATE.sqlite3 \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID \
  --confirm-cohort
```

This certificate first proves the independent snapshot has the identical immutable scan universe,
scan-attempt journal, scan results, deferral contract, and repository proof. It then restores only
the 334 generic supersession markers to their prior terminal failure documents and records hashes
of the before, source, and repaired task sets. The pipeline preserves that immutable universe on
future passes. Every candidate, repository, analysis row, discovery certificate, and refreshed
citation-cache entry remains unchanged. The certificate changes no fingerprint or budget and
authorizes zero new scans or network requests. The resumed run must still pass staging, final
visibility, checkpoint privacy, and the offline V1/V2 semantic audit before the owner gate; it
cannot commit, push, or arm automated collection.

If the fresh final-visibility epoch finds an exact stable node has become `missing`, the run fails
before installation and retains only the sanitized node lookup. The incident-only visibility
control proves exactly one such missing result, binds the completed/pending visibility batch
partition, and changes only the reviewed source identity for the fresh-metadata precedence fix:

```bash
python3.12 -m collector.cli run-visibility-resume-control \
  --run-id RUN_ID \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID \
  --confirm-cohort
```

That resume must ignore the historical preseeded metadata epoch, create a genuinely fresh epoch,
and remove the missing identity through the normal public-admission path. Older complete metadata
tasks remain immutable history; later crash recovery selects only the newest `fresh:` epoch and
never merges two epochs. No repository name or private metadata is retained by the control, and
the full final-visibility gate still runs again before any install.

If that fresh epoch reaches the unchanged cumulative GraphQL ceiling because the immutable
preseeded task documents and `historical_graphql_usage` describe the same requests, the exact
accounting control proves the duplicated result universe and resumes only the already-journaled
partial fresh epoch:

```bash
python3.12 -m collector.cli run-graphql-resume-control \
  --run-id RUN_ID \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID \
  --confirm-cohort
```

This does not increase a budget or erase usage. It counts each embedded request once, preserves
every completed fresh batch, and refuses the resume unless the pending metadata plus a complete
visibility epoch still fit inside the reviewed point ceiling.

Fresh metadata may correctly purge identities that are no longer explicitly public and may
observe newer heads for surviving repositories. The privacy reconciliation control compares the
post-refresh database to the independent pre-refresh state, proves the exact purged scan rows,
and pins every surviving repository to its already-scanned head without authorizing a rescan:

```bash
python3.12 -m collector.cli run-privacy-resume-control \
  --run-id RUN_ID --reference-state PRE_REFRESH_STATE --confirm
```

Renames remain public metadata, while scan evidence remains bound to its immutable node and head.
The final visibility epoch still re-attests every output identity.

If the privacy-reconciled candidate set differs from the older partially completed final-
visibility set, a completed fresh initial-metadata epoch must not authorize reuse of the failed
attestation. The exact no-work control binds the completed fresh epoch, the prior visibility
epoch/set and status partition, the post-citation durable state, and the one-commit epoch-
selection correction:

```bash
python3.12 -m collector.cli run-visibility-set-resume-control \
  --run-id RUN_ID --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID --confirm-cohort
```

The control changes only the reviewed source identity. It creates no task or request and changes
no scan, attempt, citation, fingerprint, or budget row. The resumed pipeline plans a new final-
visibility epoch from the current staged repository set and supersedes the incompatible old epoch
through ordinary journaled task semantics before validation or local installation.

If that newly planned epoch itself returns one exact stable node as `missing`, use the chained
post-supersession control rather than reusing either older visibility epoch:

```bash
python3.12 -m collector.cli run-visibility-rejection-resume-control \
  --run-id RUN_ID --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID --confirm-cohort
```

This control selects only the newest epoch, hashes the missing node instead of retaining its name,
and authorizes a fresh initial-metadata epoch. It preserves the scan universe, scan evidence,
citations, fingerprints, and budgets; any additional privacy narrowing still rebuilds the staged
candidate before a new final attestation.

The old GraphQL partial-epoch certificate is valid only for its reviewed refresh. If a forced new
refresh collides with that older 16-character epoch before making a request, certify the exact
zero-request collision and start a genuinely new epoch:

```bash
python3.12 -m collector.cli run-visibility-refresh-resume-control \
  --run-id RUN_ID --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID --confirm-cohort
```

The control requires the old completed and collision-pending task counts to match, proves that the
pending collision tasks have no attempts or network-usage rows, and preserves them until ordinary
task supersession occurs after the new epoch is safely planned.

If the required full refresh would exceed the unchanged 2,500-point journal solely because the
reviewed cohort still uses 50-lookup requests, the incident-only budget control may select the
client's already-supported 100-lookup maximum for this cohort:

```bash
python3.12 -m collector.cli run-visibility-budget-resume-control \
  --run-id RUN_ID --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id RUN_ID --confirm-cohort
```

The control proves the exact lookup count, current journal charge, planned metadata and final-
visibility request counts, and projected unit-cost total. It changes neither the 2,500-point cap
nor any completed evidence; actual response costs remain journaled and fail closed at the same
hard ceiling.

If one such request returns malformed transport JSON, the coordinator fails before reuse. The
incident-only transport retry control binds that one pending attempt and reserves one conservative
GraphQL point before the existing 1/3 task is retried:

```bash
python3.12 -m collector.cli run-visibility-transport-retry-control \
  --run-id RUN_ID --confirm
```

The reserve is included in all later same-run budget checks even after the retry succeeds; it
does not increase the 2,500-point limit.

If a forced resume mistakenly creates a replacement epoch, stop it and use the retained pre-retry
state to restore only the certified pending rows of the original epoch:

```bash
python3.12 -m collector.cli run-visibility-epoch-recovery-control \
  --run-id RUN_ID --reference-state PRE_RETRY_STATE --confirm
```

The control retains every completed replacement response for budget evidence, reserves one point
for an interrupted replacement request, restores no completed result, and makes the original
epoch selection explicit. The normal coordinator then supersedes the replacement pending rows.

If that recovered epoch proves one additional formerly public scanned repository is now missing,
the public-only persistence boundary purges its repository, candidate, scan-result, analysis, and
task rows before the scan-bound count guard stops the coordinator. At that clean boundary, certify
only the exact additional purge against the retained pre-refresh state:

```bash
python3.12 -m collector.cli run-post-refresh-privacy-control \
  --run-id RUN_ID --reference-state PRE_REFRESH_STATE --confirm
```

The control binds the missing metadata response and all purged evidence hashes, proves every
surviving scan task is semantically identical, separately binds the normal resume timestamp refresh
on the same owner-deferred partition, records the new scan-head pin set, and reconstructs every
stopped fresh-candidate task key against its proof-era repository head in the immutable reference
database. It authorizes no metadata request or scan attempt.

macOS may deny a worktree read for a detector-relevant file before the LFS-pointer check. The
`run-lfs-inspection-issues` lane handles only those exact `errno=1` incidents: it re-attests the
public repository, HEAD, path, Git blob OID/SHA-256, small non-pointer bytes, and the absence of a
custom checkout filter or working-tree encoding. It substitutes that exact local Git blob for the
denied worktree read during a one-worker retry, and publication revalidates the task/result proof.
Other paths, blobs, I/O errors, and real LFS pointers remain fail-closed.

### Reviewed Phase 8 identity/scan recovery successor

`run-cohort-recovery-successor` is the supported recovery path for the Cohort A
candidate-identity and scan-runtime incident. It is not a general resume flag. The predecessor
must be stopped, backed up, explicitly abandoned, and sourced from an audited ancestor of clean
current `main`:

```bash
python3.12 -m collector.cli run-cohort-recovery-successor \
  --predecessor-run-id PREDECESSOR_RUN_ID \
  --predecessor-source-ref PREDECESSOR_COMMIT \
  --reason phase8_cohort_identity_scan_remediation \
  --confirm
python3.12 -m collector.cli cohort-reconcile \
  --successor-run-id SUCCESSOR_RUN_ID \
  --confirm-cohort
```

The recovery revalidates and inherits only exact completed discovery and GitHub metadata task
documents. It proves unchanged discovery query execution and metadata serialization/network
semantics, records chained task provenance and result hashes, reconstructs only current-plan
coverage, charges inherited and historical request usage, and verifies the exact preseeded
metadata task/result/input-context universe again when the coordinator resumes. Metadata remains
public-only and collision checked. GitHub's current canonical node ID plus canonical full name is
authoritative; an older discovery node-ID encoding may fall back through the exact requested or
canonical name only when both resolve to that same public repository. Rename aliases are retained,
while node/name mismatches and alias collisions fail closed.

The independently reconstructed identity preflight for the certified 28-library scope is 155,861
discovery observations, 37,644 unique discovery repositories, 38,698 exact metadata results,
38,383 publishable metadata repositories, 38,358 admitted candidate repositories, and 57,267
repository/library pairs before scan work. The 465 completed predecessor scans then admitted 86
additional cross-library pairs on repositories already in that same certified universe, making
57,353 the reviewed successor total without adding a repository. Under the immediately preceding
detector epoch, 805 pairs were reusable and 38,142 unique repositories required a scan. The content
remediation below changes the shared detector fingerprint for every library, so the recovery must
reuse zero old scan verdicts and plan 38,358 unique repository scans. With 517 predecessor
dispatches charged, the lineage preflight is 38,875 planned/consumed dispatches against the
unchanged 60,000 limit; the preflight and runtime gate both enforce that combined total. Any
different identity/repository total, unexplained pair total, nonzero old-detector scan reuse, or
scan total requires review before network work. Retryable
clone/fetch/cache-integrity and per-repository timeout failures receive at most one same-contract
retry; the exact sanitized worker error is durable. Detector defects and resource-limit failures
remain non-retryable. Candidate data remains behind the owner-acceptance gate, and automated collection remains
unarmed.

If the coordinator fails before acquiring the network lock or creating any scan task because the
reviewed preseed-contract validator itself cannot execute, use the same command with
`--control-plane-remediation`. That narrowly reviewed mode accepts only the missing `re` module
import, requires an identity/scan recovery predecessor with zero completed scans, preserves the
unchanged detector fingerprints, and creates a new chained successor. It never mutates an
immutable live run contract or converts partial scan work into reusable evidence.

If a no-network successor is abandoned because its displayed preflight omitted already charged
lineage scan attempts, chain from that immediate predecessor with
`--preflight-budget-remediation`. This mode accepts only the reviewed CLI/successor budget-gate
change and its exact tests/docs, requires zero predecessor scan tasks, preserves detector and
network-task fingerprints, revalidates every inherited discovery/metadata document, and reports
the historical, new, and combined dispatch totals before collection.

If a scan exposes a scanner-only correctness defect after work has begun, use
`--scan-runtime-remediation` only after the predecessor is stopped, backed up, and explicitly
abandoned. The mode requires discovery and metadata network execution to remain exact, audits the
reviewed scanner semantic nodes, invalidates every predecessor scan whose detector fingerprint
changed, and reuses only certified discovery/metadata tasks. Git checkout always skips LFS smudge:
an unavailable LFS object outside detector-relevant paths cannot block a scan, while an LFS pointer
on a detector-relevant tracked path fails closed as `repository_content_unavailable`.
The `evidence-content-and-attempt-diagnostics` profile is the reviewed first Cohort A recovery
contract. It accepts exactly the frozen production-source bytes and support files for that incident,
while separately proving that discovery requests, query plans, metadata requests, serialization,
public-only policy, and task execution ASTs are unchanged. It inherits the certified 134 discovery
tasks and 774 metadata tasks with their lineage, result hashes, and charged usage, but cannot
inherit any predecessor scan because every detector fingerprint changed.

This profile uses one shared notebook parser for bare triage, worktree classification, and history
dating. Strict nbformat JSON remains authoritative. A strict UTF-8 Python file mislabeled
`.ipynb` is accepted only with a Python shebang and successful AST parse. Tolerant JSON recovery is
accepted only when all invalid bytes or unescaped controls are confined to ignored notebook
outputs/metadata; damage to structure, cell types, code, or markdown fails closed. Notebook
retention searches decoded authored cells, so valid JSON Unicode escapes cannot hide evidence.

The follow-on `strict-notebook-recovery-and-deadline-propagation` profile is intentionally separate.
It permits a trailing comma only inside a `metadata` or `outputs` container (or one of their
descendants), replaces only that comma with a space, then requires the ordinary strict JSON parser
and notebook structure validator to consume the complete document. A trailing comma in the root,
cells, worksheets, a cell object, or authored `source` remains invalid; comments, single quotes,
missing commas, and truncation remain invalid. Literal escaped controls or a literal replacement
glyph in otherwise strict UTF-8 JSON are preserved verbatim instead of being mislabeled as decoder
damage, so they cannot join detector tokens. Invalid UTF-8 that reaches authored content still
fails closed. The same profile prevents the repository deadline exception (a `TimeoutError`) from
being caught and relabeled by the LFS file-inspection error path. Both semantics are detector
relevant, so every selected detector fingerprint changes. Ordinary fingerprint reuse remains
forbidden. The owner-reviewed checkpoint continuation is narrower: it may map only an exact
completed task whose source transaction, effective detector fingerprint, public identity, HEAD,
payload, result/candidate/analysis postimages, and local content compatibility certificate all
pass. Uncertified rows are never reused.

The first run needing this profile stopped at that attempt-accounting gate.
Run `20260731T052650Z-cd66b01e` has 63 dispatched scan attempts: 49 have exact durable usage
(37 completed results and 12 terminal failures, totaling 1,073,036,674 materialized bytes), while
14 were active when the supported abandonment closed them as `interrupted`. Their task/payload/
repository/HEAD identity and abandonment reason are exact, but their worker-local Git counters were
never durably closed. Current cache state cannot reconstruct a cumulative high-water mark: one
receipt reports zero bytes beside a 477,391,366-byte bare cache, one interrupted repository has no
remaining cache receipt, and the predecessor could perform bounded public LFS hydration. Therefore
public `diskUsage`, a later cache snapshot, or a guessed clone/fetch count is not accepted as an
upper-bound certificate. The owner subsequently approved the incident-specific checkpoint
continuation: all 14 attempts remain null/unknown (never zero), their dispatch identities consume
the 60,000-attempt budget, and the 69,844,600,883 known historical bytes remain charged. Reports
label the lifetime byte total `not_evaluable`; the known-byte ceiling and every other hard budget
remain enforced. This is not a general incomplete-usage bypass.

The same contract certifies the 37 completed scans without replay. It verifies 237 atomic result
rows, 421 candidate postimages, 14 repository-analysis postimages, and the actual effective
detector fingerprints used by the predecessor. Across the exact 37 HEADs, all 181 unique
detector-eligible notebook blobs are local and the predecessor/current parsers agree on every one;
85 missing notebook paths are all excluded `.ipynb_checkpoints` paths. Certified rows are copied
under successor fingerprints with provenance and original timestamps, creating no new attempt or
usage charge. The 12 failed and 14 interrupted repositories run first; typed transient failures
receive at most the existing second attempt while unrelated scans continue.

Git LFS is detector- and classification-band-aware. An irrelevant pointer is skipped. A relevant
HEAD object is fetched only for an exact supported path from the canonical public GitHub origin,
without a token, credential helper, custom endpoint, `.lfsconfig`, or custom transfer. Object count,
per-object bytes, aggregate bytes, SHA-256, and declared size are all bounded and verified. Both LF
and standards-valid CRLF pointer records are recognized. Effective repository and per-worktree Git
configuration is checked for endpoint, transfer-agent, URL-rewrite, and auth overrides before the
unauthenticated request. Relevance follows the exact executable classifier surface: for example,
direct-only targeted evidence is CMake-only, while admitted `environment*.yml`/`.yaml` manifests are
structurally parsed for bundled/declared evidence. A hydrated negative may complete. A hydrated
positive fails closed because the current implementation cannot certify historical LFS bytes for
first-adoption dating. Exact timestamped
`results/YYYYMMDD_HHMMSS/clones/<project>/` snapshots are treated as copied projects and cannot
establish host adoption.

Every new scan dispatch now creates an immutable `scan_attempts` row in the same transaction as
the lease. When a worker returns, success/failure, typed diagnostic, retryability, timing, Git
subprocesses, clones, fetches, and materialized bytes are durably closed before the separate
verdict transaction; result rows and task completion then commit atomically. A crash between those
boundaries retries the missing verdict while charging the finished attempt exactly once. Retry
attempts stay monotonic; prior attempts are never overwritten or reset to zero. A closed,
retryable coordinator interruption remains explicitly charged as usage-unknown and may consume
only its already-authorized compatible retry; every non-retryable, live, or malformed incomplete
attempt fails closed. All completed attempt usage is charged to the 60,000 dispatch/fetch and
Git-byte budgets across restart. Failed
regular clone/fetch commands are charged before dispatch and retain any measured cache growth; an
outcome that crosses the Git-byte ceiling is durably closed as a typed non-retryable attempt before
the run stops. The audited predecessor charge is 517 dispatched scans: 503 exact and 14 pre-v5
interrupted attempts. Exact rows account for 45,373,367,985 materialized bytes; the 14 unknowns
carry a public-metadata/exact-HEAD-cache upper bound of 23,398,196,224 bytes, for
68,771,564,209 bytes charged to the successor. Their phase/Git/clone/fetch counts remain explicitly
unknown rather than fabricated. Public state checkpoints retain only admitted public attempt rows
and redact local/private diagnostic identity. A stage exception marks the actual running stage
failed instead of leaving stale `running` state.
On a compatible resume, only durable `pending` scan tasks enter a worker batch. Durable terminal
failures remain explicit unresolved diagnostics and continue blocking publication; they are never
blindly redispatched and cannot prevent independent pending retries from running.
The same audited mode also recognizes the narrower
`git-root-rename-boundary-and-timeout-classification` profile. An explicit bounded Git-command
timeout becomes one-retry `repository_git_timeout`, while unrelated detector timeouts remain
non-retryable `detector_error`. Root commits skip similarity detection because they cannot have a
rename predecessor; non-root and merge commits retain the existing rename/copy analysis. Only
edited-rename similarity may use a 420-second Git-command ceiling, still subordinate to the
540-second repository wall; exact-renames and other Git commands retain their existing caps.
The `generated-evidence-band-exclusion` recovery profile is narrower still: mature-library
confirmed and targeted evidence cannot originate under unambiguous generated/output roots such
as `dist/`, while authored references remain targeted and tracked third-party source remains
eligible for the bundled distinction.
The follow-on `generated-lfs-evidence-relevance` profile makes that provenance rule apply before
content hydration and availability enforcement. Exact `cubin/` and `cubins/` path segments are
precompiled/generated output, so unavailable LFS objects there cannot block a repository and
cannot establish any evidence band. Binary/media assets whose names merely begin with
`Dockerfile` (for example `Dockerfile.png`) are likewise not executable manifests. Authored
`Dockerfile` variants, ordinary source outside those exact path segments, tracked third-party
source eligible for bundled classification, and unavailable LFS objects on genuinely
detector-relevant paths retain their existing behavior. This detector change invalidates all
predecessor scan verdicts; the audited successor may reuse only the unchanged, certified
discovery and metadata documents.
The `copied-orbslam-workspace-provenance` profile handles a separate collision: a robotics
workspace bundled wholesale ORB-SLAM2, OpenCV, dlib, g2o, YDLidar-SDK, and other upstream
projects, with their text files represented by LFS pointers. A distinctive multi-file
ORB-SLAM2 layout now marks only the copied subtree, while `raulmur/ORB_SLAM2` remains a
canonical project unit and ordinary similarly named host directories remain eligible. The
hand-verified `sammydev395/yahboomcar_ros2_ws_software` aggregate is excluded as a whole
because every observed CUDA-X signal belongs to those copied upstream trees. Embedded-root
matching is case-normalized so an uppercase `ORB_SLAM2/` path cannot bypass the same
provenance decision.
The `worker-deadline-and-notebook-bom` profile corrects two fail-closed scan-runtime
boundaries observed in the attended cohort. A repository alarm that escapes a worker at
the future boundary is now durably classified as the same retryable
`repository_timeout` as an in-worker deadline, so it receives only the existing bounded
fresh retry. A leading UTF-8 BOM in a tracked `.ipynb` is removed before both triage and
mature parsing, as permitted for JSON parsers; no other invalid notebook syntax is
repaired, and evidence-bearing malformed notebooks still fail closed.
The `clone-integrity-timeout-policy` profile removes a legacy 60-second
subprocess cap from the connectivity and commit-graph integrity checks. Those
checks now use `CXIT_GIT_TIMEOUT_SECONDS` like other Git work while remaining
strictly bounded by the unchanged per-repository deadline. This prevents
CPU-heavy valid clones from being rejected merely because concurrent Mac
workers slow `git fsck`; it does not skip either integrity check or expand a
run/repository budget.
The `--candidate-policy-remediation` recovery mode is reserved for a
hand-reviewed candidate-evidence collision rather than a scanner defect. It
proves that discovery and metadata task documents, query execution,
public-only certificates, metadata epoch, and request charges remain exact,
then permits only the reviewed candidate-policy nodes and detector-entry
hashes to change. An observation exclusion is keyed by exact repository,
source, signal, path, and blob identity; a changed blob or any independent
observation remains eligible, so an old collision cannot permanently hide
future adoption. Repository-level exclusions remain library-scoped and are
reserved for repositories whose reviewed contents are entirely
non-adoption corpus/copy evidence. Unaffected detector/HEAD results remain
reusable; affected library pairs are rescanned or retired under the new
fingerprint.

## Discovery and completeness contract

Sourcegraph is an advisory broad-recall source in full/onboard runs. Its packed queries use
explicit V3 keyword mode, public `github.com` scope, and `select:file`; `count:50000` is a
detectable ceiling, not permission to truncate. A lane is complete only when it stays below that
ceiling and the one-minute server boundary, reports no unexpected skip, and a `progress` event
with `done=true` is followed by the required final `event: done`. Complete lanes may add
candidates; incomplete observations are quarantined and their quality certificates remain
visible. The free public service is not a zero-result or retirement authority because it can
reach its timeout while claiming terminal completion. A weekly run without a due GitHub lane
still requires complete Sourcegraph recall and fails immediately otherwise. GitHub code search
is the required GitHub reconciliation and candidate-retirement authority: exact queries are
recursively partitioned by extension and byte size. An exact-size leaf below the 1,000-row API
ceiling may use bounded pagination, but acceptance requires an explicit empty page, typed complete
responses, unique repository/path/blob identities, and at least as many unique items as the largest
reported count within that walk; it does not trust `total_count` or `Link` as the terminal
boundary. Page-order churn may retry the whole walk up to three times, but partial walks are never
merged and each accepted retry must independently satisfy the full proof. Saturated or persistently
unstable leaves fall back to complementary path terms and repository-membership peeling.
`incomplete_results`, malformed pages, and unsplittable leaves are fatal; an underreported count
that returned additional unique public items is retained and records a mismatch metric. Active
detector coverage must be refreshed within 28 days.
Requests are serialized at a seven-second floor. A successful response with zero remaining waits
for `X-RateLimit-Reset` before another socket. `Retry-After` takes precedence; primary exhaustion
waits for reset, while secondary 403/429 responses with positive remaining quota back off for 60,
120, then 240 seconds when no server delay is supplied. Search responses at or above 900 reported
matches proactively raise the request floor through 15, 60, then 120 seconds; secondary events use
the same escalation. The floor drops one level after 20 consecutive successful unsaturated
searches. This preserves the fast path for narrow work without letting a broad partition walk
immediately re-enter a CPU/abuse throttle. A server-directed delay may consume up to the full
configured mode-specific cumulative retry-wait allowance; that allowance, request budgets, and
run-wall bounds all fail closed before another socket.
The attended 36-hour reconciliation allows up to two cumulative hours of GitHub code-search retry
waits so one certified, non-overlapping partition walk is not replayed merely because intermittent
secondary delays exceed the weekly allowance. The four-hour weekly refresh retains the
600-second ceiling. Both modes still fail before crossing their run wall or request budget.
GitHub executes a multi-signal logical query pack as its exact member queries rather than sending
the expensive compound `OR` to the API. The result is admitted only after every member lane has a
complete public certificate; observations are unioned and deduplicated, partitions retain the
member signal ID, and any incomplete member quarantines the whole logical pack. The task and
coverage authority retain the reviewed logical-pack fingerprint, so this changes execution cost,
not evidence meaning.
A full reconcile runs both sources but gates coverage on GitHub. GitHub GraphQL then resolves stable node IDs, renames,
visibility, fork/archive state, default branch, HEAD, and needed display metadata in bounded
batches. After scanning, aggregation, citations, and universal staging validation, the collector
runs a second authoritative GraphQL pass over exactly the stable node IDs in the would-be
publication. Batches contain at most 50 IDs and use the journaled five-minute task lease with
heartbeat renewal. Every result must explicitly be `PUBLIC`, `isPrivate=false`, non-fork, and
non-archived; partial, missing, renamed-to-another-ID, budget, reserve, or lease failures abort
before installation.

Every adapter produces machine-readable completeness/cap/lag/error evidence. A skipped,
incomplete, capped, malformed, timed-out, or unresolved required source prevents a release from
claiming a complete epoch. Publication evaluates the required-source tasks and coverage belonging
to the current immutable plan; advisory gaps remain reviewable diagnostics, while obsolete or
superseded coverage can neither satisfy nor block the gate. The last-good V2 manifest remains
live.

This contract is optimized for current public direct integrations; it is not a literal census of
all Git history. A repository whose only integration was removed before any free index observed it
may be absent. Historical first-use dating is performed after a repository is discovered. Removed
historical integrations are not the primary product goal.

## Evidence semantics and catalog

- `confirmed` (shown as **Integration**): reviewed direct use in the repository's own source—an
  include, import, symbol, or API call. This is the headline.
- `declared`: an authored dependency manifest or Dockerfile names the reviewed official package,
  but the repository's own source does not use it. It is stored in the shared `bundled` data band
  and relabeled **Declared** for Python-distributed libraries.
- `bundled`: the repository ships a vendored SDK/library copy in-tree, but its own source does not
  use it.
- `targeted`: authored code or build configuration deliberately references, links, selects, or
  generates for the library without direct source use or qualifying middle-band evidence.

Declared, bundled, and targeted remain secondary. A repository has one classification per
library, with confirmed direct use taking precedence.

Mature detectors retain all three bands and their historical rows. Every newly onboarded
high-volume library evaluates confirmed direct use. A lower band is enabled only where the Phase 8
evidence contract certifies exact syntax: 19 libraries accept exact official distributions in
structurally parsed authored manifests as declared/bundled, and 15 accept exact reviewed CMake/link
targets as targeted. All remaining lower bands are `not_evaluated` with `null` counts, never
collapsed into rejected or displayed as zero. Framework/transitive attribution is deferred.

The catalog is versioned and additive: 65 total entities equal 49 first-party NVIDIA entries
observed on 2026-07-27, 14 component rows (13 active plus preview cuSPARSEDx), and two retained
products. Partner libraries are excluded. The 56 active detectors comprise 12 mature three-band
detectors and 44 reviewed REQ-14 direct-lane detectors with selectively certified lower bands.
`cuda.compute` and `cuda.parallel` stay catalog-visible with all bands `not_evaluated` but are
absent from discovery/scanning by owner scope decision. Previously tracked entries remain retained even if a changing
marketing page omits them. Entries lacking an honest direct-code metric display
`metric_contract_status=pending` and all classification coverage as `not_evaluated`.

Confirmed Dx/Mp/Xt/Lt and TensorRT-LLM component evidence rolls up to its parent using a unique
repository union. A repo using cuBLASDx, cuBLASLt, and cuBLASXt counts once for cuBLAS and once in
the portfolio repository total. Its three component rows, dates, commits, and evidence remain
independent and unchanged.

## State, cache, interruption, and invalidation

SQLite is the operational truth; generated JSON is ignored local output. Repository/library results
are keyed by public node ID, HEAD, and per-library detector fingerprint. Discovery, detector,
dating, aggregation, citation, presentation, and catalog changes invalidate only the affected
work. A genuine shared extraction-semantic change can still require an explicit all-library
reconcile.

Scan outcomes are committed after each completed repository task. A new compatible run reuses
completed HEAD/fingerprint results, so an interruption does not discard earlier successful work;
the active repository can be retried. A single-instance database lock prevents competing network
runs. Staging and content-addressed publication prevent partial public releases.

A new release attempt starts a fresh final-visibility epoch. A compatible crash retry may resume
only the exact task plan and stable-ID set while its conservative epoch-start remains within the
120-minute install limit; completed batches, including a fully completed pre-install
attestation, are reused without spending quota again. A failed, stale, or mismatched gate instead
repeats the initial authoritative metadata pass before rematerializing and starts a new final
epoch. Same-run GraphQL points remain cumulative across epochs, while `remaining` is restored
only from an unexpired rate-limit window. Checkpoints retain sanitized public task results and
aggregate quota fields, but strip any identity not present in the final public repository table.

The Git cache starts with treeless depth-one bare repositories. Direct-only negatives normally use
bare `ls-tree` and one persistent `cat-file --batch --filters -Z` stream, so they avoid a worktree
and preserve standard checkout EOL/ident semantics. Older Git or correctness-sensitive custom
filters safely fall back to an isolated worktree. Mature classification fetches every
ordinary-size current blob in one bounded pack, keeps sparse large own-source files up to the
triage limit, and removes still-promised large assets from only the ephemeral scan index before
its whole-index search. Positive dating fetches commit/tree history without all historical blobs.
Per-repository locks, isolated temporary worktrees, and LRU accounting bound concurrent use:

- target: 200 GiB
- hard stop: 250 GiB
- weekly workers: six
- reconcile workers: fourteen
- default per-repository timeout: 540 seconds

Startup scavenges abandoned worktrees and prunes Git worktree metadata. Cache eviction removes
objects, not SQLite verdicts or public checkpoints.

After the first successful genuine publication, `StateDB.export_checkpoint_shards` writes all durable public
operational tables—including candidates, results, tasks, coverage, and citation cache—to
content-addressed shards and replaces `data/state-checkpoint/manifest.json` last. Runtime locks are
excluded. The checkpoint can reconstruct SQLite if the Mac-local database is lost.

## Citation behavior

The scanner reads repository-wide CFF text once at HEAD. The supported
`collector.citation_pipeline` stage uses `collector.citation_extract` for bounded public-source
extraction and:

- caches parsed CFF/DOI evidence by repository HEAD and analysis fingerprint;
- caches OpenAlex query snapshots by library query fingerprint;
- caches works and source extraction by work payload fingerprint;
- reports per-library `as_of`, complete, capped, stale, carried-forward, errors, and extraction
  limits; and
- may carry explicitly stale last-good citation data with a fresh adoption release.

An all-failed first citation stage cannot manufacture an empty replacement. Citation completeness
is separate from adoption completeness and is visible in release quality.

## Publication and dashboard

V2 is manifest-driven:

```text
data/v2/manifest.json
data/v2/libraries/<id>/index-<hash>.json
data/v2/libraries/<id>/repos/part-<n>-<hash>.json
data/v2/citations/<id>/index-<hash>.json
data/v2/citations/<id>/part-<n>-<hash>.json
data/v2/exports/repositories/{jsonl,csv}/part-<n>-<hash>.*
data/state-checkpoint/manifest.json
```

The home page loads only `manifest.json`, whose maximum is 250 KiB. A library page initially loads
its index and first adoption shard, paginates 200 visible rows, and loads remaining same-library
parts for further pages/filter/sort/export. Citation parts load only when the research tab opens.
Normal pages never load another library's repositories or the full export.

Artifacts are sorted deterministically and packed by exact final encoded bytes. Every non-manifest
artifact must remain strictly below 4,000,000 encoded bytes and the universal hard limit is
strictly below 5 MiB. One oversized row fails
publication. Hashes and row counts live in parent indexes/descriptors. No-change data shards remain
byte-identical; volatile release metadata lives in the manifest.

Publication builds and validates in a sibling staging directory, records a durable publication
journal, installs immutable content-addressed artifacts first, and atomically replaces the live
manifest last. Restart recovery either validates and finishes the exact manifest/checkpoint pair
or rolls the provisional pair back; an unresolved recovery failure preserves the journal and
blocks new work.

The final-visibility stage journals the exact stable-ID set hash, conservative epoch-start
`checked_at`, completion time, repository/batch counts, GraphQL requests/points/remaining, and the
oldest attestation age. Installation rechecks that age and refuses anything older than 120
minutes. The local planner models both GraphQL passes: 30,000 repositories are 600 initial plus
600 final requests (1,200 total), and 60,000 are 1,200 plus 1,200 (2,400 total). It refuses a
projected point-budget, reserve, or 120-minute final-pass freshness breach.

## Default budgets and SLOs

These are design targets and configured limits, not completed production measurements.

| Operation | Performance target | Default wall limit |
|---|---:|---:|
| Warm no-change weekly | 30 minutes | 1-hour incident threshold |
| Normal weekly | 2 hours | 4 hours |
| Targeted onboarding | 4 hours | 4-hour default; up to 8 only by reviewed override |
| Full ~30k reconciliation | 24 hours | 36 hours |
| Phase 8 Cohort A production incident | measured, attended | owner-reviewed seven days; wall only |
| Stress ~60k | 48-hour resumable design target | override required; default reconcile remains 36 hours |

The weekly defaults are 2,000 scans/fetches, 500 Sourcegraph requests, 2,000 GitHub search
requests, at most 2,500 GraphQL points while retaining 2,500 remaining, and six workers. Reconcile
defaults are 60,000 scans/fetches, 1,000 Sourcegraph requests, 20,000 GitHub search requests, the
same GraphQL reserve, and fourteen workers. Normal operations target at least 90% scan-result reuse and
less than 16 GiB RSS. Flags can lower budgets; increases require operator review.

Budget exhaustion, unresolved work, coverage failure, privacy uncertainty, or validation failure
marks the run failed and preserves the last-good manifest. Do not weaken budgets just to make a run
finish.

## Safe verification

Before the first collection:

```bash
./refresh.sh --check
python3.12 -m collector.cli plan --json
python3.12 -m compileall -q collector
python3.12 test_req14_state.py
python3.12 test_req14_discovery.py
python3.12 test_req14_transports.py
python3.12 test_req14_scanner.py
python3.12 test_req14_citations.py
python3.12 test_req14_publication.py
python3.12 test_req14_portfolio.py
python3.12 test_req14_pipeline.py
python3.12 test_req14_successor.py
python3.12 test_req14_safety.py
python3.12 test_req14_acceptance.py
python3.12 test_req14_evidence_contract.py
python3.12 ops/smoke_scan.py --repos EXPmaster/nqs --repo-timeout 60
```

Use Homebrew Python 3.12 for these commands. The readiness and plan commands do not collect. The
smoke scan is a separately bounded named repository and writes only ignored scratch output.

## First attended production reconciliation

Launchd must remain unarmed. Before invoking the collection command, review and explicitly approve
`docs/REQ14-PHASE8-READINESS.md`, `collector/req14_evidence_contract.json`, and
`ops/req14_detector_fingerprints.json`. A plan is read-only; approval of the detector contract must
still precede `reconcile --confirm-full`.

After that explicit approval, from a clean, current `main`:

```bash
./refresh.sh --check
python3.12 -m collector.cli plan --mode reconcile --json
python3.12 -m collector.cli reconcile --confirm-full
python3.12 -m collector.cli validate
git status --short
```

Do not leave the run unattended. Review coverage certificates, unresolved/error counts, catalog
and per-library changes, classification coverage, citation quality/staleness, existing-library
regressions, manifest/artifact sizes, checkpoint contents, and the planner's actual-vs-budget
metrics. Only
after owner acceptance should the local result set be used for an explicitly
authorized downstream purpose. The public source repository does not publish
or version generated data.

If a resumed final-visibility epoch proves that exactly one previously scanned stable node is now
missing, the incident-specific `run-final-visibility-privacy-control` may quarantine that
repository and its cascading evidence only after its source, task, result, and count proofs pass.
The control preserves compatible completed visibility batches and citation cache rows, resumes
only the pending batches from that same sealed epoch, and never authorizes publication by itself.

If the completed local result set is rejected, keep it outside the checkout for diagnosis and
force a clean future plan. Use explicit validated paths:

```bash
project_root="$(git rev-parse --show-toplevel)"
rollback_dir="$(mktemp -d /tmp/cxit-rejected-reconcile.XXXXXX)"
mv "$project_root/data" "$rollback_dir/data"
if [ -d "$project_root/.state" ]; then
  mv "$project_root/.state" "$rollback_dir/state"
fi
python3.12 -m collector.cli plan --mode reconcile --json
```

This preserves the rejected release and state under the printed temporary path rather than
deleting them. Generated output must not be added back to this source repository.

## Scheduling and host state

- No host-specific scheduler definition is published. Any maintainer scheduler
  must be configured separately and remains intentionally unarmed by default.
- Before any future arm, verify `gh auth token` and the OpenAlex key from the
  scheduler's non-interactive context.
- CI collection schedules are intentionally absent.
- Public CI tests source only; it has no collect, canary, or scan-smoke jobs.

Do not arm automated collection merely because REQ-14 code and tests pass. Arming requires the first attended
full reconciliation, owner review, and explicit approval.
