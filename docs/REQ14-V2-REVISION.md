# REQ-14 V2 revision: unattended reliability and throughput

Status: future engineering requirement and research/validation spike. This is not an
approved implementation design, does not close REQ-14, and does not authorize arming
automated collection. The required outcomes are normative; the possible mechanisms below must be
measured and may be adopted, modified, or rejected.

## Problem statement

The attended Phase 8 run proved that V2 can preserve evidence and fail closed, but it
also exposed runtime behavior that is not acceptable for an unattended weekly refresh.
One broad discovery lane can take hours, provide no internal progress, repeatedly hit
GitHub secondary throttling or server errors, and stop the coordinator before independent
libraries run. Recovery currently requires an operator to inspect state, decide whether
a retry is safe, restart the process, and rearm an external boundary watcher.

Before V2 is scheduled unattended, it must make bounded forward progress through
ordinary throttling and transient infrastructure faults without weakening discovery
completeness, classification accuracy, public-only handling, durable accounting, or the
publication gate. A terminally blocked library may block acceptance/publication, but it
must not silently become zero adoption or prevent independent work from completing.

## Production incident evidence

The following observations are inputs to the revision spike, not assumptions about the
final solution:

1. **Discovery scope can explode.** The original cuSPARSELt broad lanes produced 964
   provisional partitions before the reviewed scope reduction removed those two lanes.
   Broad anchors need measured selectivity, cost, and recall before they are enabled.
2. **A single GitHub lane can occupy hours.** Warp's first required GitHub lane ran for
   roughly two hours and then failed closed. It recorded 51 logical operations and 76
   request attempts: 14 rate-limited attempts, 12 server-error attempts, and 25 retries.
   No partial result was accepted.
3. **A retry can repeat the same long black-box walk.** Warp attempt 2 performed another
   14 logical operations and 15 requests before the owner stopped it to reduce the
   release cohort. Those requests were charged, but no reusable terminal discovery
   document existed.
4. **Secondary throttling is different from primary quota exhaustion.** Long GitHub code
   searches received `429` responses while the reported primary search allowance was
   still positive. The initial transport behavior did not apply GitHub's required
   secondary-limit wait. The immediate fix added a minimum 60-second response and
   exponential/persistent pacing, but the resulting 120-second floor can make a broad
   lane take hours and has not yet demonstrated unattended stability.
5. **Pacing recovery is slow and opaque.** The current pressure ladder can remain at
   120 seconds per call until enough consecutive successes lower it. There is no
   operator-visible explanation of the current level, next eligible request, recovery
   progress, or expected remaining work.
6. **Intra-task progress is not durable.** The task lease heartbeat proves that a process
   is alive, but completed/total partitions, current query/phase, request progress, and
   last useful result are not persisted. Request-use totals are journaled only when an
   attempt terminates. An observer cannot distinguish 5% from 95% complete.
7. **The task is the recovery boundary.** Independently completed pagination or search
   partitions inside a GitHub lane cannot currently be reused after the lane fails.
   Retrying can replay the whole lane even when much of its work was valid.
8. **One required-task failure stops discovery.** The coordinator exits fail-closed when
   the active required lane does not certify. This protects publication, but it also
   leaves unrelated libraries pending until a human reviews and restarts the run.
9. **Restart and boundary control are operator-managed.** The attended run used an
   external polling watchdog to stop at the desired product boundary, and that watcher
   had to be recreated when the collector restarted. This is not a durable unattended
   control plane.
10. **Status and logs can be ambiguous.** During a retry, the task row remained `running`
    while retaining the prior `discovery-query-failed` error code. Earlier monitoring
    emitted repetitive status lines; the quieter configuration then exposed only a
    heartbeat and terminal result. Neither is a sufficient low-noise operational
    contract.
11. **Credential and throttle scope is not proven.** Different PATs have separate primary
    quotas, but the observed secondary limits may also depend on workload, account, or
    network characteristics. The scheduler cannot assume that another PAT makes
    concurrent heavy search safe.
12. **State growth needs measurement and control.** During the incident the collector
    database was about 6.8 GiB and state backups about 18 GiB. The spike must attribute
    growth to durable evidence, provisional partitions, indexes, retry history, WAL, and
    backup policy before defining retention or compaction.
13. **Transient infrastructure failures recur.** The attended run also observed DNS
    resolution failures, synthetic HTTP 599s, GitHub server errors, and publishing-host
    failures. Short probes could succeed while a long production-shaped walk still
    failed, so a one-shot health check is not sufficient evidence of recovery.
14. **Successful metadata work is not yet a reusable recovery boundary.** In the Cohort A
    metadata pass, 38,658 repository results succeeded while 40 ended in `partial_error`.
    The run correctly failed closed, but the audited successor path could inherit only
    discovery tasks, so the successor replayed all 774 metadata batches. Full-stage
    replay was not logically necessary. Every expensive stage needs durable,
    compatibility-checked checkpoints that preserve valid completed units and retry only
    failed or incomplete units.
15. **Checkout can invoke unrelated external content systems.** A public repository's
    detector-irrelevant 53 MB executable was tracked through Git LFS, and checkout failed
    because the repository owner had exhausted the LFS quota. The worker mislabeled the
    materialization failure as a detector defect. The immediate attended-run fix skips LFS
    smudge and fails closed only when a detector-relevant path is an LFS pointer; the revision
    spike must verify equivalent treatment for LFS, submodules, custom filters, and other
    checkout-time content providers without silently reducing evidence coverage.
16. **Nested timeouts need typed ownership.** Two history-dating subprocesses hit their
    explicit 120-second `git diff-tree` cap while the enclosing repository budget still
    had time. The worker durably retained the exact error but classified it as a
    non-retryable detector defect. The attended-run correction gives a rendered Git
    subprocess timeout one same-contract retry as `repository_git_timeout`, while an
    unrelated detector timeout remains `detector_error`. A bounded probe proved that retry
    alone did not help one repository. Tracing proved that non-root edited-rename
    similarity on the partial clone completed correctly in 357 seconds, so only
    50%-similarity detection receives a 420-second command ceiling beneath the unchanged
    540-second repository wall. The same correction skips similarity detection for a true
    root commit, which cannot have a rename predecessor. The revision spike must define
    typed timeout ownership, budgets, retry evidence, and observability at every nested
    subprocess/stage/repository/run boundary.
17. **Cross-library recall must apply the same path provenance contract as primary
    detection.** A completed one-pass scan surfaced an NVSHMEM token inside a committed
    `dist/.../torch/__init__.py` PyInstaller payload and proposed a targeted pair for the
    host repository. The token was real, but the path was generated bundled output rather
    than host intent. The attended fix excludes unambiguous generated/output roots from
    mature confirmed/targeted references while retaining authored targeted references and
    tracked third-party source as bundled evidence. The revision spike must prove that
    primary discovery, cross-library expansion, classification, dating, and retirement all
    use the same generated/vendor/copied-project/local-shadow provenance contract.
18. **Content availability must be enforced only after path relevance is established.**
    The attended Cohort A scan correctly failed closed on three unavailable LFS pointers,
    but the paths were not valid evidence surfaces: two were generated precompiled-kernel
    files under exact `cubin/` directories, and one was a `Dockerfile.png` screenshot.
    Treating every text-shaped `.cpp` path and every basename beginning with `Dockerfile` as
    executable evidence converted excluded output/media into terminal completeness failures.
    The attended correction excludes exact `cubin/` and `cubins/` output segments before
    hydration, rejects binary/media Dockerfile lookalikes, preserves authored Dockerfile
    variants, and continues to fail closed for an unavailable LFS pointer on genuine source
    or manifest evidence. The revision spike must make the ordering explicit across sparse
    hydration, custom filters, submodules, history traversal, and classification so
    availability rigor never expands the evidence surface or silently suppresses a valid one.
19. **Copied-project recognition needs positive identity, canonical exceptions, and
    case-normalized boundaries.** After the generated-output repair, a robotics software
    bundle failed on an unavailable `ORB_SLAM2/CMakeLists.txt` LFS pointer. The repository
    is a wholesale aggregate of ORB-SLAM2, OpenCV, dlib, g2o, YDLidar-SDK, and other
    upstream trees; its cuFFT/cuRAND signals are those projects' code, not host adoption.
    The attended correction requires a distinctive six-path ORB-SLAM2 layout, preserves
    `raulmur/ORB_SLAM2` as the canonical project unit, scopes nested copies to their exact
    root, case-normalizes root containment, and exactly excludes the hand-verified aggregate.
    The revision spike must replace one-off growth with a durable, auditable provenance
    model that distinguishes first-party monorepo components, vendored dependency copies,
    mirrors/aggregates, and canonical upstream repositories without losing legitimate host
    integrations.
20. **Worker-boundary deadlines and standards-valid notebook encodings need one durable
    contract.** A repository alarm that escaped through `Future.result()` was stored as a
    non-retryable `detector_error` even though the identical in-worker condition was a
    retryable `repository_timeout`. A separate tracked notebook was valid JSON after its
    leading UTF-8 BOM, but Python's string JSON parser rejected that marker. The attended
    correction applies the existing bounded fresh retry at either worker boundary and
    strips exactly one leading U+FEFF before both notebook evidence parsers. It does not
    repair malformed JSON, parse notebook outputs/metadata as evidence, or relax the
    repository deadline. The revision spike must unify timeout ownership/typing across
    processes and define explicit text-decoding policy so standards-valid encodings cannot
    become false completeness failures.
21. **Clone integrity checks must share the configured timeout policy.** The cohort's
    large-repository lane exposed a legacy 60-second cap on
    `git fsck --connectivity-only --no-dangling`. Under concurrent CPU load, valid
    filtered clones repeatedly crossed that cap even though the repository retained most
    of its unchanged 540-second deadline. The attended correction uses
    `CXIT_GIT_TIMEOUT_SECONDS` for connectivity and commit-graph checks, still clamped by
    the repository wall deadline, without skipping integrity or increasing any hard
    budget. The revision spike must benchmark integrity validation under realistic worker
    contention and decide whether cache-level validation receipts can safely eliminate
    redundant work.
22. **Discovery collisions and unrelated checkout failures must not manufacture
    candidate completeness blockers.** The certified cuTENSOR observation for
    `aarnphm/aarnphm.github.io` matched only `CUtensorMap` and
    `cuTensorMapEncodeTiled`, CUDA Driver TMA identifiers rather than the cuTENSOR
    library. The scan later failed on a different unavailable compiler-course LFS
    notebook before it could clean-reject that collision. Separately, all 48 cuDSS
    observations in `4shen/webshell` were repeated PHP malware-corpus samples, and
    macOS could not materialize one invalid-byte path in that corpus. The attended
    correction records the cuTENSOR false positive as an exact
    repository/source/signal/path/blob observation exclusion, so any changed or
    independent future observation still qualifies, and records the malware repository
    as a cuDSS-only corpus exclusion. The audited successor must prove discovery and
    metadata documents unchanged, invalidate only the two affected detector
    fingerprints, retain compatible scan results, and remove both illegitimate pairs
    before dispatch. The revision spike must derive scalable collision/provenance rules
    without turning checkout portability or content-provider failures into adoption
    evidence, permanent future blind spots, or weakened required-source completeness.
23. **Repository identity is canonical metadata, not a stable textual node-ID
    representation.** Cohort A discovery contained 37,644 unique repositories, but the
    first admission path kept only 10,115 because 30,914 discovery observations used
    GitHub's older base64 node-ID representation while the metadata epoch returned the
    newer opaque representation for the same canonical repository. Exact ID matching
    admitted only 6,730 discovery identities; legacy state then obscured the loss. The
    attended correction treats current public metadata node/name as authoritative,
    permits an old ID to fall back through its exact requested/canonical name only when
    both resolve to the same repository, preserves rename aliases, and refuses
    node/name/alias collisions. The revision spike must test identity format changes,
    renames, transfers, case changes, deletion/recreation, and alias collision without
    weakening public-only enforcement.
24. **Task status is not an attempt ledger.** The failed scan run persisted only generic
    `scan_error`, overwrote prior task summaries on retry, and could not durably charge
    failed-attempt fetches or materialized bytes. Stale leases also lost the exact
    attempt boundary. The attended correction adds immutable per-attempt identity,
    payload/head, typed error, retryability, phase timing, Git subprocess, clone/fetch,
    and byte accounting. Lease and attempt start are atomic; completion/failure closes
    both atomically; attempts remain monotonic; unknown interrupted usage blocks
    compatible resume. The revision spike must extend the same immutable-attempt and
    budget model to every expensive stage and prove crash behavior at every transaction
    boundary.
25. **Current-tree content recovery must be reproducible by dating and must not invent
    evidence.** One `.ipynb` was valid Python with a Python shebang; another malformed
    JSON notebook had its only damage in ignored outputs/metadata. Independent current
    and history parsers would either reject valid authored content or recover a current
    positive that history could not date. Git LFS adds the same asymmetry: exact HEAD
    bytes may be available while historical objects are not. The attended correction
    uses one notebook parser for bare/worktree/history, accepts Python only after strict
    UTF-8 plus AST validation, and permits tolerant JSON only when damage is confined to
    ignored outputs/metadata. Exact public LFS hydration may establish a negative, but a
    hydrated positive fails closed until historical LFS evidence is certified. The
    revision spike must generalize this reproducibility contract to submodules, custom
    filters, generated files, and external content providers.
26. **A successor must charge unknowable predecessor work without inventing precision.**
    The pre-ledger Cohort A scan dispatched 517 repositories. Only 503 retained exact
    timing/network/byte results; 14 were interrupted with no result document. Treating
    those attempts as zero would evade the 60,000-dispatch and Git-byte ceilings, while
    guessing one clone/fetch would present false precision. The attended correction
    carries immutable per-task proof rows, preserves exact metrics where present, records
    timing/Git/clone/fetch as unknown for the 14 gaps, and charges a deterministic
    public-metadata/exact-HEAD-cache byte upper bound. The revision spike must generalize
    this split exact/unknown/upper-bound accounting to every stage and prove that a
    restart neither double-charges nor loses work.
27. **Availability policy and classifier capability must be the same contract.** Several
    edges initially diverged: valid CRLF LFS pointers were not recognized; direct-only
    targeted LFS relevance included non-CMake paths the classifier could never accept;
    `environment*.yml`/`.yaml` files were admitted but only exact `environment.yml` was
    parsed; serialized-notebook prefiltering missed decoded JSON escapes; and effective
    per-worktree LFS endpoint/transfer/URL-rewrite configuration was not denied. Each
    mismatch could create either a false clean reject, a false completeness blocker, or
    an unaudited network path. The attended correction derives relevance from executable
    band surfaces, parses every admitted manifest variant, searches decoded authored
    notebook cells, accepts the standards-valid pointer form, and checks effective
    repository configuration. The revision spike must make these equivalence properties
    generated and mechanically testable rather than duplicated by hand.

28. **A successor preflight must charge lineage attempts and explain durable candidate
    growth.** The first content-remediation successor correctly carried the predecessor's
    517 scan attempts into its immutable execution contract, and runtime would have
    enforced them, but its displayed fetch preflight still compared only 38,358 new
    repositories with the 60,000 ceiling. It also surfaced 57,353 repository/library
    pairs rather than the 57,267 pre-scan baseline. A read-only replay against the exact
    pre-scan snapshot proved that all 86 additional pairs came from durable cross-library
    candidates discovered by the 465 completed predecessor scans, on repositories already
    in the same 38,358-repository universe. The immediate correction makes preflight and
    runtime both enforce and report 517 historical plus 38,358 new dispatches, or 38,875
    total. The correction is itself chained through a zero-scan, no-network
    `preflight-budget-remediation` successor rather than mutating or branching around the
    deficient immutable run. The revision must generalize this rule: every derived
    work/budget total needs an explicit before/after lineage decomposition, and durable
    candidate growth must be attributable to exact evidence rather than treated as
    unexplained drift.

29. **Content recovery must be grammar-scoped, and deadline signals must not be
    relabeled by broad I/O catches.** An attended Cohort A scan found a public notebook
    whose only syntax defect was a trailing comma inside ignored metadata, plus strict
    JSON notebooks containing literal escaped control/replacement characters. Treating
    the latter as decoder damage was a false failure; accepting arbitrary relaxed JSON
    would instead invent evidence. The correction uses a token-aware, length-preserving
    recovery that permits trailing commas only within metadata/output descendants and
    then requires a complete strict parse. Root, cell, worksheet, and source syntax stays
    fail-closed, and genuine invalid UTF-8 in authored content is still rejected. The
    same scan proved that the worker deadline exception inherits from `TimeoutError` and
    therefore `OSError`; an LFS probe caught it and emitted a non-retryable detector
    error at exactly the repository deadline. The immediate fix propagates the deadline
    before handling ordinary file errors. The revision spike must test cancellation
    delivery through every broad exception boundary and generate parser recovery
    properties from explicit authored-versus-ignored grammar, rather than adding
    corpus-specific exceptions.

30. **Graceful abandonment must durably close in-flight usage, not only identity and
    status.** Run `20260731T052650Z-cd66b01e` dispatched 63 V5 scan attempts. Forty-nine
    closed with exact timing/network/materialization usage; the supported abandonment
    marked the other 14 `interrupted` with exact task/payload/repository/HEAD identity and
    a machine-readable reason, but necessarily left `usage_complete=0` because the
    counters still lived only in worker memory. A later cache is not a cumulative
    high-water receipt: Git fetch accounting sums positive deltas, clone failure may
    remove its temporary cache after charging it, Git packs may be replaced or evicted,
    one observed receipt says zero beside a 477,391,366-byte bare cache, one has no cache
    remaining, and this scanner can add bounded public LFS transfers. GitHub `diskUsage`
    is metadata rather than a source-enforced transfer ceiling. The attempted recovery
    therefore remains fail-closed instead of disguising a heuristic as a conservative
    bound. The revision must persist monotonic in-flight usage from workers at a bounded
    cadence and perform a final worker/coordinator handshake on attended stop, while
    proving crash/replay idempotence and keeping dispatch, byte, clone, fetch, and timing
    unknowns visible when that handshake cannot complete.

31. **A compatible result is an audited transaction, not a matching mutable cache key.**
    The checkpoint contained 37 exact completed scans, but their task keys/result rows used
    the effective detector fingerprints present in the shared `libraries` table while the
    immutable run manifest stored the raw detector family. The immediate fix makes the run
    plan the sole authority for deriving effective fingerprints. The incident-specific
    continuation separately certifies all 37 source transactions: 237 result rows, 421
    candidate postimages, 14 AI-analysis postimages, exact public identities/HEADs, and 181
    eligible notebook blobs whose old/current parser outcomes are identical. It preserves the
    original timestamps and provenance and creates no synthetic attempt. The 14 interrupted
    attempts remain usage-unknown under a frozen owner policy, so lifetime materialized bytes
    are explicitly not evaluable even though known bytes and dispatch identities remain charged.
    The revision must generalize per-result provenance and graceful usage high-water receipts;
    it must not generalize this one-run owner exception or permit a fingerprint-only bypass.

32. **Portfolio-scale scan duration exceeded the reviewed wall without exhausting other
    budgets.** Cohort A produced 38,358 admitted repositories, materially above the earlier
    ~30,000 sizing marker. The attended 14-worker scan remained checkpoint-correct but could not
    plausibly finish inside 36 hours. The incident control extends this run to seven days while
    charging elapsed segments and proving every other budget unchanged. This is production
    evidence for the future benchmark/SLO spike, not permission to make weekly walls unbounded.

33. **Failure isolation must distinguish exact content negatives from semantic bypasses.** Multiple
    public repositories contained malformed `.ipynb` blobs; four were serialized negatives and
    one 104 MB notebook had corruption/output payloads that defeated strict whole-document JSON
    parsing. A frozen task-specific proof re-attests repository/head/path/blob identity and
    searches authored surfaces for the complete 169-token retention universe before treating only
    those exact bytes as fast negatives. Missing current-tree objects are separately retryable
    cache-integrity incidents. The future design needs a general durable issue lane, but must keep
    exact proof, unchanged evidence meanings, and publication-gated provenance.

34. **Generated mobile-build trees need exact segment semantics, not broad name filters.** The
    public `Silian1234/shootAnalyzer` tree commits Buildozer output beneath `.buildozer/`, including
    a file/directory case collision that cannot be materialized faithfully on the Mac's
    case-insensitive filesystem. Those copied OpenCV/TensorFlow sources also contain CUDA-X
    headers and would create false confirmed/bundled/targeted evidence. The owner-approved incident
    rule excludes only an exact `.buildozer/` directory segment from materialization and every
    evidence band; it preserves `buildozer.spec`, lookalike names, and authored source elsewhere.
    The run-local migration must prove this is a monotonic exclusion, certify that no completed
    result cites the path, and retry only the affected failed repository. Future V2 research should
    determine whether other generated-build roots can be identified from auditable structure
    without turning one exact rule into an unsafe generic ignore list.

35. **Paper search must enforce temporal plausibility and library-specific precision.** The
    published citation sample exposed pre-release papers for 15 libraries (including cuBLAS
    results back to 1935) because OpenAlex full-text searches were not bounded by each library's
    release date and ambiguous tokens matched unrelated acronyms, names, and OCR text. The
    immediate correction adds the release floor to both the source query and the local/CFF
    acceptance gate, includes that floor in the query fingerprint, and keeps raw extraction
    failures out of the public UI. The future V2 paper-search work must also require reviewed
    per-library positive and negative title samples, explicit collision strategies for ambiguous
    names, exact source-total reconciliation, and a regression gate proving that every published
    paper is temporally plausible. Collector diagnostics remain durable operator evidence and
    must never be rendered as end-user content.

## Questions to investigate and verify

The spike must evaluate alternatives, not assume these are the answers:

- Can band-aware, signal-aware query planning bound broad libraries without losing any
  qualifying positive or hard-negative coverage?
- What query-pack and partition size minimizes replay and cap risk while preserving an
  exact, gap-free coverage certificate?
- Can independent GitHub partitions, Sourcegraph lanes, or libraries run concurrently
  behind one centrally enforced quota, congestion, privacy, and budget controller?
- Can independently complete partitions be checkpointed and reused under identical
  query/discovery fingerprints, source-visibility rules, execution contracts, and
  bounded coverage epochs?
- What is the smallest safe recovery unit for metadata, clone/fetch/history, scanning,
  enrichment, citations, aggregation, and exports, and how can exact compatibility be
  proven so that a small tail failure never forces a full successful stage to replay?
- What adaptive pacing responds correctly to primary limits, secondary throttling,
  `Retry-After`, abuse detection, 5xx bursts, DNS faults, and healthy recovery without
  oscillation or hours of unnecessary delay?
- Can the coordinator continue unrelated work while explicitly quarantining a blocked
  library, keeping that library `not_collected`/`not_evaluated`, and still preventing
  incomplete publication?
- What durable, secret-free progress model exposes completed/total partitions, current
  source/phase, useful-result and request counts, last activity, retry history,
  congestion state, and next eligible action with negligible overhead?
- What supervision model safely resumes after process death, reboot, expired
  credentials, or network restoration without external ad hoc watchdogs?
- What state schema, retention, vacuum/compaction, and backup strategy keeps disk use
  bounded while preserving the audit and restart contracts?
- Which checkout-time content providers can affect qualifying evidence, and how can
  unrelated LFS/submodule/filter failures be isolated while detector-relevant missing
  content remains an explicit publication blocker?
- Which GitHub authentication and network-scope assumptions can be proven from official
  behavior and bounded probes, and which must remain conservative runtime constraints?

## Required unattended-run behavior

V2 is not ready to be armed for unattended collection until all of the following are
implemented and validated:

1. A production-shaped full-portfolio benchmark defines the weekly target, hard ceiling,
   request budgets, disk budget, and minimum safety margin from measured candidate and
   partition distributions. Bounded live probes must corroborate fixture results.
2. Every query has a reviewed cost/selectivity estimate and a hard partition/cap plan.
   Pathological scope growth fails preflight before consuming an unbounded number of
   requests.
3. Progress is durable and queryable at a useful sub-task boundary. Operators can tell
   useful progress from intentional pacing, throttling, retry, and a true stall without
   reading raw SQLite or attaching a process tracer.
4. A restart never replays a terminal certified task. The maximum compatible
   sub-task replay after interruption is measured, documented, and explicitly approved;
   incomplete pagination is never presented as complete evidence. This applies to every
   expensive stage, not discovery alone: validated metadata, repository, scan,
   enrichment, citation, aggregation, and export units are durably checkpointed and
   compatibility-checked, and recovery retries only failed or incomplete units.
5. Ordinary `429`, `Retry-After`, 5xx, DNS, socket-timeout, and connection-reset events
   recover automatically within the hard wall/request budgets. Retry behavior is
   centrally paced and cannot create a thundering herd.
6. A blocked library is explicit and actionable. Independent libraries may continue,
   but the blocked library cannot be retired, counted as zero, marked evaluated, or
   admitted to a complete release. The final gate reports the exact blocker.
7. Process death or Mac restart resumes the compatible run from durable state under one
   supported supervisor. Duplicate collectors, stale leases, and duplicate network
   attempts are prevented or detected fail-closed.
8. Status fields are internally consistent: current status, prior failures, active
   attempt, retry eligibility, and terminal reason are distinct. No stale error can
   masquerade as the active task state.
9. Operational output is low-noise: product/stage transitions, material pacing changes,
   warnings, failures, recovery, and the final gate are emitted once with stable
   machine-readable fields. Routine heartbeats remain queryable but are not spammed.
10. Disk, WAL, cache, and backup growth have enforced budgets and safe cleanup rules.
    Cleanup cannot remove evidence or lineage needed for the active run, comparison, or
    accepted release.
11. Public-only validation, frozen detector semantics, zero-gap required GitHub
    coverage, exact request accounting, and manifest-last publication remain unchanged.
    Optimization is rejected if it reduces recall/precision or obscures incompleteness.
12. Launchd remains unarmed until an attended run, fault-injection suite, restart test,
    and V1/V2 reconciliation all pass and the owner explicitly approves unattended
    operation.

## Validation matrix

At minimum, automated and attended tests must inject:

- primary quota exhaustion and positive-remaining secondary `429`;
- valid, missing, malformed, and contradictory `Retry-After`/rate-limit headers;
- isolated and bursty 5xx responses, DNS failures, synthetic 599s, socket timeouts, and
  connection resets;
- capped/incomplete search results and interrupted pagination;
- a small metadata or downstream tail failure after tens of thousands of successful
  units, proving that compatible successes are retained and only unresolved units replay;
- process kill during request, pacing sleep, checkpoint write, and task completion;
- Mac reboot/resume, expired or missing GitHub authentication, stale lease, and duplicate
  coordinator startup;
- oversized query scope, disk-budget pressure, WAL growth, and backup failure; and
- an exhausted library beside healthy independent libraries.

Each case must prove request charging, lineage, public-only persistence, exact resume
behavior, final coverage diagnostics, non-publication on unresolved gaps, and concise
operator reporting.

## Spike deliverables

- A reproducible incident/benchmark dataset with per-library, per-pack, and per-partition
  runtime/request/state-size distributions.
- A comparison of candidate schedulers, pacing algorithms, checkpoint boundaries,
  supervision models, and storage policies.
- Recall/precision and hard-negative regression results for every scope optimization.
- Failure-injection and crash/restart evidence.
- A measured full and incremental weekly-capacity model for the current cohort and the
  projected all-CUDA-X portfolio.
- An adopt/modify/reject decision for every question above, with migrations and rollback
  plans for adopted changes.
- A final unattended-readiness report and explicit owner approval before automated collection is
  armed.
