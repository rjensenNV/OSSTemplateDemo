# REQ-14 benchmark and capacity evidence

Status: accepted for Phases 0–7 on 2026-07-28. Phase 8 remains the
owner-triggered production reconciliation and is intentionally not represented
by this benchmark.

## Verdict

The post-refactor scanner has enough measured margin for the REQ-14 capacity
goals on this Mac:

- Keep 14 processes for attended reconciliation/cold work.
- Keep 6 processes for normal warm changed work.
- Use 2,800 repositories/hour as the conservative reconciliation planning
  rate and 2,500 repositories/hour as the normal warm planning rate.
- The exact-final-source 14-worker confirmation measured 2,921.68
  repositories/hour on the history-heavy mature lane. Its linear scanner-only
  projection is 10.268 hours for 30,000 candidates and 20.536 hours for 60,000.
- The exact-final-source 6-worker confirmation measured 2,541.31
  repositories/hour. At the rounded-down 2,500/hour planning floor, 3,000
  changed repositories project to 1.20 scanner-hours.
- The exact-final-source direct-only clean-negative confirmation measured
  14,716.00 repositories/hour with 14 workers. This is evidence for the
  inexpensive common negative path, not a projection for the complete
  pipeline.
- Scanner capacity meets the 24-hour 30k reconciliation goal. The two-pass
  GraphQL design also fits that goal, but the two-hour weekly end-to-end goal
  is not proven for a worst-case 30k known-candidate universe: conservative
  two-pass GraphQL latency plus 3,000 changed scans already projects about
  2.41 hours before search, citations, validation, or publication. Actual
  warm runs should be materially smaller, especially in the final
  stable-ID visibility set; Phase 8 must measure that distribution.

These are capacity measurements, not adopter-count, completeness, or Phase 8
production claims.

## Frozen provenance

The final acceptance pair and direct-negative confirmation used:

| Item | Value |
|---|---|
| Final collector Python digest | `ed14f6daafdc2d83face5649a982b1c8a3e8d65a1ef1369681efb3a0119b1277` |
| Full scanner-matrix collector digest | `923ad82863a9ca0788f447bdfc64ac1bb91a3034a98deedf6ca1a887883cf149` |
| Collector Python files | 36 |
| Benchmark harness digest | `2890a1b62d6834f440429a67435c5becb939e7f058fcc37f626efc02a7c41a51` |
| Corpus digest | `21c9cab554ee9f6342729e706612e416cff9613b476fb619a8ddd53843e98728` |
| Git base | `f38e99a0a65fa82fca6cd942fb37ac4d68568742` plus the recorded working tree |
| Mac | `Mac16,7`, 14 CPU cores, 48 GiB RAM, macOS 26.5.2 |
| Runtime | Python 3.12.13; Apple Git 2.50.1 |

Every accepted report records start and end contexts. The collector and
benchmark harness digests were unchanged during each pass.

The complete 1/2/4/6/14 matrices and an immediate warm repeat used collector
digest `923ad828...`. That digest contains the exact final scanner, detector,
cache, security, and accuracy code. A subsequent planner-only change rounded
the two measured planning floors down in `collector/planner.py`: 2,500/hour
for normal warm work and 2,800/hour for reconciliation. The 6-worker mature,
14-worker mature, and 14-worker direct-negative confirmations were rerun at
digest `7e6a2ef0...` with unchanged semantic digests and outcome counts.

A final CLI-only change then added compare-subprocess session containment in
`collector/cli.py`, moving the collector digest from `7e6a2ef0...` to
`5e9a8bdd...`. Scanner, planner, pipeline, state, corpus, and harness code did
not change. The same three confirmations were rerun at that digest with
unchanged semantic results.

The commit gate then removed one extra blank line at EOF in
`collector/fingerprints.py`, moving the byte-level all-Python digest from
`5e9a8bdd...` to `ed14f6da...` without changing any function body or
semantics. Scanner, planner, pipeline, state, corpus, and harness behavior
remained unchanged, and all 64 pipeline tests passed. The three confirmations
were rerun once more against this final staged source. Their final values are
reported below.

## Corpus and method

The fixed public corpus contains 105 repositories:

- ten centered popularity samples from each language/classification stratum;
- five explicit outliers, including OneFlow, CuPy, FlashInfer, CMake, and
  vLLM;
- two serialized giant-cache outliers;
- immutable pinned HEADs and public GitHub `diskUsage` estimates.

The mature lane intentionally over-represents history work: 88 repositories
matched at least one library and 17 were clean rejects. The direct-negative
lane applies the real `cudaq-qec` and `cudaq-solvers` direct-only detectors to
104 valid clean-negative repositories. `yhw-yhw/SHOW` is excluded from that
performance lane because its own-source notebook is malformed; the scanner
correctly fails closed. This is a documented correctness refusal, not a
silently omitted production result.

Scanner passes used existing public bare caches, immutable HEADs, no GitHub
credentials, a disabled credential helper, and a 240-second per-repository
deadline. Passes ran sequentially with no overlapping collector or benchmark
processes and the host otherwise held idle. They made no discovery, metadata,
citation, publication, or production-data changes.

## Worker matrix

### Direct-only clean-negative lane

| Workers | Wall time | Throughput | Peak descendant RSS |
|---:|---:|---:|---:|
| 1 | 205.483s | 1,822.05 repos/h | 1.10 GiB |
| 2 | 191.926s | 1,950.75 repos/h | 0.88 GiB |
| 4 | 65.080s | 5,752.89 repos/h | 1.64 GiB |
| 6 | 39.604s | 9,453.62 repos/h | 2.09 GiB |
| 14 | 28.573s | 13,103.16 repos/h | 3.33 GiB |

All five passes produced stable digest
`56b8bf6d6420dd71be264adee1addcf31e5f4efba562f013c04825d57be7a753`,
zero unresolved outcomes, 882 Git subprocesses, zero clone/fetch operations,
zero materialized bytes, and zero cache growth.

The small gain from one to two workers is structural: the coordinator reserves
one process for serialized giants, leaving only one ordinary worker at a total
worker count of two. Four and above provide actual ordinary-lane parallelism.

### Mature/history-heavy lane

| Workers | Wall time | Throughput | Peak descendant RSS |
|---:|---:|---:|---:|
| 1 | 845.382s | 447.14 repos/h | 4.24 GiB |
| 2 | 734.313s | 514.77 repos/h | 5.23 GiB |
| 4 | 235.387s | 1,605.86 repos/h | 5.12 GiB |
| 6 | 149.184s | 2,533.79 repos/h | 6.76 GiB |
| 14 | 132.414s | 2,854.68 repos/h | 9.05 GiB |

Every matrix pass produced stable digest
`20b104650db72450bacf47b841e6447751d17663a3eec1a422f81c875318bbef`,
88 matches, 17 clean rejects, zero unresolved outcomes, and no
deadline overrun. Each pass examined 345,753 eligible files and
4,307,102,504 bytes, with 5,326 policy-pruned large assets and zero oversized
eligible own-source skips.

An immediate 14-worker warm repeat on the same exact scanner digest completed
in 126.342s at 2,991.88 repositories/hour with 7.84 GiB peak RSS, the same
88/17 outcomes and semantic digest, and zero fetches or cache growth. This
4.6% improvement over the 132.414s matrix run is the observed warm-run
variance, not a higher planner floor.

Four workers clear the 1,500/hour cold floor, but six are needed to clear the
2,000/hour changed-work target with useful margin. Fourteen add 77.8% over
four and 12.7% over six. The 11.2% wall-time reduction from six to fourteen
costs 33.8% more peak RSS in the full matrix. That supports 14 for attended
reconciliation, while six retain the normal default because they meet the
warm target with lower memory and process overhead for smaller weekly task
sets.

## Final-source confirmations and hydrating limitation

The final collector digest was confirmed on the same frozen warm cache:

| Pass | Wall | Throughput | Outcome | Peak RSS |
|---|---:|---:|---|---:|
| Mature, 6 workers | 148.742s | 2,541.31 repos/h | 88 match / 17 reject | 7.26 GiB |
| Mature, 14 workers | 129.378s | 2,921.68 repos/h | 88 match / 17 reject | 7.53 GiB |
| Direct-negative, 14 workers | 25.442s | 14,716.00 repos/h | 104 clean reject | 3.30 GiB |

All three final-digest passes had zero errors, unresolved work, clone/fetch
operations, materialized bytes, or cache growth. Mature passes retained
digest
`20b104650db72450bacf47b841e6447751d17663a3eec1a422f81c875318bbef`;
the direct pass retained digest
`56b8bf6d6420dd71be264adee1addcf31e5f4efba562f013c04825d57be7a753`.
The final 6- and 14-worker rates remain above their rounded-down 2,500/hour
and 2,800/hour planner floors.

An exact-final-source hydrating repeat is not honestly available. The retained
`cold14g` cache has 105/105 entries whose `head_sha` equals
`current_tree_blob_head` and whose policy is exactly
`blob-limit-1000000+sparse-v1`. A prior pass already consumed the missing
objects. Recreating missing objects would require destructive pruning,
metadata resets, or a fresh network clone, so it was not done.

Earlier transport-only evidence is retained, but it is explicitly from prior
collector digest `4e8117d8...`: 105/105 repositories completed in 113.613s
with 13 fetches and 1,986,035 local materialized object bytes, zero errors,
and the same mature semantic digest. Its -17,576,072-byte net cache delta was
valid concurrent LRU/prune behavior. This proves the cache accounting and
hydration mechanism on the pinned corpus; it is not represented as an
exact-final-source semantic acceptance pass.

No fresh clone test is claimed. One pinned corpus repository disappeared from
public GitHub after the corpus was frozen, so a credential-free fresh
105-repository clone would no longer reproduce the same corpus.

## SLO projections

| Scenario | Rate used | 30,000 candidates | 60,000 candidates |
|---|---:|---:|---:|
| Final measured mature, 14 workers | 2,921.68/h | 10.268h | 20.536h |
| Conservative reconcile planner | 2,800/h | 10.71h | 21.43h |
| Final measured mature, 6 workers | 2,541.31/h | 11.805h | 23.610h |
| Normal warm planner if all changed | 2,500/h | 12.00h | 24.00h |
| Final direct-negative current-tree lane | 14,716.00/h | 2.039h | 4.078h |

The direct-negative row excludes discovery and every later pipeline stage.
The full-reconcile rows are scanner-only. The weekly two-hour case depends on
persisted state and the specified reuse gate; it must not silently convert
into an all-changed reconciliation.

The final measured mature reconcile rate leaves 13.732 hours before the
24-hour 30k target and 27.464 hours before the 48-hour 60k stress target.
Phase 8 must measure actual discovery, metadata, citation, validation,
checkpoint, and publication overhead before production closure.

The GraphQL architecture deliberately has two passes: initial authoritative
metadata/HEAD resolution, then a pre-install visibility pass over the stable
node IDs in the would-be publication. At the selected 50-repository shape,
the conservative planner assumes one point per batch and charges both passes:

| Universe | Initial batches | Final batches | Total points | Remaining from 5,000 | Final-pass serial latency |
|---:|---:|---:|---:|---:|---:|
| 30,000 | 600 | 600 | 1,200 | 3,800 | 42.76m |
| 60,000 | 1,200 | 1,200 | 2,400 | 2,600 | 85.52m |

Both envelopes stay within the 2,500-point run budget, the 2,500 remaining
quota reserve, and the 120-minute final-visibility freshness limit. The 60k
quota case has only 100 points of reserve margin. Using the planner's
3.0-second initial-batch assumption plus the measured 4.276-second
final-batch latency, two-pass GraphQL contributes up to 72.76 minutes at 30k
and 145.52 minutes at 60k. Therefore:

- 30k reconciliation remains comfortably inside 24 hours when scanner and
  GraphQL projections are combined: the 2,800/hour scanner floor plus both
  GraphQL passes totals about 11.93 hours before search and publication,
  leaving about 12.07 hours of target margin.
- 60k remains inside the 48-hour stress envelope, but has little GraphQL point
  margin for unexpected extra batches. Scanner plus two-pass GraphQL projects
  about 23.85 hours before other stages, leaving about 24.15 hours of stress
  margin.
- A worst-case weekly model with 3,000 changed scans plus both GraphQL passes
  over 30,000 IDs exceeds two hours before other stages. The real final pass
  covers publishable stable IDs, not necessarily every discovered candidate,
  so Phase 8 must measure actual initial/final set sizes before treating the
  two-hour weekly goal as closed.

## Method A/B and semantic parity

The bare current-tree method was compared with sparse worktrees over all 105
repositories in three trials per method:

| Method | Median wall |
|---|---:|
| Sparse worktree | 804.071563s |
| Bare `ls-tree` plus batched `cat-file` | 17.438482s |

The bare method was 46.109 times faster. Both methods agreed on 206,628
eligible text paths, 20 binary exclusions, 159 policy skips, and the complete
path-set digest. Results were stable across all trials.

Raw bytes differed only for two declared CRLF fixtures in each of two related
CMake repositories: 28 checkout-added carriage-return bytes in total.
`.gitattributes` explicitly declares `eol=crlf` for those files. Canonical
blob content and checkout content match after the declared Git filter
normalization. The production reader now uses one persistent
`cat-file --batch --filters -Z` stream for standard transforms and safely
falls back to a worktree on older Git or correctness-sensitive custom filters.

This optimization also fixed the direct-only MCP outlier: the pinned scan
moved from an error after 146.041 seconds and 3,321 Git subprocesses to a
clean reject in 6.783 seconds and 8 subprocesses, a 21.5-times speedup and
415-times fewer subprocesses. Copied projects below explicit
`deployment`/`fixture`/`corpus` source roots no longer contribute host
adoption evidence.

The mature goldens pass:

- Chapel retains targeted NVSHMEM at `8fdcdde03f4c`, dated 2025-09-18.
- AOSP/PyTorch retains bundled NVPL and targeted NVSHMEM with hydrated first
  commits/dates.
- MCP remains empty, rejecting output-only base64 and copied-project
  collisions.

These goldens specifically demonstrate that the mature
confirmed/bundled/targeted distinctions are preserved while the new large
libraries remain direct-confirmed only.

## GraphQL batch bake-off

One bounded aggregate metadata/HEAD query per shape produced:

| Batch | GraphQL points | Elapsed | Result | Quota remaining |
|---:|---:|---:|---|---:|
| 10 | 1 | 1.300s | 10 OK | 4,996 |
| 25 | 1 | 2.130s | 25 OK | 4,995 |
| 50 | 1 | 4.276s | 49 OK, 1 isolated partial | 4,994 |

The 50-node shape remains selected: it has the same one-point observed cost
with fewer requests. The partial is the repository that disappeared after
the corpus was pinned, not a batch-shape failure. Partial errors remain
per-node and do not poison successful public rows. No 403/429 occurred, and
quota remained well above the 50% reserve.

The bake-off times one batch shape, not the whole two-pass protocol. The
planner applies the selected 4.276-second result to every serial final
visibility batch and independently budgets the initial metadata pass. Both
passes share the same same-run point journal across retries/epochs, so a
failed final gate cannot reset spent quota. This is why the capacity model
counts two passes and why the 60k reserve is called out above.

## Noise, transfer, and acceptance limits

- Interface byte deltas are host-wide observations on a shared Mac interface.
  They include unrelated traffic and are not used as proof of Git transfer.
- Collector-instrumented clone/fetch counts and local object growth are the
  authoritative run-budget observations. Local materialized bytes are not
  wire bytes.
- The worker matrix used warmed pinned objects to isolate scanner scaling.
  Prior-digest hydrating evidence separately exercised real missing-object
  fetches. No exact-final-source hydrating claim is made because no honest
  stale cache remained.
- Peak RSS is a descendant-process sample. All accepted passes stayed below
  the 16 GiB ceiling; the production pipeline also enforces the ceiling.
- The benchmark cache hard stop was 25 GiB. Production uses the separately
  enforced 200 GiB target and 250 GiB hard stop.
- The one malformed-notebook exclusion applies only to the clean-negative
  performance lane. A selected production task remains fail-closed and cannot
  publish an incomplete result.
- This work did not run discovery, a production reconciliation, citations, or
  publication; did not write production state/data; and did not arm automated collection.

Local detailed evidence is retained under
`.state/req14-benchmark/reports/`, including the worker reports, final
source confirmations, prior-digest hydrating report, GraphQL bake-off, method
A/B report, and semantic line-ending audit.
