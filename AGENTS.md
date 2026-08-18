# Agent Guidance for CUDA-X Developer Intelligence

## Project context

CUDA-X Developer Intelligence is a standard-library-only Python 3.12 collector
and static dashboard for public third-party and research adoption of NVIDIA
CUDA-X libraries. The project is active and in preview. This public source
repository intentionally excludes generated adoption and citation data.

Read these files before changing behavior:

- `CONTRIBUTING.md` — public contribution and review policy.
- `docs/PROJECT-CONTEXT.md` — architecture, live state, and design history.
- `docs/REQUIREMENTS.md` — point-in-time, host-agnostic requirements mirror.
- `docs/Documentation.md` — maintainer and operator runbook.
- `README.md` — public methodology and local usage.

## Repository map

| Path | Purpose |
| --- | --- |
| `collector/cli.py` | Supported command surface |
| `collector/pipeline.py`, `planner.py` | Orchestration, invalidation, and budgets |
| `collector/discovery/` | Sourcegraph and partitioned GitHub discovery |
| `collector/repo_cache.py`, `scan.py`, `scanner_v2.py` | Bounded Git materialization and evidence classification |
| `collector/state.py` | SQLite operational state and checkpoint export |
| `collector/citation_pipeline.py` | Cached OpenAlex/CFF enrichment |
| `collector/publish_v2.py`, `validate_v2.py` | Content-addressed publication and validation |
| `collector/req14_evidence_contract.json` | Reviewed detector evidence boundary |
| `ops/req14_detector_fingerprints.json` | Approval-time detector lock |
| `data/` | Ignored local generated artifacts; never add to source commits |
| `tests/` | Offline Python and JavaScript regression suites |
| `web/` | Static V2-only dashboard |

Use `rg` and targeted reads. Never add generated repository, citation,
checkpoint, or dashboard data to this public source repository.

## Build, test, and verify

Required tools are Python 3.12, Git, and Node.js 24. No package installation is
required. Run from the repository root:

```bash
python3.12 -m compileall -q collector
python3.12 -m py_compile ops/smoke_scan.py ops/verify_req14_evidence.py
bash ops/run_tests.sh
bash -n refresh.sh ops/run_tests.sh
```

Read-only and fixture-only checks:

```bash
python3.12 -m collector.cli plan --json
python3.12 -m collector.cli compare
python3.12 ops/verify_req14_evidence.py --band all
```

Do not run a collector or citation command merely to test setup. Use `--help`,
the read-only planner, local tests, or one explicitly bounded smoke repository.

## Project guardrails

- Preserve the public-only boundary. Discovery, metadata admission, state,
  checkpoints, final visibility, and publication must fail closed for private
  or unresolved repositories.
- Coverage failure is not zero. Incomplete required discovery, unresolved
  metadata, exhausted budgets, or unresolved scans block publication.
- `confirmed` means own-source include/import/API use. Weaker evidence remains
  a separate declared, bundled, or targeted band. Unevaluated bands remain
  `not_evaluated`/`null`.
- Do not enable or change a detector without updating the evidence contract,
  positive and hard-negative validation, readiness material, and fingerprint
  lock.
- A detector edit invalidates only affected repository/library pairs. A shared
  engine semantic change can still require a reviewed full reconciliation.
- V2 loads only `data/v2/manifest.json` initially. The manifest is at most
  250 KiB, each non-manifest artifact is strictly below 4,000,000 encoded
  bytes, and every artifact is strictly below 5 MiB.
- Do not propagate the retired V1 `repo_keys` field into V2 artifacts.
- Use `collector.cli onboard`; never use the retired `collector.run` or
  `onboard_merge` command paths.
- `refresh.sh` is maintainer-operated. CI must test and validate only; it must
  never collect or use production credentials. Its generated output stays
  local under ignored `data/`.
- Never print, commit, or place GitHub/OpenAlex credentials in URLs. Collector
  child processes must not inherit collection credentials unnecessarily.
- Do not claim full-portfolio recall, performance, cache efficiency, or counts
  without a separately reviewed result set and its validation records.
- Preserve unrelated work. Never force-push or rewrite history as part of an
  ordinary contribution.
- Treat `LICENSE`, `SECURITY.md`, `.github/CODEOWNERS`, and evidence
  locks as controlled surfaces; change them only when the request explicitly
  requires it.
- The confirmed initial-response SLA for public issues and pull requests is
  seven calendar days. Do not add other support, roadmap, security-response,
  or resolution-time commitments without maintainer confirmation.

Security vulnerabilities must not be discussed publicly. Follow
`SECURITY.md`.
