# Contributing to CUDA-X Developer Intelligence

Thank you for your interest in improving CUDA-X Developer Intelligence.
External contributions are open and welcome, including code, tests,
documentation, detector evidence, usability improvements, and well-scoped
proposals.

All project participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Contribution scope

Contributions may address any public part of the source repository. Changes
must preserve the project's fail-closed public-data boundary, evidence
definitions, bounded collection model, and source-only distribution policy.

Open an issue for prior discussion before working on:

- new or materially changed detectors, evidence bands, or attribution rules;
- discovery, privacy, repository-visibility, or completeness semantics;
- state, fingerprint, budget, checkpoint, or publication contracts;
- large architectural changes, compatibility breaks, or performance claims;
- changes that require credentials, extensive network collection, or a full
  reconciliation to validate.

Generated adoption, citation, export, checkpoint, and dashboard artifacts under
`data/` are out of scope for pull requests. Security vulnerabilities are also
out of scope for public issues and pull requests; follow [SECURITY.md](SECURITY.md).

## Reporting bugs and proposing changes

- Use the GitHub bug-report form for reproducible incorrect behavior. Include
  the smallest practical reproducer, expected and actual behavior, and relevant
  environment details.
- Use the feature-request form for proposals. Describe the user problem,
  intended outcome, alternatives, and evidence or compatibility impact.
- Use the documentation form for missing, incorrect, or unclear documentation.
- Use the question form for best-effort help with public project workflows.
- The maintainer triages correctness, privacy, security, and evidence-integrity
  problems ahead of enhancements. The initial response SLA is seven calendar
  days; investigation, resolution, and implementation remain best effort.

## Development setup

Use Python 3.12 from a clean checkout. The collector has no third-party Python
package dependencies.

```bash
python3.12 -m collector.cli --help
python3.12 -m collector.cli plan --json >/dev/null
```

Git is required for collector and scanner tests. Node.js 24 is required for the
frontend checks.

### Tests and checks

Run the source checks before opening a pull request:

```bash
python3.12 -m compileall -q collector
python3.12 -m py_compile ops/smoke_scan.py ops/verify_req14_evidence.py
bash ops/run_tests.sh
bash -n refresh.sh ops/run_tests.sh
```

The default suite uses local fixtures and temporary repositories; it does not
need credentials or production data. Do not run `refresh`, `onboard`, a
citation collection, or a full reconciliation merely to test setup.

Changes to a reviewed detector must also update the evidence contract, pinned
positive and hard-negative cases, readiness material, and detector fingerprint
lock. A maintainer may request an explicitly bounded public-repository smoke
test when fixture evidence is insufficient.

### Coding conventions

- Preserve Python 3.12 compatibility and the standard-library-only runtime.
- Match the surrounding style and keep public interfaces documented.
- Fail closed when public visibility, required coverage, evidence, or budget
  state is incomplete or unresolved.
- Treat incomplete and unevaluated results explicitly; never convert them to
  zero.
- Never commit credentials, private links, local state, logs, caches, or
  generated `data/` artifacts.
- Add or update tests for behavior changes as needed.

## Performance-sensitive changes

Discuss performance-sensitive work in an issue first. Pull requests must
describe the workload, environment, baseline and changed measurements,
variability, correctness checks, and any memory, disk, network, recall, or
latency tradeoffs. Use bounded fixtures or an approved public smoke repository;
do not make production-scale claims from synthetic results.

## Pull request process

1. Link the issue or proposal when prior discussion is required.
2. Keep the change focused and update documentation and tests together with
   behavior.
3. Run the required source checks and list the exact commands and results in
   the pull request.
4. Explain evidence, privacy, compatibility, and performance impact where
   applicable.
5. Complete the pull request checklist and respond to review feedback.

Commit messages must follow
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

## Developer Certificate of Origin

All commits must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). Add the
sign-off when committing:

```bash
git commit -s -m "fix: describe the change"
```

The sign-off adds a `Signed-off-by: Name <email>` trailer certifying that you
have the right to submit the contribution. Pull requests containing unsigned
commits cannot be merged. If needed, amend or rebase your branch to add valid
sign-offs before requesting review.

## Review process

Pull requests are reviewed by the project maintainer,
[@rjensenNV](https://github.com/rjensenNV); see
[.github/CODEOWNERS](.github/CODEOWNERS) and
[MAINTAINERS.md](MAINTAINERS.md). The maintainer provides an initial response
within seven calendar days. If that window passes, comment on the pull request
to request a status update. Resolution and merge timing remain best effort.

## AI-assisted contributions

AI-assisted contributions are permitted with these requirements:

- **You are responsible:** Review and understand all AI-generated code before
  submitting it. Do not submit code you cannot explain or defend in review.
- **Verify correctness:** Run the test suite and review the diff carefully for
  subtle bugs and security issues.
- **No AI-generated sensitive content:** Do not use AI to generate security
  policies, legal text, or license headers; these require human judgment and
  legal review.
- **Disclose substantial AI assistance:** State in the pull request when a
  substantial portion of the change was AI-generated so reviewers can
  calibrate their review.

See [AGENTS.md](AGENTS.md) for instructions for coding agents working in this
repository.

## Security issues

Do not report security vulnerabilities through public issues or pull requests.
Follow the process in [SECURITY.md](SECURITY.md).
