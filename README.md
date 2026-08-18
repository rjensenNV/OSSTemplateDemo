# CUDA-X Developer Intelligence

CUDA-X Developer Intelligence is a Python collector and static dashboard for
analyzing public third-party software and research adoption of NVIDIA CUDA-X
libraries. Contributions are open and welcome.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![DCO: required](https://img.shields.io/badge/DCO-required-blue.svg)](CONTRIBUTING.md#developer-certificate-of-origin)
[![Tests](https://github.com/rjensenNV/OSSTemplateDemo/actions/workflows/tests.yml/badge.svg)](https://github.com/rjensenNV/OSSTemplateDemo/actions/workflows/tests.yml)
![Python: 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Project status: Preview](https://img.shields.io/badge/Status-Preview-f5a623)

External Support and resolution are best
effort through GitHub Issues; the maintainer provides an initial response to
issues and pull requests within seven calendar days.

## Overview

The project discovers public GitHub repositories with auditable evidence of
direct CUDA-X use, dates first adoption, preserves weaker evidence in separate
classification bands, identifies visible AI-assistance markers, and connects
OpenAlex research mentions to confirmed public adopters.

Key capabilities include:

- Composite Sourcegraph and partitioned GitHub code-search discovery with
  machine-readable completeness certificates.
- Explicit public-visibility checks before repositories enter state and again
  immediately before local publication.
- Evidence bands that keep confirmed own-source integration separate from
  declared, bundled, targeted, and unevaluated evidence.
- Cached OpenAlex research enrichment and bounded public source extraction.
- Content-addressed, lazily loaded static artifacts with manifest-last
  publication and deterministic JSONL/CSV exports.

## Quick start

From a clean checkout, inspect the collector's read-only plan without
credentials or network collection:

```bash
python3.12 -m collector.cli plan --json |
  python3.12 -c 'import json,sys; p=json.load(sys.stdin); print("mode={} cold_state={}".format(p["mode"], p["cold_state"]))'
```

Which should print:

```text
mode=refresh cold_state=True
```

This command plans work only. It does not collect repositories, create public
claims, or require generated data.

## Requirements

- Pyhton 3.12
- Git
- Node.js 24 for frontend validation
- A modern browser to view a locally generated dashboard

## How collection works

The supported pipeline is stateful and makes work proportional to new,
changed, or invalidated repository/library evidence:

1. **Plan** — compare discovery, detector, dating, aggregation, citation,
   catalog, and presentation fingerprints before network work.
2. **Discover** — use recursively partitioned GitHub code search for required
   GitHub-native coverage.
3. **Resolve public metadata** — batch GitHub metadata and require explicit
   public visibility, a stable repository identity, a current default branch
   and HEAD, and non-fork/non-archived state.
4. **Scan bounded content** — inventory exact public trees, reuse persistent
   partial clones and fetch bounded history only for positive dating and enrichment.

`confirmed` evidence—an include, import, API, or symbol used by the
repository's own source—is the headline metric. `declared`, `bundled`, and
`targeted` evidence remains secondary. A lower evidence band is enabled only
when the reviewed evidence contract defines exact qualifying syntax; all other
bands remain `not_evaluated`.

## Collector commands

Run commands from the repository root using Python 3.12:

```bash
# Read-only and no network:
python3.12 -m collector.cli plan --json

# Fixture-only detector comparison:
python3.12 -m collector.cli compare

# Maintainer-operated bounded weekly local collection:
python3.12 -m collector.cli refresh

# Validate locally generated V2 artifacts:
python3.12 -m collector.cli validate

# Explicit attended full reconciliation:
python3.12 -m collector.cli plan --mode reconcile --json
python3.12 -m collector.cli reconcile --confirm-full
```

Do not use `refresh`, `onboard`, or `reconcile` as setup tests. Use
`./refresh.sh --check`, the read-only planner, local tests, or an explicitly
bounded smoke repository.

## Research citations

Each research-enabled library uses a distinctive OpenAlex query. Results are
reported as full-text-indexed mentions, not verified use or a complete research
census. The collector records query freshness, caps, errors, and carry-forward
state separately from adoption completeness.

An OpenAlex API key can be supplied through `OPENALEX_API_KEY` or a mode-600
`~/.config/openalex-api-key`. Operators may set `OPENALEX_MAILTO` to a public
contact address for polite-pool identification. The project does not embed a
maintainer's personal address in network requests.

## Known limitations

- No adoption or citation result dataset is shipped with the source snapshot.
- Public indexes cannot prove literal completeness after evidence has been
  removed before either discovery source observes it.
- AI-assistance markers are a lower bound; many tools and workflows leave no
  public commit marker.
- OpenAlex full-text mentions are a floor, and a mention does not prove that a
  paper used the library.
- First-adoption dates follow public Git author dates and can move after a
  squash or rebase.

## Development

Run the same source checks used by public CI:

```bash
python3.12 -m compileall -q collector
python3.12 -m py_compile ops/smoke_scan.py ops/verify_req14_evidence.py
bash ops/run_tests.sh
bash -n refresh.sh ops/run_tests.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution scope, development
rules, the DCO sign-off requirement, and the pull request process. Architecture
and operating details are in
[docs/Documentation.md](docs/Documentation.md); the evidence and design history
is in [docs/PROJECT-CONTEXT.md](docs/PROJECT-CONTEXT.md).

## Support and contributions

- Bug reports, questions, feature proposals, and documentation requests:
  GitHub Issues
- Initial response: within seven calendar days
- Resolution and implementation: best effort
- Contribution scope: open to external contributions of all kinds
- Legal contribution requirement: commit sign-off under the
  [Developer Certificate of Origin](https://developercertificate.org/)
- Maintainer: [MAINTAINERS.md](MAINTAINERS.md)

All project participants must follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests. Follow [SECURITY.md](SECURITY.md) to report them
privately.

## License

The software and project-authored documentation in this repository are
licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

Third-party components remain under their respective terms. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and preserved
license material.
