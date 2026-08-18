# REQ-14 Phase 7 detector review

> Historical Phase 7 record. The stricter Phase 8 approval authority is
> `docs/REQ14-PHASE8-READINESS.md` plus the machine-readable evidence contract
> and fingerprint lock. It approves 44 direct detectors and keeps
> `cuda.compute` and `cuda.parallel` out of collection scope; its later selective lower-band certifications supersede the
> confirmed-only Phase 7 policy described below.

This is the bounded acceptance record for the direct-integration detector
batches added before the first production reconciliation. It is not a claim
that GitHub has been exhaustively collected. The owner-triggered Phase 8 run
remains the production coverage and adoption-count acceptance event.

## Classification contract

- Existing mature libraries keep their `confirmed`, `bundled`, and `targeted`
  evidence and historical dates. This includes the established Dx, DALI,
  cuQuantum, NVPL, NVSHMEM, nvmath, cuPQC, and ovrtx surfaces.
- The REQ-14 additions are deliberately narrower: only reviewed direct
  own-source includes, imports, or API use can produce `confirmed`. Their
  `bundled` and `targeted` fields are `not_evaluated`, not zero.
- Component evidence remains separately auditable. Parent cards use a unique
  repository union, so a repository using a parent and several components is
  counted once in the family and once in the portfolio.
- Framework-mediated and transitive use is deferred. A framework install or a
  backend selection without direct library evidence cannot become confirmed.
- Public visibility must be resolved independently. NVIDIA-owned repositories,
  forks, mirrors, generated environments, vendor copies, local shadow headers,
  and copied upstream projects are excluded or classified below the headline.

## Batch implementation

| Batch | Direct detector scope | Required evidence |
|---|---|---|
| Math | cuBLAS/Lt/Xt/Mp, cuFFT/Xt/Mp, cuRAND, cuSOLVER/Mp, cuSPARSE/Lt, cuTENSOR, cuDSS, AmgX | Exact SDK include or reviewed API surface in host-owned source |
| Scientific, physics, quantum | cuEquivariance, Warp, PhysicsNeMo, CUDA-Q QEC, CUDA-Q Solvers | Executable, non-shadowed import plus distinctive API use where the namespace can collide |
| Deep learning and parallel | cuDNN, TensorRT, TensorRT-LLM, CUTLASS, FlashInfer, Thrust, CUB | Exact header/prefix or executable direct import in host-owned source |
| Data | cuDF, cuVS, cuML, cuOpt, cuGraph, NeMo Curator, Morpheus, nvCOMP, GPUDirect Storage | Executable direct import or exact SDK include |
| Image and video | nvImageCodec, CV-CUDA, cuCIM, NPP, Video Codec SDK, Optical Flow SDK | Executable direct import or exact SDK include |
| Communication | NCCL, NIXL | Exact SDK include or executable direct import; existing NVSHMEM continues through its mature three-band detector |

Every declaration has a positive fixture and collision-negative coverage. The
suite also exercises vendor/environment/generated paths, NVIDIA ownership,
copied projects, local module and header shadows, parent/component rollups,
dating anchors, and direct-only `not_evaluated` publication semantics.

## Discovery coverage plan

For every declared direct signal, Sourcegraph uses the reviewed literal
header/import query as weekly broad recall and requires a terminal stream with
no unexpected skip. GitHub code search uses the same signal as the
GitHub-native coverage authority. A result window above 1,000 is recursively
partitioned by relevant extension and supported `size:` ranges until every
leaf is exhaustively paged. An unsplittable, capped, incomplete, timed-out, or
malformed leaf makes that source/library epoch incomplete.

The weekly GitHub lane rotates, but every active detector must receive complete
GitHub coverage within 28 days. An attended reconciliation completes both
sources for every active signal. Absence from one source never deletes prior
evidence; retirement requires complete source coverage plus current public
metadata and current-tree resolution.

## Human sample review

On 2026-07-28, a bounded public search sample reviewed 93 fragments across 47
review lanes: all 46 new direct detectors plus the existing mature NVSHMEM
lane (one query shape and at most two results per library).
Human review found 29 clear direct-positive fragments, 61 collision-negative,
non-direct, or configured-exclusion fragments, one ambiguous wrapper fragment,
and two classifier mistakes. The two mistakes were `inikep/lzbench`'s vendored
nvCOMP header and `ROCm/RIXL`'s own `nixl.h`; both are now named production
scanner regression fixtures and the copied/local-header guards reject them.
The report is precision evidence only: it cannot establish
historical recall, alternate-query recall, or that a library without a positive
top-two fragment has no adopters.

The per-library review was stratified rather than relying on popularity-ranked
public results alone. Each new detector was reviewed against its direct-positive
golden fixture, at least one collision/local-shadow/vendor/docs negative, and
its bounded public candidate fragments below; NVSHMEM used its mature
confirmed/targeted fixtures plus the same public comparison. Thus every lane
has positive and negative classification evidence even when the two public
fragments happened to be first-party, documentation-only, or collisions. This
is detector precision and bounded candidate evidence, not a substitute for the
complete Phase 8 source epochs.

| Library | Human-reviewed sample result | Acceptance disposition |
|---|---|---|
| cuBLAS | Two external exact-header positives | Supported |
| cuBLASLt | StarPU direct; Paddle local-wrapper occurrence ambiguous alone | Supported with local-wrapper guard |
| cuBLASXt | Two external exact-header positives | Supported |
| cuBLASMp | Two NVIDIA first-party results | No external positive in bounded sample |
| cuFFT | NERSC direct; local-wrapper collision | Supported |
| cuFFTXt | ZLUDA direct; copied SDK definition negative | Supported |
| cuFFTMp | IPPL direct; exact excluded copied GROMACS repository | Supported with exact-exclusion regression |
| cuRAND | Two external exact-header positives | Supported |
| cuSOLVER | ArrayFire direct; NVIDIA/AMGX first-party | Supported |
| cuSOLVERMp | Documentation/build-only fragments | No external direct positive in bounded sample |
| cuSPARSE | Two external exact-header positives | Supported |
| cuSPARSELt | Two external exact-header positives | Supported |
| cuTENSOR | DaCe direct; local wrapper occurrence negative alone | Supported |
| cuDSS | PyTorch direct; NVIDIA/MatX first-party | Supported |
| AmgX | Build-only fragments | No external direct positive in bounded sample |
| cuEquivariance | External configured import; NVIDIA first-party | Supported |
| Warp | NVIDIA first-party fragments | No external positive in bounded sample |
| PhysicsNeMo | NVIDIA first-party fragments | No external positive in bounded sample |
| CUDA-Q QEC | NVIDIA first-party documentation | No external positive in bounded sample |
| CUDA-Q Solvers | NVIDIA first-party documentation | No external positive in bounded sample |
| cuDNN | External wrapper includes SDK; install-doc negative | Supported |
| TensorRT | ONNX-TensorRT direct; copied SDK header negative | Supported |
| TensorRT-LLM | Nesa direct; install-doc negative | Supported |
| CUTLASS | Documentation-only fragments | No external direct positive in bounded sample |
| FlashInfer | FlashMLA direct; install-script negative | Supported |
| Thrust | Name/attribution documentation collisions | No external direct positive in bounded sample |
| CUB | Vendor/download documentation and NVIDIA first-party | No external direct positive in bounded sample |
| cuda.compute | NVIDIA first-party samples | No external positive in bounded sample |
| cuda.parallel | Documentation-only fragments | No external direct positive in bounded sample |
| cuDF | RAPIDS first-party repositories | No external positive in bounded sample |
| cuVS | OpenViking direct; NVIDIA first-party | Supported |
| cuML | Install/release documentation | No external direct positive in bounded sample |
| cuOpt | Local-module import and documentation collisions | Alternate-shape recall review remains Phase 8 work |
| cuGraph | PyG direct; NVIDIA first-party | Supported |
| NeMo Curator | NVIDIA first-party documentation/benchmark | No external positive in bounded sample |
| Morpheus | Official first-party repositories | No external positive in bounded sample |
| nvCOMP | First-party DALI and vendored lzbench header | No external positive; vendor regression fixed |
| GPUDirect Storage | NVIDIA/DALI first-party | No external positive in bounded sample |
| nvImageCodec | OpenHUTB direct; RAPIDS first-party | Supported |
| CV-CUDA | Official first-party repositories | No external positive; owner exclusion verified |
| cuCIM | Slideflow direct; documentation collision | Supported |
| NPP | First-party and copied SDK header | No external positive in bounded sample |
| Video Codec SDK | Two copied header definitions | No external positive in bounded sample |
| Optical Flow SDK | Patch-path fragment | No external positive in bounded sample |
| NCCL | Two external exact-header positives | Supported |
| NIXL | RIXL self-header collision | No external positive; local-header regression fixed |
| NVSHMEM | ParRes direct; PyTorch build-only evidence | Mature confirmed/targeted distinction preserved |

## Accuracy corrections from the review

The final detector path:

- applies global exact exclusions and per-library vendor profiles during
  candidate admission, V1 carry-forward, state retirement, scan selection, and
  publication;
- applies NVPL's separate copied-backend profile, including preserved
  parent/source lineage;
- rejects a project-owned exact header as proof of the external SDK while still
  allowing a local wrapper that includes the genuine SDK header;
- distinguishes internal extension/monorepo manifests from copied nested
  projects;
- parses executable notebook code with Jupyter magics and literal
  `__import__` calls;
- rejects distinctive copied Darknet, Paddle, GGML/Ollama, PyTorch, CMake,
  Kokkos, CUDA Samples, fake CUDA/NCCL, CUTLASS, and Isaac-GR00T roots without
  suppressing canonical/host integrations; and
- rejects documentation/agent-skill and embedded-token/base64 collisions in
  mature fallback evidence.

The frozen 105-repository scanner corpus exercises 37 of the 58 configured
detectors through the real production path. Synthetic full-registry fixtures
exercise all 46 new declarations together and independently.

The final focused replay on 2026-07-28 also corrected the bounded smoke utility
itself: it had still called the retired V1 scanner and therefore could not
validate the production path. The replacement resolves only the named public
HEADs, runs the real V2 one-pass scanner with one worker and a disposable
cache, and never writes production data.

That replay found one additional copy-layout gap in `inikep/lzbench`: complete
nvCOMP and libbsc source distributions lived below generic `misc/` and `bwt/`
roots. Signature-based embedded-project guards now exclude the nvCOMP, GDS,
CUB, and Thrust evidence inside those copied distributions without treating a
normal host wrapper as vendor code. The final bounded V2 result for lzbench is
a clean reject. `ROCm/RIXL` no longer reports NIXL from its project-owned
`nixl.h`; its independently valid GDS and mature NVSHMEM direct integrations
remain. Both named public replays completed inside the 120-second
per-repository bound.

## What remains for Phase 8

The first attended reconciliation must review every source coverage
certificate, unresolved candidate count, public-visibility decision, detector
sample, citation cap/error, parent rollup, runtime budget, and proposed release
delta. Libraries without a clear positive in this bounded sample receive
additional review during that run. No expanded portfolio count, completeness
percentage, production runtime, or cache-hit claim is accepted before that
owner review.
