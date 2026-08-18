# REQ-14 Phase 8 pre-collection readiness

Review date: 2026-07-28
Contract: `req14-phase8-precollection-v3-2026-07-28` (cuSPARSELt
confirmed-only scope revision: 2026-07-29)

This is the approval artifact for the attended Phase 8 reconciliation. It is
not a production collection. The machine-readable authority is
`collector/req14_evidence_contract.json`; the approved implementation hashes
are frozen in `ops/req14_detector_fingerprints.json`.

## Evidence boundary

- The 12 mature detectors retain their shipped confirmed,
  bundled/declared, targeted, component, and DALI-operator behavior.
- The 44 enabled REQ-14 detectors all evaluate confirmed direct use.
- Nineteen Python-distributed libraries additionally evaluate the shared
  bundled band under the published label **Declared**. Only an exact official
  distribution in a structurally parsed authored dependency surface qualifies.
- Fifteen libraries additionally evaluate **Targeted**. Only an exact reviewed
  imported/link target in qualifying authored CMake syntax qualifies.
- `cuda.compute` and `cuda.parallel` are out of collection scope by owner
  decision. Their official catalog rows remain visible as
  `metric contract pending`, with all three bands `not_evaluated`.
- Framework/transitive attribution remains deferred. In particular, low-level
  CUDA component wheels found in framework lock/freeze output are not used to
  infer cuBLAS, cuDNN, cuSPARSE, and similar libraries in this pass.
- Discovery roots only nominate files. The classifier rechecks exact syntax,
  exact package/target allowlists, host ownership, public visibility, and all
  collision/vendor/generated/environment/local-shadow exclusions.
- Operators/components are never inferred from a declaration or link target.
  Existing parent rollups remain unique-repository projections of direct child
  evidence.

## Validation record

The bounded verifier `python3.12 ops/verify_req14_evidence.py --band all`
reads only frozen public GitHub metadata and pinned files. It performs no
discovery, clone, history scan, state mutation, collection, or publication.
The combined replay checked 74 pinned files in 69 active public repositories.

- Confirmed: **44/44 libraries** and **45/45 pinned surface positives** replayed
  through production triage (42 public non-fork/non-archived repositories; 44
  unique files).
- Declared/bundled: **19/19** pinned external positives replayed through the
  structural manifest parser (16 repositories/files).
- Targeted: **15/15** pinned external positives replayed through the reviewed
  CMake classifier (14 repositories/files).
- Synthetic exhaustive replay covers all **30** approved distribution names
  and all **55** approved CMake/link targets.
- Hard negatives cover comments, prose/strings, near names, invalid
  requirements, directives/options/group keys/channels, CMake message and
  unrelated assignments, case errors, vendor/generated/environment/skill and
  embedded paths, and project-local Python/header shadows.
- Evidence-bearing malformed manifests fail the repository; they never become
  a silent clean negative.

## Attended live-protocol correction

The first attended attempt, run `20260728T183014Z-967fbad8`, was deliberately
stopped during discovery after 38 of 260 query tasks. It installed no candidate
release and changed no public data.

- Sourcegraph's documented stream ends with `progress` carrying `done=true`
  followed by a required final `event: done`. The pre-production fixture
  incorrectly ended after the progress event, so every live Sourcegraph result
  was quarantined as incomplete. Discovery engine version 3 now requires and
  validates both terminal markers.
- Live GitHub code search returned distinct public results beyond both its
  reported `total_count` and advertised last page. Discovery engine version 3
  therefore stopped using GitHub's advertised pagination boundary and
  recursively divided the declared extension/size universe.

The second attended attempt, run `20260728T185913Z-2d9811ee`, was deliberately
stopped on its first GitHub task. It also installed no candidate release and
changed no public data. The live endpoint exposed two additional cases that the
fixtures had not modeled: more than one response page at an exact byte size,
and a full response containing 100 items while reporting `total_count=99`.
Discovery engine version 4 therefore adds complementary, disjoint
`path:<segment>` / `-path:<segment>` splits after size exhaustion. It accepts
only a short terminal response with no `next` link and no reported unseen
remainder; full responses are always subdivided. An underreported count on a
short terminal response is retained and recorded as a mismatch metric because
discarding returned public items would itself undercount. Any leaf that cannot
be reduced to this boundary remains a fatal coverage gap.

A bounded, state-free replay of the exact failed cuFFTDx lane then completed
against the live production transport in 635 seconds: 1,702 unique explicitly
public file observations from 105 paced requests, zero quarantined
observations, and zero coverage gaps. GitHub's reported count disagreed with
the returned item count on 45 visited partitions, independently confirming
that `total_count` is diagnostic rather than a safe acceptance boundary.

The third attended attempt, run `20260728T194001Z-0b1c7d84`, was deliberately
stopped after 11 completed discovery tasks when its journal showed retryable
Sourcegraph `shard-match-limit` gaps for nvCOMPDx and DALI. The old coordinator
would otherwise have run every remaining query before rejecting the incomplete
composite. The attempt installed no candidate release, changed no public data,
and was not published.

Live positive controls exposed two Sourcegraph assumptions that fixtures had
not exercised:

- the Stream API's implicit pattern mode returned zero results for a pinned
  DALI repository, while the same query with `patternType:keyword` returned the
  expected file immediately;
- `count:all` produced `shard-match-limit` skips, while the official
  `select:file` projection with a numeric ceiling returned the same 1,303 DALI
  files across 235 repositories as the unprojected content query, without the
  4,259 repeated line matches.

Discovery engine version 5 therefore makes Sourcegraph's public contract
explicit: V3 keyword mode, public `github.com` scope, `select:file`,
`count:50000`, `timeout:1m`, and no forks or archives. Reaching the numeric
ceiling, any unexpected skip, either missing terminal marker, or a reported
duration at the server timeout boundary makes that Sourcegraph lane incomplete
and quarantines its observations.

The free public Sourcegraph service cannot truthfully certify completeness:
live single-signal DALI probes reached the server boundary, returned only two
files, and still claimed terminal completion without a skip. Sourcegraph is
therefore an advisory recall source for full/onboard runs, never a zero-result
or retirement authority. Complete Sourcegraph lanes may add candidates;
incomplete lanes remain visible in quality certificates but contribute no
observations. GitHub's independently packed and recursively partitioned lanes
are the required GitHub-native coverage and candidate-retirement authority.
A weekly run whose GitHub reconciliation lane is not due still requires its
Sourcegraph recall lanes to be complete and fails immediately otherwise.
A final bounded replay through the exact production adapter confirmed the
fail-closed behavior: the packed DALI import lane reported terminal completion
after 60,506 ms with only three files, and all three observations were
quarantined under `server_timeout_boundary`.

The fourth attended attempt, run `20260728T204608Z-f104c9aa`, stopped
fail-closed on DALI's broad GitHub lane after 13 completed discovery tasks. Its
import lane had completed authoritatively with 3,785 public file observations,
131 disjoint partitions, and no gap. The broad package lane then reached an
exact 1,844-byte tie dominated by 100 files from one repository; the older
fallback accumulated long filename exclusions until GitHub rejected the query
with HTTP 400. No candidate release was installed or published.

Discovery engine version 6 replaces that pathological fallback with a
repository-membership peel. When an exact-size response contains repeated
files from one explicitly public repository, one concrete match is retained as
the repository's discovery witness and the disjoint `-repo:owner/name`
remainder is searched recursively. The downstream clone still scans the
repository in full, so no classification evidence is lost; discovery avoids
enumerating redundant matching files. Unique-repository ties retain the prior
complementary path fallback and remain fail-closed if they cannot be divided.
A state-free replay of the exact DALI broad lane then completed against the
production transport: 5,099 public match witnesses across 1,940 repositories,
261 disjoint partitions, zero gaps, zero quarantined observations, zero
retries, and no rate-limit or budget rejection.

The fifth attended attempt, run `20260728T221743Z-b4337e59`, advanced through
59 discovery tasks and then stopped fail-closed on NVPL's exact `"nvpl"`
GitHub anchor. The saved certificate contained 4,739 quarantined observations,
175 requests, and an `unsplittable_page` at an exact 417-byte path shared by
101 distinct public repositories. No candidate release was installed or
published.

That leaf was below GitHub Search's documented 1,000-result window and the
official REST API supports paginated traversal. A live page probe returned 100
items on page 1, the 101st item on page 2, and an explicit empty page 3.
Discovery engine version 7 therefore adds a bounded exact-size pagination
fallback before path/repository splitting. It does not trust `total_count` or
the advertised `Link` boundary: acceptance requires an explicit empty page,
typed complete responses, unique repository/path/blob identities, and at least
as many unique items as the largest count reported by any visited page. A full
tenth page, duplicate/hidden remainder, malformed response, or incomplete page
falls back to disjoint partitioning or remains a fatal gap. The exact failed
leaf replay then completed with 101 public observations, three requests, zero
gaps, and zero quarantine.

A subsequent state-free replay of the complete 39,120-match NVPL anchor passed
the old 417-byte failure and then exposed a larger exact-size tie at 916 bytes:
about 1,400 matches remained after repository peeling, beyond one 1,000-result
window. The replay failed closed after 501 successful paced requests, with
14,126 observations quarantined, no transport/rate-limit/retry failure, and no
data or state writes.

The 916-byte tie came from a bare `"nvpl"` discovery lane that was inconsistent
with the certified detector. The scanner never classifies a bare NVPL token:
it requires a component-qualified header/package/reference or an explicit
build-selection signal. The bare value had remained only as a legacy
`pip_pattern`, even though the manifest scanner's declared-package expression
already rejected it. The query plan now removes that non-qualifying anchor and
adds the singular `header_prefix` field it had omitted, so NVPL confirmed
discovery uses the reviewed `nvpl_` header shape while its component packages
and build-selection anchors remain separate. This is a recall correction as
well as a performance correction: direct header integrations no longer depend
on coincidental overlap with a build/package lane.

A state-free replay of the replacement `"nvpl_"` header lane then exposed
GitHub page-order churn within a 130-result exact-size leaf: one walk reached
an explicit empty page but contained duplicate identities. Repeating that
exact public query produced two identical, independently complete walks of
100 + 30 + empty, with 130 unique identities. Discovery engine version 8
therefore retries an entire below-cap exact-size walk at most three times.
It never unions partial attempts, and a retry is accepted only if that one
walk independently has typed complete pages, an explicit empty terminator,
unique identities, and at least the largest count reported within the walk.
Persistent instability still falls back to disjoint splitting or fails closed.
The complete live replacement-lane replay then passed: 2,761 public
observations across 211 partitions, 236 successful requests, nine proven
paginated leaves, zero gaps, zero quarantine, and no transport, retry,
rate-limit, or budget failure.

- These corrections change discovery completeness mechanics only. The approved
  classification bands, exclusions, and evidence meanings are unchanged. The
  discovery and NVPL detector fingerprints change because the candidate
  generator now exactly matches those approved signals. The production
  fingerprint manifest was
  repinned and the complete CI-equivalent local suite passed before retry.

Legend: `C` = confirmed evaluated, `D` = declared/bundled evaluated, `T` =
targeted evaluated, `NE` = explicitly not evaluated. Validation codes are
`C-E` exact include, `C-P` prefix include, `P-I` executable import, `P-A`
product-specific import/API, `D-E` exact declaration, and `T-E` exact CMake
target.

## Readiness matrix

The commit, path, official source URL, complete target/package allowlist, and
hard-negative contract for every `D`/`T` cell are frozen in the machine
contract. Repository names below identify the independent public replay.

| Library | Bands | Exact qualifying signals | Components/operators | Positive replay and negatives | Remaining blocker |
|---|---|---|---|---|---|
| cuBLAS | C/NE/T | C: `cublas.h`, `cublas_v2.h`; T: exact `CUDA::cublas[_static]` | ops NE | C: hgpvision/darknet; T: davisking/dlib; C-E/T-E | D: no certified source-copy rule; component-wheel declarations may be framework-transitive |
| cuBLASLt | C/NE/T | C: `cublasLt.h`; T: exact `CUDA::cublasLt` or `CUDA::cublasLt_static` | → cuBLAS; ops NE | C: starpu-runtime/starpu; T: opencv/opencv; wrapper + CMake negatives | D: cuBLAS wheel cannot distinguish Lt |
| cuBLASXt | C/NE/NE | `cublasXt.h` | → cuBLAS; ops NE | Rust-GPU/rust-cuda; C-E | no distinct bundle/config contract |
| cuBLASMp | C/NE/T | C: `cublasmp.h`, `cublasMp.h`; T: exact `cublasmp` or `-lcublasmp` linker operand | → cuBLAS; ops NE | C/T: Distributed-GEMM-Thesis; copied TransformerEngine/sample and CMake negatives | D: runtime-wheel declarations lack an intentional external authored positive |
| cuFFT | C/NE/T | C: `cufft.h`; T: exact approved `cufft/cufftw` dynamic/static target | ops NE | C: nerscadmin/IPM; T: openmm/openmm; C-E/T-E | D: low-level wheel declarations may be framework-transitive |
| cuFFTXt | C/NE/NE | `cufftXt.h` | → cuFFT; ops NE | microsoft/onnxruntime; copied-header negative | no distinct bundle/config contract |
| cuFFTMp | C/NE/T | C: `cufftMp.h`; T: exact `cufftMp` link/find operand | → cuFFT; ops NE | C: IPPL-framework/ippl; T: gromacs/gromacs; copied-repo/CMake negatives | D: public package hits are generated/transitive lockfiles |
| cuRAND | C/NE/T | C: `curand.h`, `curand_kernel.h`; T: exact dynamic/static target | ops NE | C: hgpvision/darknet; T: davisking/dlib; C-E/T-E | D: low-level wheel declarations may be framework-transitive |
| cuSOLVER | C/NE/T | C: `cusolverDn/Sp/Rf/Mg.h`; T: exact dynamic/static target | ops NE | C: arrayfire/arrayfire; T: ceres-solver; C-E/T-E | D: low-level wheel declarations may be framework-transitive |
| cuSOLVERMp | C/NE/T | C: `cusolverMp.h`; T: exact `cusolverMp` link/find operand | → cuSOLVER; ops NE | C: cp2k/cp2k; T: uestc-ndsl-hpc/distQR; build/docs negatives | D: runtime-wheel declarations lack an intentional external authored positive |
| cuSPARSE | C/NE/T | C: `cusparse.h`; T: exact dynamic/static target | ops NE | C: starpu-runtime/starpu; T: osqp/osqp; C-E/T-E | D: low-level wheel declarations may be framework-transitive |
| cuSPARSELt | C/NE/NE | C: `cusparseLt.h` | → cuSPARSE; ops NE | C: cupy/cupy; C-E | D: package declarations are commonly framework lock/freeze transitives; T: broad `cusparseLt` build-name discovery is operationally unbounded and targeted intent is not dependable enough for this reconciliation |
| cuTENSOR | C/NE/T | C: `cutensor.h`, `cutensorMg.h`; T: exact `cutensor` link/find operand | ops NE | C: spcl/dace; T: correaa/boost-multi; wrapper/CMake negatives; exact `CUtensorMap` discovery blob excluded while any changed/new observation remains eligible | D: distribution declarations lack an intentional external authored positive |
| cuDSS | C/NE/T | C: `cudss.h`; T: exact `cudss` or `cudss_static` linker operand | ops NE | C: cvxgrp/scs; T: owensgroup/RXMesh; C-E/T-E; 4shen/webshell malware corpus excluded for cuDSS only | D: binary-wheel declarations still have transitive-intent ambiguity |
| AmgX | C/NE/NE | `amgx_c.h` | ops NE | mfem/mfem; build-only negative | no official standalone lower-band signal |
| cuEquivariance | C/D/NE | C: import `cuequivariance`, `_torch`, `_jax`; D: exact corresponding hyphen/underscore-normalized distributions | ops NE | C: RosettaCommons/foundry; D: aws-samples/drug-discovery-workflows; P-I/D-E | no exact non-declaration config signal |
| NVIDIA Warp | C/D/NE | C: import `warp` + reviewed `wp.*` API; D: `warp-lang` | ops NE | C: Autodesk/XLB; D: google-deepmind/mujoco; bare-import + D-E negatives | no exact non-declaration config signal |
| PhysicsNeMo | C/D/NE | C: import `physicsnemo`; D: `nvidia-physicsnemo` | ops NE | C: End-to-End-AI-for-Science; D: Project-MONAI/physiotwin4d; prefix negative | no exact non-declaration config signal |
| CUDA-Q QEC | C/D/NE | C: import `cudaq_qec`; D: `cudaq-qec` | ops NE | C: Dies-Irae/BP-SF; D: NERSC tutorial; P-I/D-E | no exact non-declaration config signal |
| CUDA-Q Solvers | C/D/NE | C: import `cudaq_solvers`; D: `cudaq-solvers` | ops NE | C/D: NERSC tutorial; P-I/D-E | no exact non-declaration config signal |
| cuDNN | C/NE/NE | `cudnn.h`, `cudnn_frontend.h` | ops NE | clab/dynet; copied-header/install-doc negatives | low-level wheel declarations may be framework-transitive; no standard exact CMake target |
| TensorRT | C/D/T | C: import `tensorrt` or include `NvInfer.h`/`NvInferRuntime.h`; D: `tensorrt`; T: exact `nvinfer`/`nvinfer_plugin` link/find | ops NE | C: onnx/onnx-tensorrt; D: MIT-SPARK/DAAAM; T: jolibrain/deepdetect; D/T negatives | — |
| TensorRT-LLM | C/D/NE | C: import `tensorrt_llm`; D: `tensorrt-llm` | → TensorRT; ops NE | C: nesaorg/nesa; D: k2-fsa/sherpa; P-I/D-E | no exact non-declaration config signal |
| CUTLASS | C/NE/NE | header under `cutlass/` | ops NE | SHI-Labs/NATTEN; copied-CUTLASS negative | declaration/source-copy evidence not intent-isolated in this pass |
| FlashInfer | C/D/NE | C: import `flashinfer`; D: `flashinfer-python` | ops NE | C: deepseek-ai/FlashMLA; D: mlc-ai/mlc-llm; P-I/D-E | no exact non-declaration config signal |
| Thrust | C/NE/NE | header under `thrust/` | ops NE | antonmks/Alenka; copied/attribution negatives | CCCL bundle/declaration cannot prove Thrust selection |
| CUB | C/NE/NE | header under `cub/` | ops NE | k2-fsa/k2; copied-CCCL negative | CCCL bundle/declaration cannot prove CUB selection |
| cuDF | C/D/NE | C: import `cudf`; D: `cudf-cu12`, `cudf-cu13` | ops NE | C: h2oai/db-benchmark; D: lifuguan/IGGT_official; P-I/D-E | no exact non-declaration config signal |
| cuVS | C/D/NE | C: import `cuvs`; D: `cuvs-cu12`, `cuvs-cu13` | ops NE | C: volcengine/OpenViking; D: lifuguan/IGGT_official; P-I/D-E | no exact non-declaration config signal |
| cuML | C/D/NE | C: import `cuml`; D: `cuml-cu12`, `cuml-cu13` | ops NE | C: HSP-GKN; D: lifuguan/IGGT_official; P-I/D-E | no exact non-declaration config signal |
| cuOpt | C/D/NE | C: import `cuopt`; D: `cuopt-cu12`, `cuopt-cu13` | ops NE | C: coin-or/pulp; D: herbertskyper/NeuTracer; local-shadow + D-E negatives | no exact non-declaration config signal |
| cuGraph | C/D/NE | C: import `cugraph`; D: `cugraph-cu12`, `cugraph-cu13` | ops NE | C: PyTorch Geometric; D: graphistry/pygraphistry; P-I/D-E | no exact non-declaration config signal |
| NeMo Curator | C/D/NE | C: import `nemo_curator`; D: `nemo-curator` | ops NE | C: IndicPHI; D: DDNStorage/fsi-pipeline; old guessed package + skill negatives | no exact non-declaration config signal |
| Morpheus | C/NE/NE | import `morpheus` + reviewed `config/messages/pipeline/stages` API | ops NE | morpheus-siem-lab; name/API collision negatives | public distribution name collides; no exact config signal |
| nvCOMP | C/D/T | C: `nvcomp.h`, header under `nvcomp/`, or import `nvidia.nvcomp`; D: `nvidia-nvcomp-cu12/cu13`; T: exact `nvcomp::nvcomp` | ops NE | C: dmlc/xgboost + pytorch/rl; D: scikit-hep/uproot5; T: dmlc/xgboost; dual-surface/D-E/T-E negatives | low-level `nvidia-libnvcomp-*` wheels remain NE |
| GPUDirect Storage | C/NE/T | C: `cufile.h`; T: exact approved `cuFile` dynamic/static/RDMA target | ops NE | C: axboe/fio; T: IST-DASLab/llmq; sample/CMake negatives | component-wheel declarations may be framework-transitive |
| nvImageCodec | C/D/NE | C: import `nvidia.nvimgcodec`; D: `nvidia-nvimgcodec-cu12/cu13` | ops NE | C: OpenHUTB/hutb; D: basetenlabs/truss-examples; P-I/D-E | no exact non-declaration config signal |
| CV-CUDA | C/D/NE | C: import `cvcuda`; D: `cvcuda-cu12`, `cvcuda-cu13` | ops NE | C: Tencent Hunyuan3D; D: Tengpaz/WorldRenderer; old guessed package/product-source negatives | no exact non-declaration config signal |
| cuCIM | C/D/NE | C: import `cucim`; D: `cucim-cu12`, `cucim-cu13` | ops NE | C: slideflow; D: bpi-oxford; P-I/D-E | no exact non-declaration config signal |
| NPP | C/NE/T | C: `npp.h`, `nppc.h`, `nppi.h`, `npps.h`; T: exact `CUDA::npp{c,ial,icc,icom,idei,if,ig,im,ist,isu,itc,s}[_static]` | ops NE | C: Open3D; T: PointCloudLibrary/pcl; copied-header/T-E negatives | component-wheel declarations may be framework-transitive |
| Video Codec SDK | C/NE/NE | `nvEncodeAPI.h`, `nvcuvid.h`, `cuviddec.h` | ops NE | opencv_contrib; redistributed-header negative | no official standalone package/config contract |
| Optical Flow SDK | C/NE/NE | `nvofapi.h` or current CUDA/D3D/Vulkan interface headers | ops NE | opencv_contrib; patch/copied-header negatives | no official standalone package/config contract |
| NCCL | C/NE/NE | `nccl.h` | ops NE | ParRes/Kernels; source-fork/fake-SDK negatives | wheel declarations may be framework-transitive; no certified exact config target |
| NIXL | C/D/NE | C: import `nixl` or include `nixl.h`; D: `nixl` | ops NE | C: vllm; D: ray-project/ray; self-header/D-E negatives | no exact non-declaration config signal |

## Corrections and performance safeguards added in this gate

- Corrected current distribution anchors from the non-existent
  `nvidia-nemo-curator` and `nvidia-cvcuda-*` guesses to `nemo-curator` and
  `cvcuda-cu12/cu13`; the old names are tested hard negatives.
- Added structural parsing for common authored Python dependency surfaces,
  including safe static `setup.py` literals/variables and pip-compile hash
  continuations. Invalid two-column package listings no longer qualify.
- Added exact, case-sensitive CMake target classification with bracket-comment,
  message, near-name, unrelated-variable, vendor, generated, and copied-project
  rejection.
- Rejected the unsupported `CUDAToolkit::` pseudo-namespace after checking the
  current upstream `FindCUDAToolkit` contract; official imported targets use
  `CUDA::`.
- Added nvCOMP's current official Python API and distribution surface, plus its
  official CMake target; both C++ and Python confirmed surfaces have pinned
  external positives.
- Added cuDSS's canonical CMake linker operands after official compilation
  guidance and an independent public link configuration agreed.
- Rechecked cuTENSOR, cuBLASMp, cuFFTMp, and cuSOLVERMp against
  official sample/link layouts and independent authored public CMake examples.
  Their exact canonical linker-library names qualify as targeted evidence.
  Their distribution declarations remain `NE` where the only public hits are
  generated/transitive lockfiles or package-index mirrors.
- Reduced cuSPARSELt to its certified confirmed header lane. Its broad
  `cusparseLt` build-name query is removed and targeted remains explicitly
  `not_evaluated`; this avoids treating a high-collision linker token as a
  dependable all-repository discovery contract.
- Rechecked NCCL, NIXL, and CV-CUDA build hits. Their apparent targets remain
  project-defined, framework-dominant, copied, or without a distinct certified
  external link contract, so their ambiguous targeted bands remain `NE`.
- Removed `cuda.compute` and `cuda.parallel` from active REQ-14 detection by
  owner decision while retaining honest pending cards in the versioned catalog.
- Kept discovery efficient by searching short reviewed target-family roots,
  while classification still checks the complete exact allowlist.
- Prevented the lower-band legacy probe from bypassing direct triage: a local
  module/header rejected as a shadow can never be promoted back to confirmed.
- Bumped the shared scanner semantic epoch and regenerated per-library
  fingerprints; the first approved reconciliation will re-evaluate only the
  work invalidated by these frozen semantics.

## Approval gate

Do not run `reconcile --confirm-full`, `refresh.sh`, or any collection entry
point until the owner approves this contract and fingerprint lock. Launchd
remains unarmed. After approval, follow the attended reconciliation runbook,
validate the proposed release, and compare overlapping V2/V1 classifications,
membership, first-use evidence, operators/components, AI markers, citations,
and exports before accepting or publishing.
