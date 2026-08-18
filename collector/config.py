"""Static configuration for the CUDA-X integration tracker.

Library registry + detection signatures + exclusion rules + AI-agent
signatures. All values here are intentionally easy to edit; adding a
library is a one-line registry entry.
"""

from .catalog import REQ14_DIRECT_LIBRARIES

# ---------------------------------------------------------------------------
# Library registry (v1 = Tier-1 MathDx device extensions).
# `released_on` drives each library's time-series x-axis origin. Dates are
# original first Early Access (sourced from approved release records and pages
# in the approved product catalog), NOT the samples-repo debut, which lags release.
# `token` = the substring used for code-search discovery + git pickaxe.
# `header` = the canonical include header confirmed at clone time.
#
# REQ-07 research citations (collector/citation_pipeline.py, OpenAlex search):
#   `citation_query`      = the OpenAlex full-text term. A distinctive coined
#                           token for tier-A names (cuFFTDx); a QUOTED phrase
#                           ('"NVIDIA DALI"') for tier-C collision names.
#   `citation_cooccur`    = optional list of extra full-text terms AND-ed in to
#                           disambiguate (e.g. ["CUDA","GPU"] for CUTLASS/CUB).
#   `citation_tier`       = A (distinctive) | B (NVIDIA-coined, high-mention) |
#                           C (collision: phrase + co-occurrence required).
#   `citation_confidence` = high | medium (medium = residual false-positives).
# ONBOARDING A LIBRARY'S CITATIONS: add `citation_query` (precision-checked per
# the spike — never a bare token without verifying a 6-title sample) and the
# tier/confidence. The stateful citation pipeline picks it up automatically.
# ---------------------------------------------------------------------------
LIBRARIES = [
    {
        "id": "cufftdx", "name": "cuFFTDx", "tier": 1,
        "token": "cufftdx", "header": "cufftdx.hpp",
        "citation_query": "cuFFTDx", "citation_tier": "A", "citation_confidence": "high",
        "released_on": "2021-03",  # first/oldest Dx lib; earliest observed integration 2021-03; confirm exact EA w/ MathDx team
        "released_confidence": "low",
        "description": "Device-side Fast Fourier Transform (in-kernel FFT).",
    },
    {
        "id": "cublasdx", "name": "cuBLASDx", "tier": 1,
        "token": "cublasdx", "header": "cublasdx.hpp",
        "citation_query": "cuBLASDx", "citation_tier": "A", "citation_confidence": "high",
        "released_on": "2022-11",  # MathDx 22.11
        "released_confidence": "medium",
        "description": "Device-side BLAS / in-kernel GEMM.",
    },
    {
        "id": "cusolverdx", "name": "cuSolverDx", "tier": 1,
        "token": "cusolverdx", "header": "cusolverdx.hpp",
        "citation_query": "cuSolverDx", "citation_tier": "A", "citation_confidence": "high",
        "released_on": "2025-01",  # MathDx 25.01, "0.1.0 first EA", posted 2025-01-30
        "released_confidence": "high",
        "description": "Device-side dense factorizations, solves, eigen/SVD.",
    },
    {
        "id": "curanddx", "name": "cuRANDDx", "tier": 1,
        "token": "curanddx", "header": "curanddx.hpp",
        "citation_query": "cuRANDDx", "citation_tier": "A", "citation_confidence": "high",
        "released_on": "2025-01",  # MathDx 25.01, posted 2025-01-30
        "released_confidence": "high",
        "description": "Device-side random number generation.",
    },
    {
        "id": "nvcompdx", "name": "nvCOMPDx", "tier": 1,
        "token": "nvcompdx", "header": "nvcompdx.hpp",
        "citation_query": "nvCOMPDx", "citation_tier": "A", "citation_confidence": "high",
        "released_on": "2025-06",  # MathDx 25.06.0, posted 2025-07-07
        "released_confidence": "high",
        "description": "Device-side (de)compression.",
    },
    # Backlog: cuSPARSEDx — named in the MathDx package soul but not yet shipped.
    # --- Python-first libraries (pip-distributed: detected via imports + deps,
    # not a C++ #include). language="python" routes them through the Python
    # detector in discover.py / scan.py; C++ libs above are untouched. ---
    {
        "id": "dali", "name": "DALI", "tier": "python-pilot",
        "language": "python",
        "token": "nvidia.dali",            # targeted/any-ref fallback term
        # tier C: bare 'dali' = 152k collisions (the painter, lighting protocol);
        # the quoted phrase disambiguates (spike-verified, tail-clean).
        "citation_query": '"NVIDIA DALI"', "citation_tier": "C", "citation_confidence": "high",
        "import_namespace": "nvidia.dali",  # strict anchor (avoids bare-'dali' false positives)
        "strict_import": True,
        "allow_qualified_call": False,
        "pip_pattern": "nvidia-dali",       # matches nvidia-dali-cuda1XX / -tf-plugin / -nightly / -weekly
        "operator_namespaces": ["fn", "ops"],  # nvidia.dali.fn.* / nvidia.dali.ops.* (REQ-04)
        "index_hints": ["pypi.nvidia.com", "developer.download.nvidia.com/compute/redist"],
        "header": "",                       # no canonical C++ header on the Python path
        "released_on": "2018-06",           # open-sourced 2018-06-19 (announced at CVPR'18)
        "released_confidence": "medium",
        "description": "GPU-accelerated data loading and preprocessing for deep learning.",
    },
    # --- cuQuantum (umbrella SDK, dual-surface): Python `import cuquantum` PLUS
    # five distinctive C++ component headers. Registered Python-first and EXTENDED
    # with `cpp_headers` (own-source #include of any => confirmed) and `components`
    # (signal-substring -> label map, recorded per-repo in the operators field as
    # the multi-component breakdown). Citation = the umbrella token "cuQuantum"
    # (261, clean); per-component citation is NOT viable (cuStabilizer collides
    # with "Cu stabilizer" superconductor papers). See [[CUDA-X Library Onboarding
    # - cuQuantum + NVPL Detection Design]]. Component tokens are all distinctive;
    # NO substring collision with any tracked lib. ---
    {
        "id": "cuquantum", "name": "cuQuantum", "tier": "quantum",
        "language": "python",
        "token": "cuquantum",               # targeted/any-ref fallback term
        "import_namespace": "cuquantum",     # strict anchor (SDK presence; submodule = component)
        "strict_import": True,
        "allow_qualified_call": False,
        "pip_pattern": ["cuquantum-python", "cuquantum-cu", "custatevec-cu", "cutensornet-cu",
                        "cudensitymat-cu", "cupauliprop-cu", "custabilizer-cu"],
        "cpp_headers": ["custatevec.h", "cutensornet.h", "cudensitymat.h",
                        "cupauliprop.h", "custabilizer.h"],
        # signal substring (in own-source text) -> component label, for the breakdown.
        # Covers C++ headers, low-level `cuquantum.bindings.<c>`, legacy `cuquantum.<c>`,
        # high-level `cuquantum.tensornet/.densitymat/.stabilizer/.pauliprop`, and wheels.
        "components": {
            "custatevec": "cuStateVec", "cutensornet": "cuTensorNet",
            "cudensitymat": "cuDensityMat", "cupauliprop": "cuPauliProp",
            "custabilizer": "cuStabilizer",
            "cuquantum.tensornet": "cuTensorNet", "cuquantum.densitymat": "cuDensityMat",
            "cuquantum.stabilizer": "cuStabilizer", "cuquantum.pauliprop": "cuPauliProp",
        },
        "citation_query": "cuQuantum", "citation_tier": "A", "citation_confidence": "high",
        "citation_paper_doi": "10.1109/QCE57702.2023.00119",  # cuQuantum SDK paper (IEEE QCE 2023)
        "index_hints": ["pypi.nvidia.com", "developer.download.nvidia.com/compute/cuquantum"],
        "header": "",
        "released_on": "2021-11",            # cuStateVec public beta / GTC Nov'21 announce (earliest component availability; umbrella spans all 5) — confirm w/ team
        "released_confidence": "low",
        "description": "GPU-accelerated quantum circuit simulation SDK: state vector, tensor network, density matrix, Pauli propagation, stabilizer.",
    },
    # --- NVPL (NVIDIA Performance Libraries): CPU math-library family for Arm/Grace
    # (NOT CUDA). A third detection mode (`family="nvpl"`). confirmed = own-source
    # #include of any nvpl_*.h (the direct-use signal). Build-level signals
    # (find_package(nvpl, nvpl::, -lnvpl_*, BLA_VENDOR=NVPL) => "Build-integrated"
    # (stored in the bundled band and included in NVPL's backend-aware integration
    # headline). pip nvpl-* / conda blas=*=nvpl => Declared.
    # Precision: never confirm on a bare compat token (cblas_/fftw3.h/LAPACKE_);
    # a conditional include inside an optional-backend file (ggml-blas) != use.
    # Citation = "NVIDIA Performance Libraries" phrase (6); CPU lib => no CUDA/GPU
    # co-occurrence; no canonical paper. ---
    {
        "id": "nvpl", "name": "NVPL", "tier": "cpu-arm",
        "language": "cpp",                   # per-repo language is C/C++; family drives dispatch
        "family": "nvpl",                    # routes to the NVPL/CPU-family detector
        "component_rollup_mode": "additive", # parent counts component integrations; rows stay distinct
        # NVPL is a CPU drop-in backend used via FFTW/CBLAS/LAPACKE compat APIs, so
        # build-level selection ("Backend") is the dominant adoption channel and the
        # headline sums confirmed (#include) + bundled (Backend). Per-lib flag: other
        # libs stay confirmed-only (REQ-05). See design note §A/§E/§F.
        "adoption_counts_build": True,
        "bundled_label": "Backend",          # UI label for the middle band (vs Declared/Bundled)
        "token": "nvpl",
        "header": "",
        "header_prefix": "nvpl_",            # own-source #include <nvpl_*.h> / <nvpl_compat/*.h> => confirmed
        # build-integration tokens (own build files) => "Build-integrated" (bundled band)
        "build_signals": ["find_package(nvpl", "nvpl::", "-lnvpl_",
                          "bla_vendor=nvpl", "ggml_blas_vendor=nvpl", "blas=*=nvpl"],
        # files that conditionally include an NVPL header for an OPTIONAL, usually
        # unselected build backend (framework dispatch shims) — a CONDITIONAL nvpl
        # include here is not the repo's own use: ggml's BLAS backend, LAMMPS/SPARTA
        # KOKKOS FFT-backend dispatch (`fftdata*.h` includes nvpl_fftw.h under an ifdef).
        "optional_backend_files": ["ggml-blas", "fftdata", "fft3d"],
        "pip_pattern": ["nvpl-blas", "nvpl-fft", "nvpl-lapack", "nvpl-scalapack",
                        "nvpl-sparse", "nvpl-rand", "nvpl-tensor"],
        "components": {
            "nvpl_blas": "BLAS", "nvpl_fft": "FFT", "nvpl_fftw": "FFT", "nvpl_lapack": "LAPACK",
            "nvpl_scalapack": "ScaLAPACK", "nvpl_blacs": "ScaLAPACK",
            "nvpl_sparse": "Sparse", "nvpl_rand": "RAND",
            "nvpl_tensor": "Tensor", "nvpltensor": "Tensor",
        },
        # Parent -> children split (data-model + UI; NO new detection heaviness — these are a
        # re-projection of the component labels the detector ALREADY emits). Each component
        # becomes a first-class sub-library (own page+graph); the parent NVPL card+page
        # additively aggregates them. A repo using multiple components contributes once per
        # component to the parent integration metric. `label` = the value in `components` above;
        # `header` = the confirm
        # token scan.py pickaxes for that component's per-component first-#include date (a wrong
        # date corrupts the child graph's x-axis anchor). `released_on` per NVPL redist manifests:
        # six components shipped in 23.11 (2023-11-14); nvpl_tensor shipped later in 24.03
        # (2024-03-18). Children inherit the parent's vendor exclusions (same scanned repos).
        "component_children": [
            {"id": "nvpl-blas", "name": "NVPL BLAS", "label": "BLAS", "header": "nvpl_blas",
             "released_on": "2023-11", "released_confidence": "high"},
            {"id": "nvpl-fft", "name": "NVPL FFT", "label": "FFT", "header": "nvpl_fft",
             "released_on": "2023-11", "released_confidence": "high"},
            {"id": "nvpl-lapack", "name": "NVPL LAPACK", "label": "LAPACK", "header": "nvpl_lapack",
             "released_on": "2023-11", "released_confidence": "high"},
            {"id": "nvpl-scalapack", "name": "NVPL ScaLAPACK", "label": "ScaLAPACK", "header": "nvpl_scalapack",
             "released_on": "2023-11", "released_confidence": "high"},
            {"id": "nvpl-sparse", "name": "NVPL Sparse", "label": "Sparse", "header": "nvpl_sparse",
             "released_on": "2023-11", "released_confidence": "high"},
            {"id": "nvpl-rand", "name": "NVPL RAND", "label": "RAND", "header": "nvpl_rand",
             "released_on": "2023-11", "released_confidence": "high"},
            {"id": "nvpl-tensor", "name": "NVPL Tensor", "label": "Tensor", "header": "nvpl_tensor",
             "released_on": "2024-03", "released_confidence": "high"},
        ],
        "citation_query": '"NVIDIA Performance Libraries"', "citation_tier": "C", "citation_confidence": "medium",
        "index_hints": ["docs.nvidia.com/nvpl", "developer.nvidia.com/nvpl"],
        "released_on": "2023-11",            # NVPL GA ~ late 2023 w/ Grace — confirm w/ team
        "released_confidence": "low",
        "description": "CPU performance-library family for Arm/Grace: BLAS, FFT, LAPACK, ScaLAPACK, Sparse, RAND, Tensor.",
    },
    # --- NVSHMEM (GPU-side OpenSHMEM communication library; C/C++). Onboarded as a
    # STANDARD C++ lib (token + header), NOT a Backend-band lib like NVPL: NVSHMEM's
    # entire API is deliberately `nv`-prefixed (nvshmem_/nvshmemx_/NVSHMEM_) so there
    # is NO compat-API token-free path — every direct user carries the `nvshmem` token
    # in source (#include <nvshmem.h>/<nvshmemx.h>/device subheaders). The token-substring
    # confirm regex catches all NVSHMEM headers and has NO collision with any tracked
    # token. Real adoption is partly M4 framework-transitive (DeepEP/Megatron/TransformerEngine/
    # vLLM/SGLang via backend config strings) — that is the unbuilt, version-sensitive M4
    # detector and is OUT of scope for v1 (documented floor); confirmed=#include is the
    # honest, trust-preserving signal. Brand-new Python binding (nvshmem4py → import
    # nvshmem.core, v0.3.1 2026) has ~0 public adoption yet → counts as targeted for now;
    # promote to dual-surface (cpp_headers) when it grows. Citation = distinctive token
    # "NVSHMEM" (Tier A, clean: 136 community papers). See design note §A. ---
    {
        "id": "nvshmem", "name": "NVSHMEM", "tier": "comm",
        "token": "nvshmem", "header": "nvshmem.h",
        # Pre-clone vendor filter (precision + refresh opt): drop forks/hand-copies of
        # the frameworks that bundle NVSHMEM in their own tree (would false-confirm a
        # root-level vendored nvshmem.h that VENDOR_PATH_RE misses). GitHub code-search
        # excludes forks so parent-match finds few today, but kept for future refreshes;
        # name-substr uses only DISTINCTIVE multi-char tokens (no bare "flux"/"quda" — too
        # broad — those rely on parent-match). Generic filter in run.py reads these.
        "vendor_parents": {"NVIDIA/nvshmem", "deepseek-ai/DeepEP", "NVIDIA/Megatron-LM",
                           "NVIDIA/TransformerEngine", "bytedance/flux", "lattice/quda",
                           "perplexityai/pplx-kernels", "ByteDance-Seed/Triton-distributed"},
        "vendor_name_substr": ("deepep", "megatron", "transformer_engine", "transformerengine",
                               "pplx-kernels", "triton-distributed"),
        "citation_query": "NVSHMEM", "citation_tier": "A", "citation_confidence": "high",
        "released_on": "2019-03",  # NVSHMEM EA ~ GTC March 2019 (corrected from 2019-09 after a genuine 2019-06 adopter, berkeley-container-library/bcl, was wrongly clamped) — confirm exact EA w/ team
        "released_confidence": "low",
        "description": "GPU-side OpenSHMEM: one-sided communication and a symmetric memory model for multi-GPU / multi-node CUDA.",
    },
    # --- nvmath-python (unified Python interface to NVIDIA math libraries). Python-first
    # (import root `nvmath`; dist name `nvmath-python`, hyphen — the classic M5 package!=import).
    # A `components` map (cuQuantum-style, Python-only — NO cpp_headers) records which surface
    # a repo uses. M5 ATTRIBUTION (LOCKED, owner review 2026-06-26 = KEEP BOTH): nvmath.device.{fft,
    # matmul,random} REMAIN attributed to cuFFTDx/cuBLASDx/cuRANDDx via config.PY_SIGNALS
    # (UNCHANGED), AND any `import nvmath` ALSO counts the repo as an nvmath-python adopter —
    # documented double-count, consistent with the no-cross-card-dedup policy (the device call
    # genuinely IS cuBLASDx; moving it would zero the Dx Python floor). Purely additive →
    # ZERO change to existing data (PY_SIGNALS untouched). Citation = distinctive hyphenated
    # "nvmath-python" (Tier A; bare "nvmath" has OCR-noise FPs). No canonical paper DOI.
    # See design note §B. ---
    {
        "id": "nvmath", "name": "nvmath-python", "tier": "python-math",
        "language": "python",
        "token": "nvmath",                   # targeted/any-ref fallback term
        "import_namespace": "nvmath",        # strict anchor (distinctive in .py)
        # opt-in precision guard: confirm only on an import-shaped match (import nvmath /
        # from nvmath / nvmath.<attr>), NOT a bare "nvmath" substring — kills the nvpro/nvtt
        # C++ "nvmath" collision (libnvmath.so / nvmath.lib / -lenvmath / "nvmath" in a libs
        # list). Opt-in so DALI/cuQuantum keep their (collision-free) substring match unchanged.
        "strict_import": True,
        "pip_pattern": ["nvmath-python"],    # single dist (no -cu12/-cu13 standalone; CUDA via extras)
        # surface breakdown (signal substring -> label), stored in the operators field.
        # dotted keys so they don't cross-match (nvmath.fft is NOT a substring of
        # nvmath.device.fft). device.* labels name the Dx lib to make the kept M5
        # double-attribution legible in the data.
        "components": {
            "nvmath.device.fft": "FFT device (cuFFTDx)",
            "nvmath.device.matmul": "Matmul device (cuBLASDx)",
            "nvmath.device.random": "RNG device (cuRANDDx)",
            "nvmath.device.solver": "Solver device (cuSOLVERDx)",
            "nvmath.fft": "FFT host (cuFFT)",
            "nvmath.linalg": "Linear algebra (cuBLAS)",
            "nvmath.sparse": "Sparse solver (cuDSS)",
            "nvmath.tensor": "Tensor (cuTENSOR)",
            "nvmath.distributed": "Distributed (cuFFTMp/cuBLASMp)",
            "nvmath.bindings": "Low-level bindings",
        },
        "citation_query": "nvmath-python", "citation_tier": "A", "citation_confidence": "high",
        "index_hints": ["pypi.nvidia.com", "docs.nvidia.com/cuda/nvmath-python"],
        "header": "",
        "released_on": "2024-08",            # nvmath-python first beta ~ 2024-08 — confirm w/ team
        "released_confidence": "low",
        "description": "Unified Python interface to NVIDIA math libraries: device (cuFFTDx/cuBLASDx/cuRANDDx via numba-cuda) and host (cuBLAS/cuFFT/cuSOLVER/cuSPARSE/cuDSS/cuTENSOR) APIs.",
    },
    # --- cuPQC (GPU post-quantum cryptography SDK). Architecturally a MathDx "Dx"
    # device-extension (operator-composition template style; depends on commonDx), but
    # NOT purely header-only (links static libs cupqc-pk/cupqc-hash) and shipped as a
    # STANDALONE SDK download (not in the CUDA toolkit, not the MathDx bundle, no pip).
    # Irrelevant for an #include-keyed tracker: headers still exist and are included.
    # MULTI-HEADER C++ lib: confirm on any of `cpp_headers` (cupqc.hpp = PK umbrella,
    # cuhash.hpp = Hash) — token "cupqc" alone MISSES a cuhash-only repo. `components`
    # give the ML-KEM / ML-DSA / cuHash breakdown (cuQuantum-style). Distinctive tokens
    # (cupqc.hpp/cuhash.hpp = near-zero collision); the generic pk.hpp/hash.hpp are NOT
    # used (would collide). No substring collision with any tracked token. Niche volume
    # (mostly NVIDIA samples + forks, already excluded) → expect a near-empty graph. ---
    {
        "id": "cupqc", "name": "cuPQC", "tier": "crypto",
        "token": "cupqc", "header": "cupqc.hpp",
        "citation_query": "cuPQC", "citation_tier": "A",
        "citation_confidence": "high",
        # Multi-header confirm (own-source #include of ANY => confirmed). cuhash.hpp is a
        # distinct component header with no "cupqc" substring, so it must be listed.
        "cpp_headers": ["cupqc.hpp", "cuhash.hpp"],
        # signal substring (lowercased, in own-source text) -> component label. Symbol-based
        # (ML_KEM_/ML_DSA_) + header-based (cuhash). A confirmed repo with only the umbrella
        # include and no component symbol falls back to "SDK (unspecified)" (like cuQuantum).
        "components": {
            "ml_kem": "ML-KEM", "ml-kem": "ML-KEM",
            "ml_dsa": "ML-DSA", "ml-dsa": "ML-DSA",
            "cuhash": "cuHash", "poseidon2": "cuHash",
        },
        "index_hints": ["docs.nvidia.com/cuda/cupqc", "developer.nvidia.com/cupqc"],
        "released_on": "2024-12",            # cuPQC 0.2.0 (EA), approved release record + public launch blog
        "released_confidence": "high",
        "description": "GPU post-quantum cryptography device-extension SDK: ML-KEM, ML-DSA (cuPQC-PK) and SHA-2/3, SHAKE, Poseidon2, Merkle (cuPQC-Hash / cuHash).",
    },
    # --- ovrtx (Omniverse RTX SDK). A genuine INTEGRATABLE library: a "lightweight C and
    # Python SDK for Omniverse RTX" (RTX sensor sim + visualization for Physical AI). Dual
    # surface: register Python-first (cuQuantum-style) so DISCOVERY uses QUOTED phrases
    # ("ovrtx" import + "ovrtx.h" header), sidestepping the ~2,800-hit bare-token junk (GitHub
    # tokenizes on '_'). Confirm is strict: `import ovrtx` (strict_import) OR own-source
    # #include of an ovrtx/ header. Do NOT key on the `ovx_` sub-prefix (collides with OpenVX).
    # New/pre-release (v0.1.0 2026-02) → near-empty graph (~2-5 real adopters) — expected, not a
    # bug. Source org NVIDIA-Omniverse already in EXCLUDED_ORGS. AI-skill doc references
    # (.claude/skills/.codex/skills .md) can surface as TARGETED noise → hand-verified
    # EXCLUDED_REPOS during certification (never confirm/headline). ---
    {
        "id": "ovrtx", "name": "ovrtx", "tier": "omniverse",
        "language": "python",
        "token": "ovrtx",
        "citation_query": "ovrtx", "citation_tier": "A",
        "citation_confidence": "high",
        "import_namespace": "ovrtx",         # strict anchor (import ovrtx); distinctive in .py
        "strict_import": True,               # import-shaped match only (kills bare-substring/ovx_ noise)
        "pip_pattern": ["ovrtx"],
        "cpp_headers": ["ovrtx.h"],          # matches #include <ovrtx/ovrtx.h> (own-source C/C++ => confirmed)
        "index_hints": ["pypi.org/project/ovrtx", "nvidia-omniverse.github.io/ovrtx"],
        "header": "",
        "released_on": "2026-02",            # GitHub v0.1.0 "Initial release" 2026-02-13 (PyPI alpha 0.0.0a0 2025-12-12)
        "released_confidence": "high",
        "description": "C/Python SDK for Omniverse RTX: RTX sensor simulation (camera/lidar/radar) and visualization for Physical AI / robotics / synthetic data.",
    },
]

# REQ-14 high-volume onboarding is deliberately additive. Mature detectors
# above retain their historical confirmed/bundled/targeted behavior. Each
# direct declaration evaluates only the bands certified by the reviewed
# evidence contract; every other band publishes as ``not_evaluated``.
LIBRARIES.extend(REQ14_DIRECT_LIBRARIES)

# Exact canonical repositories that are genuine adopters despite also being
# upstreams for copied/vendor exclusion. The exception applies only to the
# named repository itself; parent/source lineage and similarly named copies
# remain excluded.
LIBRARY_REPOSITORY_EXCEPTIONS = {
    "nvpl": frozenset({"pytorch/pytorch"}),
    "nvshmem": frozenset({
        "bytedance/flux",
        "lattice/quda",
        "rocm/transformerengine",
    }),
}
for _library in LIBRARIES:
    _exceptions = LIBRARY_REPOSITORY_EXCEPTIONS.get(_library["id"])
    if _exceptions:
        _library["repository_exceptions"] = tuple(sorted(_exceptions))

# Source file extensions that count as a genuine C/C++/CUDA integration.
SOURCE_EXTS = [
    "cu", "cuh", "cpp", "cc", "cxx", "c++",
    "h", "hh", "hpp", "hxx", "inc", "inl", "ipp", "tpp", "cinc",
]

# Python device-extension path: nvmath-python exposes some Dx libraries to
# numba-cuda kernels via nvmath.device.{fft,matmul,random}. A repo whose own .py
# source calls these is a genuine integration, counted the same as a C++ one
# (only the row's language differs). Keyed by library id. Libraries without a
# Python device API (cuSolverDx, nvCOMPDx) are absent here.
PY_SIGNALS = {
    "cufftdx": ["nvmath.device.fft"],
    "cublasdx": ["nvmath.device.matmul"],
    "curanddx": ["nvmath.device.random"],
}

# ---------------------------------------------------------------------------
# Python-first detection (pip-distributed libraries: DALI, future RAPIDS, etc.).
# These libraries have NO single canonical include, so usage is detected across
# multiple surfaces of differing strength:
#   - source IMPORT of the namespace in own .py/.ipynb  -> confirmed (Integration)
#   - the pip package named in a dependency manifest / Dockerfile, no import
#       -> "bundled" class internally, displayed as "Declared" for Python libs
#   - any other mention -> targeted
# ---------------------------------------------------------------------------
# Source surfaces scanned (code search `extension:` + git-grep pathspecs).
PY_SOURCE_EXTS = ["py", "ipynb"]
WARP_API_ANCHORS = {
    "HashGrid", "Mesh", "Tape", "array", "atomic_add", "device", "empty",
    "from_numpy", "func", "init", "kernel", "launch", "mat33", "sim",
    "spatial_vector", "struct", "synchronize", "tid", "to_torch",
    "transform", "vec3", "zeros",
}
# Dependency-manifest / build files searched in DISCOVERY (GitHub `filename:`).
PY_DEP_FILENAMES = ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
                    "environment.yml", "Pipfile", "Dockerfile"]
# Broader git-grep pathspecs used in the per-repo SCAN (leading '*' matches at
# any depth; covers requirements-dev.txt, base.Dockerfile, etc.).
PY_DEP_PATHSPECS = ["*requirements*.txt", "*requirements*.in",
                    "*pyproject.toml", "*setup.py", "*setup.cfg",
                    "*environment*.yml", "*environment*.yaml",
                    "*Pipfile", "*Dockerfile*"]

# "Targeted" discovery: the library is named in the repo's own code or build (a
# code generator that emits it, build files that fetch/link it, a non-C++ kernel
# language) without a direct source include or a bundled SDK copy. Searched
# across code+build file types only — doc-only mentions (.md/.rst/.txt) are
# intentionally excluded to avoid catalog/blog/awesome-list noise.
TARGETED_EXTS = ["py", "cmake", "toml", "cfg", "sh", "rs"]
TARGETED_FILENAMES = ["CMakeLists.txt", "Makefile"]

# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------
# Owner orgs to exclude (matched against the owner derived from the repo PATH,
# never via the API — the API 403s for the NVIDIA org). Lowercased compare.
EXCLUDED_ORGS = {
    "nvidia", "rapidsai", "nvlabs", "nv-legate", "nvidia-merlin",
    "nvidia-isaac-ros", "nvidia-omniverse", "ai-dynamo", "cvcuda",
    # NVIDIA-led projects whose org name lacks the nvidia- prefix — first-party use, not
    # third-party adoption. newton-physics = the Newton physics engine (NVIDIA software, built on
    # Warp/Omniverse); its ovrtx use is NVIDIA using its own RTX SDK (owner review, 2026-07-15).
    "newton-physics",
}
# Exclude any owner starting with these prefixes.
EXCLUDED_ORG_PREFIXES = ("nvidia-", "nv-")
# Repo names matching these substrings are packaging or 3rd-party hand-copies of
# NVIDIA sample repos (not genuine adopters). `cudalibrarysamples` catches manual
# copies of NVIDIA/CUDALibrarySamples that slip past the fork + org exclusions
# (§3.0 trust: 3P sample-repo copies). Substring match on the lowercased name.
EXCLUDED_NAME_SUBSTR = ("feedstock", "cudalibrarysamples")

# Hand-verified false-positive repos that the automated heuristics can't safely catch
# (exact full_name match, lowercased). Ground-truthed 2026-06-26 during the NVSHMEM +
# nvmath-python onboarding. Two classes:
#  (a) root-level VENDORED FRAMEWORK copies whose own #include of a tracked header is the
#      framework's code, not the repo's use — TransformerEngine trees (use NVSHMEM) that
#      sit at the repo root (no third_party/ marker, so VENDOR_PATH_RE misses them), and a
#      copied-nvshmem-examples grab-bag;
#  (b) NAMESPACE COLLISIONS — nvpro/nvtt's C++ "nvmath" library (libnvmath.so / nvmath.lib /
#      "nvmath" in a libs list) matched by the bare "nvmath" substring, NOT `import nvmath`.
# Repo-level exclusion is safe: none of these are genuine adopters of ANY tracked library.
# (The 3 plumed gromacs-PATCH cases are caught generically by VENDOR_PATH_RE's .diff rule.)
EXCLUDED_REPOS = {
    # (a) vendored TransformerEngine (uses NVSHMEM) at repo root + examples grab-bag
    "innovatorlm/innovator-vl", "mlcommons/training_results_v5.1",
    "anonymous452026/ngpt-nvfp4", "ggauranshi-03/nemo-optimizers",
    "heinz217/premidtrainvl-qwen3dense", "magnate3/linux-riscv-dev",
    # (b) "nvmath" substring collisions (NOT nvmath-python): nvpro/nvtt C++ lib (libnvmath.so /
    # nvmath.lib / -lenvmath / "nvmath" in a libs list), an `nvmathdir` build variable, and a
    # `VnVMath`/`vnvmath` Sphinx directive. The opt-in strict_import anchor catches this class
    # on future scans; these are the ones already in this pre-strict_import scan.
    "vircadia/vircadia-native-core", "fire/highfidelity-hifi", "yozlet/interface",
    "koeleck/conan-packages", "shelltdf/osgall", "sandermertens/bake3",
    "jbloino/gxxtools", "vnvlabs/gui",
    # (c) UNDATED clones/derivatives of huge canonical adopters that inherited the canonical's
    # NVSHMEM code (not their own integration). SHA-dedup missed them: a pickaxe timeout on a
    # ~100k-commit history left them undated -> no integration commit SHA -> not grouped. The
    # canonical repo (pytorch/pytorch, openxla/xla, gromacs/gromacs) IS counted separately.
    # (Path-based dedup was tried + rejected: deep paths aren't unique enough -> over-merged
    # legit repos; the regression gate caught it. Hand-verified denylist is the safe tool.)
    "fanbb2333/pytorch-fakegpu", "michelle-wang0/lab3_pytorch_copy",
    "michelle-wang0/lab3_pytorch_copy_demo", "llv22/pytorch.mps", "navjit00/pytorch",
    "punksm4ck/pytorch", "tiendatngcs/pytorch-dec25",
    "zhengly1/pytorch1", "zhengly1/pytorch2", "zhengly1/pytorch3",
    "derekjchow-google/xla",
    "hits-mcm/gromacs-ramd", "hibagus/sc25_rocm_gromacs_2025.2",
    "lu1and10/ewald-splitting-with-prolates",
    # (d) ovrtx AI-agent "skill" doc references (ground-truthed 2026-07-14 during the ovrtx
    # onboarding): these name `ovrtx` only inside .claude/skills / .codex/skills / agent-skill
    # markdown as a documented dependency (seeded by ovrtx's own in-repo skills/) — NOT a source
    # import/#include, so they never CONFIRM, but the Python targeted any-file grep surfaces the
    # .md mention. Repo-level exclusion is safe ONLY for repos that adopt NOTHING else: these
    # seven are ovrtx-doc-only. (NOT excluded, despite the same ovrtx doc-mention: bayuewalker/
    # walkermind-os and sayalinvidia/sayali-skills-test — both are GENUINE `import nvidia.dali`
    # adopters (+ Dx/nvshmem/nvmath targeted); a repo-level drop would wrongly delete those real
    # adoptions, so their ovrtx doc-mention is left as harmless targeted noise. The clean fix is a
    # doc-path guard on the Python targeted grep — banked for a follow-up.)
    "openai/plugins", "concertonotes/codex-plugins", "zhongjingyun/codex-plugins",
    "jukeyman/jukeyman-skills", "jiashuoable/simready-agent",
    "monkey1sai/ai-bim-governance", "jandan138/physics-primitive-agent",
    # (e) third-party RE-UPLOAD of NVIDIA's Newton (newton-physics/newton, now org-excluded):
    # shares Newton's exact ovrtx integration SHA (a78b03b1fff5) — same first-party code, not an
    # independent adopter. Denylisted so excluding the canonical org doesn't promote its mirror
    # into the count (owner review, 2026-07-15).
    "agimani/newton",
    # (f) COINCIDENTAL "ovrtx" substring in unrelated code (verified 2026-07-15) — not the SDK:
    # a space-invaders game, an auto-generated random file tree, a Django settings file, an htmx
    # audit. Not caught by DOC_SKILL_PATH_RE (the matches are in code files, not docs/skills), so
    # denylisted by hand. bench_ds_projects also had a coincidental cuPQC substring (same generated
    # tree) — dropping the junk repo clears both.
    "gouravrdutta/space-invader-game", "aquiles021110/game-dev-2", "shreyashrs7/lang-chain",
    "pearsedarcy/aprils-site", "jengler/bench_ds_projects", "lbliii/chirp",
}

# NVPL pre-clone vendor filter (refresh optimization + precision): NVPL's candidate
# set is dominated by vendored copies/forks of these upstreams (their build files
# carry an NVPL backend option), which are not distinct adopters. Dropped BEFORE the
# clone for NVPL candidates only (lib.family=="nvpl") — see run.py. Genuine adopters
# named like these (forked-from / named-after) are the rare exception we accept losing.
NVPL_VENDOR_PARENTS = {
    "pytorch/pytorch", "ggml-org/llama.cpp", "ggerganov/llama.cpp", "ggml-org/ggml",
    "ggerganov/ggml", "lammps/lammps", "ml-explore/mlx", "ollama/ollama",
}
NVPL_VENDOR_NAME_SUBSTR = ("llama.cpp", "llamacpp", "llama-cpp", "ggml", "whisper.cpp",
                           "lammps", "/ollama")

# A tree path is "vendored" (a bundled copy of the SDK, not the repo's own
# source) if it matches this regex. Includes inside vendored paths do NOT
# count as a genuine integration.
import re  # noqa: E402

VENDOR_PATH_RE = re.compile(
    r"(^|/)("
    r"mathdx|cublasdx|cufftdx|cusolverdx|curanddx|nvcompdx|libmathdx|"
    r"third[_-]?party|thirdparty|extern(al)?|vendor(ed)?|deps|_deps|dependencies|"
    r"subprojects|submodules|external_libs|external_deps|external_modules|"
    r"src[_-]?ext|3rdparty|3rd[_-]party"
    r")/"
    r"|/[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]+)?/"   # version dirs e.g. /24.08/ /25.12/
    r"|\.(diff|patch)/",  # a patch tree of ANOTHER project (e.g. plumed's gromacs-2024.3.diff/
                          # ships gromacs source incl. its NVSHMEM use — not the repo's own use)
    re.IGNORECASE,
)

# Distinctive roots of copied upstream projects and source corpora.  These are
# deliberately narrower than generic names such as ``src`` or ``python``:
# source under one of these roots is the upstream project's implementation,
# not evidence that the enclosing repository directly integrates every CUDA-X
# library used by that implementation.  Host source may still include the
# upstream library from outside the copied root and prove direct use normally.
COPIED_PROJECT_PATH_RE = re.compile(
    r"(^|/)("
    r"cuda-samples|fake[_-]?cuda|isaac-gr00t|darknet|models-develop|"
    r"ollama|ggml|kokkos|cutlass"
    r")/"
    r"|(^|/)jobspec-conversion/data/",
    re.IGNORECASE,
)

# An "environment dump" is a package-manager install directory committed
# wholesale to git (a checked-in virtualenv / node_modules), NOT a deliberate
# vendoring of the library. Kept SEPARATE from VENDOR_PATH_RE on purpose: a
# vendored copy ("bundled") is a real adoption signal, but an env dump is pure
# noise — `pip install nvmath-python` drops the library's own files into
# site-packages, which would otherwise score as a confirmed integration.
# Hits under these paths are treated as non-evidence; a repo whose ONLY
# evidence is an env dump is dropped entirely (like EXCLUDED_ORGS / feedstock).
ENV_DUMP_PATH_RE = re.compile(
    r"(^|/)("
    r"site[_-]?packages|dist-packages|node_modules|conda-meta|"
    r"\.?venv|virtualenv|__pypackages__|\.conda|\.buildozer|"
    r"\.ipynb_checkpoints|"  # Jupyter autosave cruft (a backup copy, not real source)
    r"\.virtual_documents"   # JupyterLab-LSP generated mirrors, not authored notebooks
    r")/",
    re.IGNORECASE,
)

# A file that names a library only as AI-AGENT DOCUMENTATION — an agent "skill" (a markdown
# instruction file an agent reads) or a plain doc — is NOT code/build adoption. e.g. `ovrtx`
# appears in NVIDIA's `omniverse-cad-to-simready` agent skill (.claude/skills/.../SKILL.md, which
# bundles an `ovrtx-render-service`) copied into third-party repos: the repo documents ovrtx for an
# agent, it doesn't use it. Excluded from the "targeted" band, aligning the Python detector with
# the C++ rule that already searches only code/build files, never docs. The agent-skill PRESENCE is
# a distinct, deliberately-separate signal (roadmap Phase-1 M1.6) — not folded into code adoption.
DOC_SKILL_PATH_RE = re.compile(
    r"(^|/)(\.claude|\.codex|\.agent|\.agents|skills?|skillhub)/"   # agent-skill / skill trees
    r"|(^|/)(AGENTS?|CLAUDE|GEMINI)\.mdx?$"                          # agent instruction files
    r"|\.(md|mdx|markdown|rst|txt)$",                               # plain docs
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# AI / agent co-author detection signatures.
# Each entry: (agent_label, kind, compiled_regex). `kind` documents where the
# signal lives. Cross-checked against botcommits.dev + logic-star-ai/insights.
# NOTE: Cursor, Gemini-CLI, inline Copilot, and all web/copy-paste usage leave
# NO commit-level marker. Every AI figure here is a LOWER BOUND, never "no AI".
# ---------------------------------------------------------------------------
def _rx(p):
    return re.compile(p, re.IGNORECASE)

AI_SIGNALS = [
    ("Claude Code", "trailer", _rx(r"co-authored-by:\s*claude")),
    ("Claude Code", "email", _rx(r"<[^>]*@anthropic\.com>")),
    ("Claude Code", "body", _rx(r"generated with \[?claude code\]?|\U0001F916 generated with")),
    ("GitHub Copilot", "author", _rx(r"copilot(-swe-agent)?\[bot\]|\d+\+copilot@users\.noreply\.github\.com")),
    ("OpenAI Codex", "email", _rx(r"<[^>]*@openai\.com>|noreply@openai\.com")),
    ("Aider", "trailer", _rx(r"co-authored-by:\s*aider")),
    ("Aider", "author", _rx(r"\(aider\)")),
    ("Devin", "author", _rx(r"devin-ai-integration\[bot\]")),
    ("Devin", "trailer", _rx(r"co-authored-by:\s*devin-ai")),
    ("Google Jules", "author", _rx(r"google-labs-jules\[bot\]")),
    ("Gemini Code Assist", "trailer", _rx(r"co-authored-by:\s*gemini-code-assist\[bot\]")),
    ("OpenHands", "author", _rx(r"openhands")),
    ("Codegen", "author", _rx(r"codegen-sh")),
    ("Tembo", "author", _rx(r"tembo-io")),
]

# Repo-level config files that indicate AI-coding-tool USAGE (not authorship).
AI_CONFIG_FILE_RE = re.compile(
    r"(^|/)("
    r"CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.clinerules|\.windsurfrules|"
    r"\.aider\.conf\.yml|\.aiderignore"
    r")$|(^|/)\.cursor/|(^|/)\.github/copilot-instructions\.md$",
    re.IGNORECASE,
)
