"""Versioned CUDA-X portfolio catalog and REQ-14 direct detector declarations.

The catalog is deliberately broader than the detector registry.  A product can
belong to the official CUDA-X portfolio while lacking an honest direct-source
metric.  Those records remain visible as ``needs_metric_contract`` rather than
being published as zero-adoption libraries.
"""

import hashlib
import json
import re
from pathlib import Path

CATALOG_VERSION = "2026-07-27.1"
CATALOG_SOURCE = "https://developer.nvidia.com/cuda/cuda-x-libraries"
CATALOG_OBSERVED_ON = "2026-07-27"


def _entry(identifier, name, category, *, kind="product",
           trackability="direct_code", status="active", rollup_to=None,
           provenance="official_cuda_x", description=None):
    item = {
        "id": identifier,
        "name": name,
        "category": category,
        "kind": kind,
        "trackability": trackability,
        "catalog_status": status,
        "rollup_to": rollup_to,
        "provenance": provenance,
        "first_observed_on": CATALOG_OBSERVED_ON,
    }
    if description is not None:
        item["description"] = description
    return item


# Exactly the 49 first-party entries present in the official CUDA-X sections on
# the observation date.  Partner libraries are intentionally absent.
OFFICIAL_CUDA_X = [
    _entry("cublas", "cuBLAS", "math"),
    _entry("cufft", "cuFFT", "math"),
    _entry("curand", "cuRAND", "math"),
    _entry("cusolver", "cuSOLVER", "math"),
    _entry("cusparse", "cuSPARSE", "math"),
    _entry("cutensor", "cuTENSOR", "math"),
    _entry("cudss", "cuDSS", "math"),
    _entry("cuda-math-api", "CUDA Math API", "math",
           kind="technology", trackability="needs_metric_contract",
           description="GPU-accelerated standard mathematical functions and device intrinsics."),
    _entry("amgx", "AmgX", "math"),
    _entry("nvmath", "nvmath-python", "math"),
    _entry("cuequivariance", "cuEquivariance", "scientific"),
    _entry("alchemi", "NVIDIA ALCHEMI", "scientific",
           kind="service", trackability="needs_metric_contract",
           description="AI microservices and tools for accelerated chemistry and materials discovery."),
    _entry("culitho", "cuLitho", "scientific",
           trackability="needs_metric_contract",
           description="GPU-accelerated computational lithography for semiconductor manufacturing."),
    _entry("cuest", "cuEST", "scientific",
           trackability="needs_metric_contract",
           description="GPU-accelerated electronic structure calculations for quantum chemistry."),
    _entry("warp", "NVIDIA Warp", "physics"),
    _entry("physicsnemo", "NVIDIA PhysicsNeMo", "physics"),
    _entry("earth2", "NVIDIA Earth-2", "physics",
           kind="model_family", trackability="needs_metric_contract",
           description="Open AI models and tools for weather forecasting and climate simulation."),
    _entry("cuquantum", "cuQuantum", "quantum"),
    _entry("cupqc", "cuPQC", "quantum"),
    _entry("cudaq-qec", "CUDA-Q QEC", "quantum"),
    _entry("cudaq-solvers", "CUDA-Q Solvers", "quantum"),
    _entry("cudnn", "NVIDIA cuDNN", "deep-learning"),
    _entry("tensorrt", "NVIDIA TensorRT", "deep-learning"),
    _entry("cutlass", "CUTLASS", "deep-learning"),
    _entry("flashinfer", "FlashInfer", "deep-learning"),
    _entry("thrust", "Thrust", "parallel"),
    _entry("cub", "CUB", "parallel"),
    _entry("cuda-compute", "cuda.compute", "parallel",
           trackability="needs_metric_contract",
           description="Python access to customizable CUDA C++ parallel algorithms."),
    _entry("cuda-parallel", "cuda.parallel", "parallel",
           trackability="needs_metric_contract",
           description="Python APIs for GPU-accelerated sort, scan, reduce, and transform algorithms."),
    _entry("cudf", "cuDF", "data"),
    _entry("cuvs", "cuVS", "data"),
    _entry("cuml", "cuML", "data"),
    _entry("cuopt", "cuOpt", "data"),
    _entry("cugraph", "cuGraph", "data"),
    _entry("nemo-curator", "NeMo Curator", "data"),
    _entry("morpheus", "Morpheus", "data"),
    _entry("nvcomp", "nvComp", "data"),
    _entry("gds", "GPU Direct Storage", "data"),
    _entry("dask", "Dask", "data", kind="framework",
           trackability="needs_metric_contract",
           description="Parallel and distributed computing for Python analytics workloads."),
    _entry("nvimagecodec", "nvImageCodec", "image-video"),
    _entry("dali", "NVIDIA DALI", "image-video"),
    _entry("cvcuda", "CV-CUDA", "image-video"),
    _entry("cucim", "cuCIM", "image-video"),
    _entry("npp", "NPP", "image-video"),
    _entry("video-codec-sdk", "NVIDIA Video Codec SDK", "image-video"),
    _entry("optical-flow-sdk", "NVIDIA Optical Flow SDK", "image-video"),
    _entry("nvshmem", "NVSHMEM", "communication"),
    _entry("nccl", "NCCL", "communication"),
    _entry("nixl", "NIXL", "communication"),
]


COMPONENTS_AND_RETAINED = [
    _entry("cufftdx", "cuFFTDx", "math", kind="component",
           rollup_to="cufft", provenance="requested_component"),
    _entry("cublasdx", "cuBLASDx", "math", kind="component",
           rollup_to="cublas", provenance="requested_component"),
    _entry("cusolverdx", "cuSolverDx", "math", kind="component",
           rollup_to="cusolver", provenance="requested_component"),
    _entry("curanddx", "cuRANDDx", "math", kind="component",
           rollup_to="curand", provenance="requested_component"),
    _entry("nvcompdx", "nvCOMPDx", "data", kind="component",
           rollup_to="nvcomp", provenance="requested_component"),
    _entry("cufftmp", "cuFFTMp", "math", kind="component",
           rollup_to="cufft", provenance="requested_component"),
    _entry("cublasmp", "cuBLASMp", "math", kind="component",
           rollup_to="cublas", provenance="requested_component"),
    _entry("cusolvermp", "cuSOLVERMp", "math", kind="component",
           rollup_to="cusolver", provenance="requested_component"),
    _entry("cufftxt", "cuFFTXt", "math", kind="component",
           rollup_to="cufft", provenance="requested_component"),
    _entry("cublasxt", "cuBLASXt", "math", kind="component",
           rollup_to="cublas", provenance="requested_component"),
    _entry("cublaslt", "cuBLASLt", "math", kind="component",
           rollup_to="cublas", provenance="requested_component"),
    _entry("cusparselt", "cuSPARSELt", "math", kind="component",
           rollup_to="cusparse", provenance="requested_component"),
    _entry("tensorrt-llm", "TensorRT LLM", "deep-learning", kind="component",
           rollup_to="tensorrt", provenance="official_combined_entry"),
    _entry("cusparsedx", "cuSPARSEDx", "math", kind="component",
           trackability="needs_metric_contract", status="preview",
           rollup_to="cusparse", provenance="requested_component",
           description="Device-side sparse linear algebra for fused GPU kernels."),
    _entry("nvpl", "NVPL", "math", status="retained",
           provenance="previously_tracked"),
    _entry("ovrtx", "ovrtx", "physics", status="retained",
           provenance="previously_tracked"),
]

CATALOG = OFFICIAL_CUDA_X + COMPONENTS_AND_RETAINED

# This literal is the immutable first versioned boundary. It is intentionally
# not derived from CATALOG: deleting a row from the current snapshot must fail
# validation until an explicit retired/disappeared event is appended.
CATALOG_BASELINE_2026_07_27_IDS = frozenset(
    """
    cublas cufft curand cusolver cusparse cutensor cudss cuda-math-api amgx
    nvmath cuequivariance alchemi culitho cuest warp physicsnemo earth2
    cuquantum cupqc cudaq-qec cudaq-solvers cudnn tensorrt cutlass flashinfer
    thrust cub cuda-compute cuda-parallel cudf cuvs cuml cuopt cugraph
    nemo-curator morpheus nvcomp gds dask nvimagecodec dali cvcuda cucim npp
    video-codec-sdk optical-flow-sdk nvshmem nccl nixl cufftdx cublasdx
    cusolverdx curanddx nvcompdx cufftmp cublasmp cusolvermp cufftxt cublasxt
    cublaslt cusparselt tensorrt-llm cusparsedx nvpl ovrtx
    """.split()
)


def _catalog_event(item):
    """Return the immutable observation event for this catalog revision.

    The first checked-in revision cannot honestly reconstruct dates that were
    never recorded. Retained V1 entries record that limitation explicitly
    instead of inventing an earlier appearance date.
    """
    retained = item["catalog_status"] == "retained"
    return {
        "library_id": item["id"],
        "catalog_version": CATALOG_VERSION,
        "observed_on": CATALOG_OBSERVED_ON,
        "event": "retained" if retained else "appeared",
        "name": item["name"],
        "catalog_status": item["catalog_status"],
        "source": "last_v1_release" if retained else CATALOG_SOURCE,
        "provenance": item["provenance"],
        "effective_on": None if retained else CATALOG_OBSERVED_ON,
        "note": (
            "Present in the last V1 release but absent from the observed "
            "official CUDA-X page; original appearance date is unknown."
            if retained
            else "First versioned catalog observation."
        ),
    }


# Append-only catalog observations. Future revisions add events here:
# ``renamed`` retains the stable library_id and old/new names; ``retired`` and
# ``disappeared`` retain the row even when the source page changes.
CATALOG_EVENTS = [_catalog_event(item) for item in CATALOG]


def _cpp(identifier, name, headers, released_on, *, rollup_to=None,
         tier="req14-direct", token=None, description=None):
    headers = list(headers)
    exact_headers = [value for value in headers if not value.endswith("/")]
    header_prefixes = [value for value in headers if value.endswith("/")]
    return {
        "id": identifier,
        "name": name,
        "tier": tier,
        "token": token or headers[0].strip("/").split("/")[-1].split(".")[0],
        "header": exact_headers[0] if len(exact_headers) == 1 else "",
        "cpp_headers": exact_headers,
        "header_prefixes": header_prefixes,
        "direct_only": True,
        "classification_coverage": ["confirmed"],
        "not_evaluated_classes": ["bundled", "targeted"],
        "rollup_to": rollup_to,
        "released_on": released_on,
        "released_confidence": "low",
        "description": description or ("%s direct API integration." % name),
    }


def _python(identifier, name, namespaces, packages, released_on, *,
            rollup_to=None, description=None):
    namespaces = list(namespaces)
    packages = list(packages)
    return {
        "id": identifier,
        "name": name,
        "tier": "req14-direct",
        "language": "python",
        "token": namespaces[0],
        "import_namespace": namespaces[0],
        "import_namespaces": namespaces,
        "strict_import": True,
        "pip_pattern": packages,
        "header": "",
        "direct_only": True,
        "classification_coverage": ["confirmed"],
        "not_evaluated_classes": ["bundled", "targeted"],
        "rollup_to": rollup_to,
        "released_on": released_on,
        "released_confidence": "low",
        "description": description or ("%s direct Python integration." % name),
    }


# Reviewed exact include/import anchors used by the REQ-14 direct batches.
# Package/build signals become classification evidence only when the evidence
# contract explicitly enables their band.
REQ14_DIRECT_LIBRARY_CANDIDATES = [
    # Math APIs and requested component rollups.
    _cpp("cublas", "cuBLAS", ["cublas.h", "cublas_v2.h"], "2007-06",
         description="GPU-accelerated basic linear algebra routines."),
    _cpp("cublaslt", "cuBLASLt", ["cublasLt.h"], "2019-02",
         rollup_to="cublas",
         description="Flexible GPU matrix multiplication with advanced layouts and epilogues."),
    _cpp("cublasxt", "cuBLASXt", ["cublasXt.h"], "2013-02",
         rollup_to="cublas",
         description="Multi-GPU host API for large basic linear algebra operations."),
    _cpp("cublasmp", "cuBLASMp", ["cublasmp.h", "cublasMp.h"], "2022-08",
         rollup_to="cublas",
         description="Multi-process, multi-GPU distributed dense linear algebra."),
    _cpp("cufft", "cuFFT", ["cufft.h"], "2007-06",
         description="GPU-accelerated fast Fourier transforms."),
    _cpp("cufftxt", "cuFFTXt", ["cufftXt.h"], "2014-08",
         rollup_to="cufft",
         description="Multi-GPU fast Fourier transforms for large datasets."),
    _cpp("cufftmp", "cuFFTMp", ["cufftMp.h"], "2022-08",
         rollup_to="cufft",
         description="Multi-process, multi-GPU distributed fast Fourier transforms."),
    _cpp("curand", "cuRAND", ["curand.h", "curand_kernel.h"], "2010-09",
         description="GPU-accelerated pseudorandom and quasirandom number generation."),
    _cpp("cusolver", "cuSOLVER",
         ["cusolverDn.h", "cusolverSp.h", "cusolverRf.h", "cusolverMg.h"],
         "2014-08",
         description="GPU-accelerated dense and sparse factorizations and linear solvers."),
    _cpp("cusolvermp", "cuSOLVERMp", ["cusolverMp.h"], "2022-08",
         rollup_to="cusolver",
         description="Multi-process, multi-GPU distributed dense linear solvers."),
    _cpp("cusparse", "cuSPARSE", ["cusparse.h"], "2009-09",
         description="GPU-accelerated sparse matrix operations and linear algebra."),
    _cpp("cusparselt", "cuSPARSELt", ["cusparseLt.h"], "2021-05",
         rollup_to="cusparse",
         description="Structured-sparse matrix multiplication for NVIDIA Tensor Cores."),
    _cpp(
        "cutensor",
        "cuTENSOR",
        ["cutensor.h", "cutensorMg.h"],
        "2019-09",
        description="High-performance tensor contractions, reductions, and elementwise operations.",
    ),
    _cpp("cudss", "cuDSS", ["cudss.h"], "2023-11",
         description="GPU-accelerated direct sparse linear solvers."),
    _cpp("amgx", "AmgX", ["amgx_c.h"], "2014-01",
         description="GPU-accelerated algebraic multigrid and iterative linear solvers."),
    # Scientific, physics and quantum surfaces with stable import roots.
    _python("cuequivariance", "cuEquivariance",
            ["cuequivariance", "cuequivariance_torch", "cuequivariance_jax"],
            ["cuequivariance", "cuequivariance-torch", "cuequivariance-jax"],
            "2024-10",
            description="GPU-accelerated equivariant tensor products for geometric deep learning."),
    _python("warp", "NVIDIA Warp", ["warp"], ["warp-lang"], "2022-03",
            description="Python framework for high-performance differentiable simulation and GPU kernels."),
    _python("physicsnemo", "NVIDIA PhysicsNeMo", ["physicsnemo"],
            ["nvidia-physicsnemo"], "2023-06",
            description="Physics-informed machine learning for modeling and simulating physical systems."),
    _python("cudaq-qec", "CUDA-Q QEC", ["cudaq_qec"], ["cudaq-qec"],
            "2025-03",
            description="Tools for quantum error-correction research, simulation, and decoder development."),
    _python("cudaq-solvers", "CUDA-Q Solvers", ["cudaq_solvers"],
            ["cudaq-solvers"], "2025-03",
            description="Quantum chemistry and combinatorial optimization solvers for CUDA-Q."),
    # Deep learning and parallel.
    _cpp("cudnn", "NVIDIA cuDNN", ["cudnn.h", "cudnn_frontend.h"], "2014-09",
         description="GPU-accelerated primitives for deep neural network training and inference."),
    {
        **_python("tensorrt", "NVIDIA TensorRT", ["tensorrt"],
                  ["tensorrt"], "2016-08",
                  description="SDK for optimizing and accelerating deep learning inference."),
        "cpp_headers": ["NvInfer.h", "NvInferRuntime.h"],
    },
    _python("tensorrt-llm", "TensorRT LLM", ["tensorrt_llm"],
            ["tensorrt-llm"], "2023-10", rollup_to="tensorrt",
            description="Toolkit for optimizing and serving large language models on NVIDIA GPUs."),
    _cpp("cutlass", "CUTLASS", ["cutlass/"], "2017-12",
         description="CUDA C++ templates for high-performance matrix and tensor operations."),
    _python("flashinfer", "FlashInfer", ["flashinfer"], ["flashinfer-python"],
            "2023-11",
            description="High-performance GPU kernels for large language model inference and serving."),
    _cpp("thrust", "Thrust", ["thrust/"], "2009-01",
         description="C++ parallel algorithms and data structures for CUDA."),
    _cpp("cub", "CUB", ["cub/"], "2011-01",
         description="CUDA C++ primitives for block-, warp-, and device-wide parallel operations."),
    # Data ecosystem direct imports/APIs.
    _python("cudf", "cuDF", ["cudf"], ["cudf-cu12", "cudf-cu13"], "2018-02",
            description="GPU DataFrame library for accelerated data processing and analytics."),
    _python("cuvs", "cuVS", ["cuvs"], ["cuvs-cu12", "cuvs-cu13"], "2024-03",
            description="GPU-accelerated vector search and clustering algorithms."),
    _python("cuml", "cuML", ["cuml"], ["cuml-cu12", "cuml-cu13"], "2018-07",
            description="GPU-accelerated machine learning with scikit-learn-style APIs."),
    _python("cuopt", "cuOpt", ["cuopt"], ["cuopt-cu12", "cuopt-cu13"], "2022-03",
            description="GPU-accelerated decision optimization for routing and scheduling."),
    _python("cugraph", "cuGraph", ["cugraph"], ["cugraph-cu12", "cugraph-cu13"],
            "2018-02", description="GPU-accelerated graph analytics and algorithms."),
    _python("nemo-curator", "NeMo Curator", ["nemo_curator"],
            ["nemo-curator"], "2023-08",
            description="GPU-accelerated data curation for generative AI training datasets."),
    _python("morpheus", "Morpheus", ["morpheus"], ["morpheus"], "2022-03",
            description="GPU-accelerated cybersecurity AI framework for real-time data pipelines."),
    {
        **_cpp("nvcomp", "nvComp", ["nvcomp.h", "nvcomp/"], "2020-08",
               description="GPU-accelerated lossless data compression and decompression."),
        "language": "python",
        "import_namespace": "nvidia.nvcomp",
        "import_namespaces": ["nvidia.nvcomp"],
        "strict_import": True,
        "pip_pattern": ["nvidia-nvcomp-cu12", "nvidia-nvcomp-cu13"],
    },
    _cpp("gds", "GPU Direct Storage", ["cufile.h"], "2021-06",
         description="Direct storage-to-GPU data paths that bypass CPU bounce buffers."),
    # Image/video.
    _python("nvimagecodec", "nvImageCodec", ["nvidia.nvimgcodec"],
            ["nvidia-nvimgcodec-cu12", "nvidia-nvimgcodec-cu13"], "2023-09",
            description="GPU-accelerated image decoding, encoding, and transcoding."),
    _python("cvcuda", "CV-CUDA", ["cvcuda"],
            ["cvcuda-cu12", "cvcuda-cu13"], "2022-12",
            description="GPU-accelerated computer-vision preprocessing for AI pipelines."),
    _python("cucim", "cuCIM", ["cucim"], ["cucim-cu12", "cucim-cu13"], "2021-03",
            description="GPU-accelerated image processing and I/O for biomedical imaging."),
    _cpp("npp", "NPP", ["npp.h", "nppc.h", "nppi.h", "npps.h"], "2009-01",
         description="GPU-accelerated image, signal, and video processing primitives."),
    _cpp("video-codec-sdk", "NVIDIA Video Codec SDK",
         ["nvEncodeAPI.h", "nvcuvid.h", "cuviddec.h"], "2012-01",
         description="Hardware-accelerated video encoding and decoding APIs."),
    _cpp(
        "optical-flow-sdk",
        "NVIDIA Optical Flow SDK",
        [
            "nvofapi.h",
            "nvOpticalFlowCuda.h",
            "nvOpticalFlowD3D11.h",
            "nvOpticalFlowD3D12.h",
            "nvOpticalFlowVulkan.h",
        ],
        "2018-09",
        description="Hardware-accelerated optical flow and stereo disparity estimation.",
    ),
    # Communication.
    _cpp("nccl", "NCCL", ["nccl.h"], "2016-01",
         description="Multi-GPU and multi-node collective communication primitives."),
    {
        **_python("nixl", "NIXL", ["nixl"], ["nixl"], "2024-09",
                  description="High-performance point-to-point data transfers across heterogeneous memory and storage."),
        "cpp_headers": ["nixl.h"],
    },
]

# Reviewed build-configuration evidence for the targeted band. These are
# official imported targets (or TensorRT's canonical linker target), not broad
# product-name tokens. They are classification evidence only in authored CMake
# files; discovery may use the same literals as candidate anchors.
def _cuda_cmake_targets(*names):
    return ["CUDA::%s" % name for name in names]


REQ14_TARGETED_BUILD_SIGNALS = {
    "cublas": _cuda_cmake_targets("cublas", "cublas_static"),
    "cublaslt": _cuda_cmake_targets("cublasLt", "cublasLt_static"),
    "cublasmp": ["cublasmp", "-lcublasmp"],
    "cufft": _cuda_cmake_targets(
        "cufft",
        "cufftw",
        "cufft_static",
        "cufft_static_nocallback",
        "cufftw_static",
    ),
    "cufftmp": ["cufftMp"],
    "curand": _cuda_cmake_targets("curand", "curand_static"),
    "cusolver": _cuda_cmake_targets("cusolver", "cusolver_static"),
    "cusolvermp": ["cusolverMp"],
    "cusparse": _cuda_cmake_targets("cusparse", "cusparse_static"),
    "cutensor": ["cutensor"],
    "cudss": ["cudss", "cudss_static"],
    "gds": _cuda_cmake_targets(
        "cuFile",
        "cuFile_static",
        "cuFile_rdma",
        "cuFile_rdma_static",
    ),
    "npp": _cuda_cmake_targets(
        *[
            target + suffix
            for target in (
                "nppc",
                "nppial",
                "nppicc",
                "nppicom",
                "nppidei",
                "nppif",
                "nppig",
                "nppim",
                "nppist",
                "nppisu",
                "nppitc",
                "npps",
            )
            for suffix in ("", "_static")
        ]
    ),
    "nvcomp": ["nvcomp::nvcomp"],
    "tensorrt": ["nvinfer", "nvinfer_plugin"],
}

_REQ14_TARGETED_BUILD_DISCOVERY_ROOTS = {
    "cublas": "cublas",
    "cublaslt": "cublasLt",
    "cublasmp": "cublasmp",
    "cufft": "cufft",
    "cufftmp": "cufftMp",
    "curand": "curand",
    "cusolver": "cusolver",
    "cusolvermp": "cusolverMp",
    "cusparse": "cusparse",
    "cutensor": "cutensor",
    "cudss": "cudss",
    "gds": "cuFile",
    "npp": "npp",
    "nvcomp": "nvcomp",
    "tensorrt": "nvinfer",
}
REQ14_TARGETED_BUILD_DISCOVERY_ANCHORS = {}
for _library_id, _target_signals in REQ14_TARGETED_BUILD_SIGNALS.items():
    _root = _REQ14_TARGETED_BUILD_DISCOVERY_ROOTS[_library_id]
    REQ14_TARGETED_BUILD_DISCOVERY_ANCHORS[_library_id] = list(
        dict.fromkeys(
            (
                _signal_value.split("::", 1)[0] + "::" + _root
                if "::" in _signal_value
                else _root
            )
            for _signal_value in _target_signals
        )
    )

for _library in REQ14_DIRECT_LIBRARY_CANDIDATES:
    _signals = REQ14_TARGETED_BUILD_SIGNALS.get(_library["id"])
    if _signals:
        _library["targeted_build_signals"] = list(_signals)
        _library["targeted_build_discovery_anchors"] = list(
            REQ14_TARGETED_BUILD_DISCOVERY_ANCHORS[_library["id"]]
        )

# Citation declarations are independent of code-detection anchors.  Distinctive
# CUDA/NVIDIA product names use the direct coined term.  Collision-prone common
# names use a quoted product phrase or an explicit CUDA/GPU co-occurrence term.
# This table is intentionally complete: a newly enabled direct detector cannot
# silently omit its research-adoption lane.
REQ14_CITATION_METADATA = {
    "cublas": {"citation_query": "cuBLAS", "citation_tier": "A", "citation_confidence": "high"},
    "cublaslt": {"citation_query": "cuBLASLt", "citation_tier": "A", "citation_confidence": "high"},
    "cublasxt": {"citation_query": "cuBLASXt", "citation_tier": "A", "citation_confidence": "high"},
    "cublasmp": {"citation_query": "cuBLASMp", "citation_tier": "A", "citation_confidence": "high"},
    "cufft": {"citation_query": "cuFFT", "citation_tier": "A", "citation_confidence": "high"},
    "cufftxt": {"citation_query": "cuFFTXt", "citation_tier": "A", "citation_confidence": "high"},
    "cufftmp": {"citation_query": "cuFFTMp", "citation_tier": "A", "citation_confidence": "high"},
    "curand": {"citation_query": "cuRAND", "citation_tier": "A", "citation_confidence": "high"},
    "cusolver": {"citation_query": "cuSOLVER", "citation_tier": "A", "citation_confidence": "high"},
    "cusolvermp": {"citation_query": "cuSOLVERMp", "citation_tier": "A", "citation_confidence": "high"},
    "cusparse": {"citation_query": "cuSPARSE", "citation_tier": "A", "citation_confidence": "high"},
    "cusparselt": {"citation_query": "cuSPARSELt", "citation_tier": "A", "citation_confidence": "high"},
    "cutensor": {"citation_query": "cuTENSOR", "citation_tier": "A", "citation_confidence": "high"},
    "cudss": {"citation_query": "cuDSS", "citation_tier": "A", "citation_confidence": "high"},
    "amgx": {"citation_query": '"NVIDIA AmgX"', "citation_tier": "B", "citation_confidence": "high"},
    "cuequivariance": {"citation_query": "cuEquivariance", "citation_tier": "A", "citation_confidence": "high"},
    "warp": {"citation_query": '"NVIDIA Warp"', "citation_tier": "C", "citation_confidence": "high"},
    "physicsnemo": {"citation_query": "PhysicsNeMo", "citation_tier": "A", "citation_confidence": "high"},
    "cudaq-qec": {"citation_query": '"CUDA-Q QEC"', "citation_tier": "B", "citation_confidence": "high"},
    "cudaq-solvers": {"citation_query": '"CUDA-Q Solvers"', "citation_tier": "B", "citation_confidence": "high"},
    "cudnn": {"citation_query": "cuDNN", "citation_tier": "A", "citation_confidence": "high"},
    "tensorrt": {"citation_query": "TensorRT", "citation_tier": "A", "citation_confidence": "high"},
    "tensorrt-llm": {"citation_query": "TensorRT-LLM", "citation_tier": "A", "citation_confidence": "high"},
    "cutlass": {"citation_query": "CUTLASS", "citation_cooccur": ["CUDA"], "citation_tier": "C", "citation_confidence": "high"},
    "flashinfer": {"citation_query": "FlashInfer", "citation_tier": "A", "citation_confidence": "high"},
    "thrust": {"citation_query": '"CUDA Thrust"', "citation_tier": "C", "citation_confidence": "high"},
    "cub": {"citation_query": "CUB", "citation_cooccur": ["CUDA"], "citation_tier": "C", "citation_confidence": "medium"},
    "cudf": {"citation_query": "cuDF", "citation_tier": "A", "citation_confidence": "high"},
    "cuvs": {"citation_query": "cuVS", "citation_cooccur": ["GPU"], "citation_tier": "C", "citation_confidence": "medium"},
    "cuml": {"citation_query": "cuML", "citation_tier": "A", "citation_confidence": "high"},
    "cuopt": {"citation_query": "cuOpt", "citation_tier": "A", "citation_confidence": "high"},
    "cugraph": {"citation_query": "cuGraph", "citation_tier": "A", "citation_confidence": "high"},
    "nemo-curator": {"citation_query": '"NeMo Curator"', "citation_tier": "B", "citation_confidence": "high"},
    "morpheus": {"citation_query": '"NVIDIA Morpheus"', "citation_tier": "C", "citation_confidence": "high"},
    "nvcomp": {"citation_query": "nvCOMP", "citation_tier": "A", "citation_confidence": "high"},
    "gds": {"citation_query": '"GPUDirect Storage"', "citation_tier": "B", "citation_confidence": "high"},
    "nvimagecodec": {"citation_query": "nvImageCodec", "citation_tier": "A", "citation_confidence": "high"},
    "cvcuda": {"citation_query": "CV-CUDA", "citation_tier": "A", "citation_confidence": "high"},
    "cucim": {"citation_query": "cuCIM", "citation_tier": "A", "citation_confidence": "high"},
    "npp": {"citation_query": '"NVIDIA Performance Primitives"', "citation_tier": "C", "citation_confidence": "high"},
    "video-codec-sdk": {"citation_query": '"NVIDIA Video Codec SDK"', "citation_tier": "C", "citation_confidence": "high"},
    "optical-flow-sdk": {"citation_query": '"NVIDIA Optical Flow SDK"', "citation_tier": "C", "citation_confidence": "high"},
    "nccl": {"citation_query": "NCCL", "citation_cooccur": ["GPU"], "citation_tier": "C", "citation_confidence": "medium"},
    "nixl": {"citation_query": "NIXL", "citation_tier": "A", "citation_confidence": "high"},
}

for _library in REQ14_DIRECT_LIBRARY_CANDIDATES:
    _library.update(REQ14_CITATION_METADATA[_library["id"]])


REQ14_EVIDENCE_CONTRACT_PATH = (
    Path(__file__).with_name("req14_evidence_contract.json")
)
REQ14_EVIDENCE_CONTRACT = json.loads(
    REQ14_EVIDENCE_CONTRACT_PATH.read_text(encoding="utf-8")
)
_contract_candidates = {
    library["id"]: library for library in REQ14_DIRECT_LIBRARY_CANDIDATES
}
_contract_entries = REQ14_EVIDENCE_CONTRACT.get("libraries", {})
if set(_contract_candidates) != set(_contract_entries):
    raise ValueError(
        "REQ-14 evidence contract must cover every direct candidate"
    )
for _identifier, _library in _contract_candidates.items():
    _entry_payload = _contract_entries[_identifier]
    _repository_exclusions = _entry_payload.get(
        "repository_exclusions", []
    )
    _observation_exclusions = _entry_payload.get(
        "discovery_observation_exclusions", []
    )
    if (
        not isinstance(_repository_exclusions, list)
        or any(
            not isinstance(_name, str)
            or _name != _name.casefold()
            or _name.count("/") != 1
            or not all(_name.split("/", 1))
            for _name in _repository_exclusions
        )
        or _repository_exclusions
        != sorted(set(_repository_exclusions))
    ):
        raise ValueError(
            "REQ-14 repository exclusions must be sorted unique "
            "lowercase owner/repository names"
        )
    _observation_fields = (
        "repository",
        "source",
        "signal_id",
        "matched_path",
        "matched_blob",
    )
    if (
        not isinstance(_observation_exclusions, list)
        or any(
            not isinstance(_rule, dict)
            or tuple(sorted(_rule)) != tuple(sorted(_observation_fields))
            or any(
                not isinstance(_rule[_field], str)
                or not _rule[_field]
                for _field in _observation_fields
            )
            or _rule["repository"] != _rule["repository"].casefold()
            or _rule["repository"].count("/") != 1
            or not all(_rule["repository"].split("/", 1))
            or not re.fullmatch(
                r"[0-9a-f]{40}", _rule["matched_blob"]
            )
            for _rule in _observation_exclusions
        )
        or _observation_exclusions
        != sorted(
            _observation_exclusions,
            key=lambda _rule: tuple(
                _rule[_field] for _field in _observation_fields
            ),
        )
        or len({
            tuple(_rule[_field] for _field in _observation_fields)
            for _rule in _observation_exclusions
        }) != len(_observation_exclusions)
    ):
        raise ValueError(
            "REQ-14 discovery observation exclusions must be sorted "
            "unique exact public evidence identities"
        )
    _entry_sha = hashlib.sha256(
        json.dumps(
            _entry_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    _library["evidence_contract"] = {
        "contract_id": REQ14_EVIDENCE_CONTRACT["contract_id"],
        "entry_sha256": _entry_sha,
        "status": _entry_payload["status"],
    }
    if _repository_exclusions:
        # The pipeline's library-scoped canonical/source exclusion contract
        # already checks exact repository names and rename lineage before
        # candidate admission. Keep the reviewed denylist inside the evidence
        # entry so its hash invalidates only the affected library detector.
        _library["vendor_parents"] = set(_repository_exclusions)
    if _observation_exclusions:
        _library["discovery_observation_exclusions"] = tuple(
            dict(_rule) for _rule in _observation_exclusions
        )
    if _entry_payload["status"] == "enabled":
        _library["classification_coverage"] = [
            band
            for band in ("confirmed", "bundled", "targeted")
            if _entry_payload["bands"][band] == "evaluated"
        ]
        _library["not_evaluated_classes"] = [
            band
            for band in ("confirmed", "bundled", "targeted")
            if _entry_payload["bands"][band] == "not_evaluated"
        ]
    elif _entry_payload["status"] == "deferred":
        _library["classification_coverage"] = []
        _library["not_evaluated_classes"] = [
            "confirmed",
            "bundled",
            "targeted",
        ]
    else:
        raise ValueError(
            "unsupported REQ-14 evidence status: %s"
            % _entry_payload["status"]
        )

# Only reviewed, evidence-complete candidates enter discovery and scanning.
# Deferred catalog products remain visible through the catalog and therefore
# publish every classification band as ``not_evaluated`` rather than zero.
REQ14_DIRECT_LIBRARIES = [
    library
    for library in REQ14_DIRECT_LIBRARY_CANDIDATES
    if library["evidence_contract"]["status"] == "enabled"
]
REQ14_DEFERRED_LIBRARIES = [
    library
    for library in REQ14_DIRECT_LIBRARY_CANDIDATES
    if library["evidence_contract"]["status"] == "deferred"
]


def validate_catalog_history(
    catalog=CATALOG,
    events=CATALOG_EVENTS,
    *,
    previous_ids=CATALOG_BASELINE_2026_07_27_IDS,
):
    """Validate additive, explicitly versioned catalog history."""
    allowed_events = {"appeared", "renamed", "retained", "retired", "disappeared"}
    ids = {item["id"] for item in catalog}
    event_keys = set()
    latest = {}
    for event in events:
        required = {
            "library_id",
            "catalog_version",
            "observed_on",
            "event",
            "name",
            "catalog_status",
            "source",
            "provenance",
            "effective_on",
            "note",
        }
        if set(event) != required:
            raise ValueError("catalog event shape is invalid")
        if event["event"] not in allowed_events:
            raise ValueError("unsupported catalog event: %s" % event["event"])
        key = (
            event["library_id"],
            event["catalog_version"],
            event["observed_on"],
            event["event"],
        )
        if key in event_keys:
            raise ValueError("catalog event identity is duplicated")
        event_keys.add(key)
        latest[event["library_id"]] = event
    missing_history = ids.difference(latest)
    if missing_history:
        raise ValueError(
            "catalog entries lack an observation event: %s"
            % ", ".join(sorted(missing_history))
        )
    by_id = {item["id"]: item for item in catalog}
    for identifier, item in by_id.items():
        event = latest[identifier]
        if event["name"] != item["name"]:
            raise ValueError("latest catalog event name is stale: %s" % identifier)
        if event["catalog_status"] != item["catalog_status"]:
            raise ValueError("latest catalog event status is stale: %s" % identifier)
    removed = set(previous_ids).difference(ids)
    terminal = {
        event["library_id"]
        for event in events
        if event["event"] in {"retired", "disappeared"}
    }
    silent = removed.difference(terminal)
    if silent:
        raise ValueError(
            "catalog IDs disappeared without an event: %s"
            % ", ".join(sorted(silent))
        )
    return True


def validate_catalog():
    identifiers = [item["id"] for item in CATALOG]
    if len(OFFICIAL_CUDA_X) != 49:
        raise ValueError("official CUDA-X catalog must contain exactly 49 entries")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("catalog IDs must be unique")
    known = set(identifiers)
    for item in CATALOG:
        if item["rollup_to"] and item["rollup_to"] not in known:
            raise ValueError("unknown rollup parent: %s" % item["rollup_to"])
    candidate_ids = [
        item["id"] for item in REQ14_DIRECT_LIBRARY_CANDIDATES
    ]
    detector_ids = [item["id"] for item in REQ14_DIRECT_LIBRARIES]
    deferred_ids = [item["id"] for item in REQ14_DEFERRED_LIBRARIES]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("REQ-14 candidate IDs must be unique")
    if len(detector_ids) != len(set(detector_ids)):
        raise ValueError("REQ-14 detector IDs must be unique")
    if set(detector_ids).intersection(deferred_ids):
        raise ValueError("enabled and deferred REQ-14 IDs overlap")
    if set(detector_ids).union(deferred_ids) != set(candidate_ids):
        raise ValueError("REQ-14 evidence disposition is incomplete")
    if not set(candidate_ids).issubset(known):
        raise ValueError("REQ-14 detector missing from canonical catalog")
    if set(candidate_ids) != set(REQ14_CITATION_METADATA):
        raise ValueError(
            "REQ-14 citation metadata must cover every direct candidate"
        )
    validate_catalog_history()
    return True


validate_catalog()
