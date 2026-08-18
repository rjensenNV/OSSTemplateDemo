"""Offline acceptance tests for the Phase 8 evidence approval boundary."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from collector.catalog import (
    REQ14_DEFERRED_LIBRARIES,
    REQ14_DIRECT_LIBRARIES,
    REQ14_DIRECT_LIBRARY_CANDIDATES,
    REQ14_EVIDENCE_CONTRACT,
)
from collector.config import LIBRARIES
from collector.discovery.query_plan import signal_specs
from collector.planner import current_fingerprints
from collector.scan import direct_result_from_files, scan_repo
from collector.triage import triage_tree


ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT_LOCK = ROOT / "ops/req14_detector_fingerprints.json"
BUNDLED_IDS = {
    "cuequivariance",
    "warp",
    "physicsnemo",
    "cudaq-qec",
    "cudaq-solvers",
    "tensorrt",
    "tensorrt-llm",
    "flashinfer",
    "cudf",
    "cuvs",
    "cuml",
    "cuopt",
    "cugraph",
    "nemo-curator",
    "nvimagecodec",
    "cvcuda",
    "cucim",
    "nixl",
    "nvcomp",
}
TARGETED_IDS = {
    "cublas",
    "cublaslt",
    "cublasmp",
    "cufft",
    "cufftmp",
    "curand",
    "cusolver",
    "cusolvermp",
    "cusparse",
    "cutensor",
    "cudss",
    "gds",
    "npp",
    "nvcomp",
    "tensorrt",
}
APPROVED_PACKAGE_COUNT = 30
APPROVED_TARGET_COUNT = 53


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def _fixture(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    temporary = tempfile.TemporaryDirectory()
    repo = Path(temporary.name)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Evidence Contract Test")
    _git(repo, "config", "user.email", "evidence@example.invalid")
    for relative, body in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "fixture")
    return temporary


class EvidenceContractTests(unittest.TestCase):
    def test_every_candidate_has_an_explicit_review_disposition(self):
        entries = REQ14_EVIDENCE_CONTRACT["libraries"]
        candidates = {
            library["id"]: library
            for library in REQ14_DIRECT_LIBRARY_CANDIDATES
        }
        active = {library["id"] for library in REQ14_DIRECT_LIBRARIES}
        deferred = {library["id"] for library in REQ14_DEFERRED_LIBRARIES}
        configured = {library["id"] for library in LIBRARIES}

        self.assertEqual(44, len(candidates))
        self.assertEqual(set(candidates), set(entries))
        self.assertEqual(set(), deferred)
        self.assertEqual(set(candidates), active | deferred)
        self.assertFalse(active & deferred)
        self.assertTrue(active <= configured)
        self.assertTrue(deferred.isdisjoint(configured))

        profiles = REQ14_EVIDENCE_CONTRACT["negative_profiles"]
        for library_id, entry in entries.items():
            with self.subTest(library=library_id):
                self.assertEqual(
                    {"confirmed", "bundled", "targeted"},
                    set(entry["bands"]),
                )
                self.assertEqual(
                    (
                        "evaluated"
                        if library_id in BUNDLED_IDS
                        else "not_evaluated"
                    ),
                    entry["bands"]["bundled"],
                )
                self.assertEqual(
                    (
                        "evaluated"
                        if library_id in TARGETED_IDS
                        else "not_evaluated"
                    ),
                    entry["bands"]["targeted"],
                )
                self.assertIn(entry["negative_profile"], profiles)
                self.assertTrue(
                    entry["official_reference"].startswith("https://")
                )
                self.assertEqual(
                    "not_evaluated",
                    entry["enrichment"]["operators"],
                )
                exclusions = entry.get("repository_exclusions", [])
                self.assertEqual(
                    exclusions,
                    sorted(set(exclusions)),
                )
                for full_name in exclusions:
                    self.assertEqual(full_name, full_name.casefold())
                    self.assertRegex(
                        full_name,
                        r"^[^/\s]+/[^/\s]+$",
                    )
                observation_exclusions = entry.get(
                    "discovery_observation_exclusions", []
                )
                self.assertEqual(
                    observation_exclusions,
                    sorted(
                        observation_exclusions,
                        key=lambda rule: (
                            rule["repository"],
                            rule["source"],
                            rule["signal_id"],
                            rule["matched_path"],
                            rule["matched_blob"],
                        ),
                    ),
                )
                for rule in observation_exclusions:
                    self.assertEqual(
                        {
                            "repository",
                            "source",
                            "signal_id",
                            "matched_path",
                            "matched_blob",
                        },
                        set(rule),
                    )
                    self.assertRegex(
                        rule["matched_blob"], r"^[0-9a-f]{40}$"
                    )
                if entry["status"] == "enabled":
                    self.assertEqual(
                        "evaluated", entry["bands"]["confirmed"]
                    )
                    self.assertFalse(entry["blockers"])
                    positive = entry["public_positive"]
                    self.assertIsInstance(positive, dict)
                    self.assertRegex(
                        positive["commit"], r"^[0-9a-f]{40}$"
                    )
                    self.assertIn("/", positive["repository"])
                    self.assertTrue(positive["path"])
                    self.assertTrue(positive["signal"])
                    for additional in entry.get(
                        "additional_public_positives", ()
                    ):
                        self.assertRegex(
                            additional["commit"], r"^[0-9a-f]{40}$"
                        )
                        self.assertIn(
                            "/", additional["repository"]
                        )
                        self.assertTrue(additional["path"])
                        self.assertTrue(additional["signal"])
                    expected_coverage = {"confirmed"}
                    if library_id in BUNDLED_IDS:
                        expected_coverage.add("bundled")
                    if library_id in TARGETED_IDS:
                        expected_coverage.add("targeted")
                    self.assertEqual(
                        expected_coverage,
                        set(candidates[library_id][
                            "classification_coverage"
                        ]),
                    )
                    self.assertEqual(
                        set(exclusions),
                        {
                            str(name).casefold()
                            for name in candidates[library_id].get(
                                "vendor_parents", ()
                            )
                        },
                    )
                else:
                    self.assertEqual("deferred", entry["status"])
                    self.assertEqual(
                        "not_evaluated", entry["bands"]["confirmed"]
                    )
                    self.assertIsNone(entry["public_positive"])
                    self.assertTrue(entry["blockers"])

        self.assertEqual(
            [{
                "repository": "aarnphm/aarnphm.github.io",
                "source": "github-code-search",
                "signal_id": "broad-00",
                "matched_path": "content/lectures/420/index.md",
                "matched_blob": (
                    "d9e1feb37ad1930e04e092c3dff19949c8cd684c"
                ),
            }],
            entries["cutensor"][
                "discovery_observation_exclusions"
            ],
        )
        self.assertEqual(
            ["4shen/webshell"],
            entries["cudss"]["repository_exclusions"],
        )

    def test_every_evaluated_lower_band_has_a_frozen_certification(self):
        certifications = REQ14_EVIDENCE_CONTRACT[
            "band_certifications"
        ]
        candidates = {
            library["id"]: library
            for library in REQ14_DIRECT_LIBRARY_CANDIDATES
        }
        self.assertEqual(
            BUNDLED_IDS,
            set(certifications["bundled"]["libraries"]),
        )
        self.assertEqual(
            TARGETED_IDS,
            set(certifications["targeted"]["libraries"]),
        )
        for band, expected_ids in (
            ("bundled", BUNDLED_IDS),
            ("targeted", TARGETED_IDS),
        ):
            for library_id in expected_ids:
                with self.subTest(band=band, library=library_id):
                    certification = certifications[band][
                        "libraries"
                    ][library_id]
                    runtime = candidates[library_id]
                    expected_signals = (
                        runtime["pip_pattern"]
                        if band == "bundled"
                        else runtime["targeted_build_signals"]
                    )
                    if isinstance(expected_signals, str):
                        expected_signals = [expected_signals]
                    self.assertEqual(
                        set(expected_signals),
                        set(certification["qualifying_signals"]),
                    )
                    positive = certification["public_positive"]
                    self.assertRegex(
                        positive["commit"], r"^[0-9a-f]{40}$"
                    )
                    self.assertIn("/", positive["repository"])
                    self.assertTrue(positive["path"])
                    self.assertTrue(positive["signal"])
                    if band == "bundled":
                        self.assertTrue(
                            certification["official_references"]
                        )
                        self.assertTrue(all(
                            reference.startswith("https://")
                            for reference in certification[
                                "official_references"
                            ]
                        ))

    def test_contract_signals_cover_every_runtime_qualifier(self):
        entries = REQ14_EVIDENCE_CONTRACT["libraries"]
        for library in REQ14_DIRECT_LIBRARY_CANDIDATES:
            entry = entries[library["id"]]
            discovery = "\n".join(entry["discovery_anchors"]).casefold()
            qualifying = "\n".join(
                entry["qualifying_signals"]
            ).casefold()
            runtime_qualifiers = [
                *library.get("cpp_headers", ()),
                *library.get("header_prefixes", ()),
                *library.get("import_namespaces", ()),
            ]
            with self.subTest(library=library["id"]):
                for qualifier in runtime_qualifiers:
                    self.assertIn(qualifier.casefold(), discovery)
                    if entry["status"] == "enabled":
                        self.assertIn(
                            qualifier.casefold(), qualifying
                        )
                if entry["status"] == "deferred":
                    self.assertEqual([], entry["qualifying_signals"])

    def test_reviewed_declared_packages_are_exact_bundled_evidence(self):
        libraries = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in BUNDLED_IDS
        ]
        requirements = []
        for library in libraries:
            packages = library["pip_pattern"]
            packages = (
                [packages] if isinstance(packages, str) else packages
            )
            requirements.extend(
                "%s==1.2.3" % package for package in packages
            )
            anchors = {spec.anchor for spec in signal_specs(library)}
            self.assertTrue(set(packages).issubset(anchors))
        self.assertEqual(APPROVED_PACKAGE_COUNT, len(requirements))
        temporary = _fixture({
            "requirements.txt": "\n".join(requirements) + "\n",
        })
        self.addCleanup(temporary.cleanup)
        result = scan_repo(
            "public/declared",
            libraries,
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual(BUNDLED_IDS, set(result["libraries"]))
        self.assertTrue(all(
            row["classification"] == "bundled"
            for row in result["libraries"].values()
        ))

        negative = _fixture({
            "requirements.txt": "\n".join(
                "# %s" % line for line in requirements
            ) + "\n",
            "requirements-near.txt": "\n".join(
                "%s-collision==1" % line.split("==", 1)[0]
                for line in requirements
            ) + "\n",
            "vendor/requirements.txt": "\n".join(requirements) + "\n",
            ".venv/requirements.txt": "\n".join(requirements) + "\n",
            "README.md": "\n".join(requirements) + "\n",
        })
        self.addCleanup(negative.cleanup)
        rejected = scan_repo(
            "public/declared-negative",
            libraries,
            lambda _message: None,
            checkout=negative.name,
            include_history=False,
        )
        self.assertEqual({}, rejected)

    def test_supported_manifest_surfaces_are_structural_and_exact(self):
        warp = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "warp"
        )
        temporary = _fixture({
            "pyproject.toml": (
                "[project]\n"
                'dependencies = ["warp-lang[extras]>=1.0"]\n'
                "[dependency-groups]\n"
                'test = ["warp-lang~=1.2"]\n'
            ),
            "setup.py": (
                "from setuptools import setup\n"
                "runtime = ['warp-lang @ "
                "https://example.invalid/warp.whl']\n"
                "groups = {'gpu': runtime}\n"
                "base = {'install_requires': runtime}\n"
                "metadata = {**base, 'extras_require': groups}\n"
                "setup(**metadata)\n"
            ),
            "setup.cfg": (
                "[options.extras_require]\n"
                "gpu =\n"
                "    warp-lang>=1\n"
            ),
            "requirements-dev.in": (
                "warp-lang==1.2 \\\n"
                "    --hash=sha256:abcdef\n"
            ),
            "environment.yml": (
                "channels:\n"
                "  - warp-lang\n"
                "dependencies:\n"
                "  - python=3.12\n"
                "  - pip:\n"
                "      - warp-lang>=1\n"
            ),
            "Pipfile": (
                "[packages]\n"
                'warp-lang = "*"\n'
            ),
            "Dockerfile": (
                "RUN python3 -m pip install --index-url "
                "https://pypi.org/simple 'warp-lang[extras]>=1'\n"
            ),
        })
        self.addCleanup(temporary.cleanup)
        result = scan_repo(
            "public/manifest-surfaces",
            [warp],
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual(
            "bundled", result["libraries"]["warp"]["classification"]
        )

        negative = _fixture({
            "requirements.txt": (
                "warp-lang-helper==1\n"
                "warp-lang 1.2.3\n"
                "-r warp-lang\n"
            ),
            "setup.py": (
                "from setuptools import setup\n"
                "build(install_requires=['warp-lang'])\n"
                "setup(extras_require={'warp-lang': ['pytest']})\n"
            ),
            "setup.cfg": (
                "[metadata]\n"
                "description = warp-lang\n"
            ),
            "environment.yml": (
                "channels:\n"
                "  - warp-lang\n"
                "dependencies:\n"
                "  - python=3.12\n"
            ),
            "Pipfile": (
                "[scripts]\n"
                'warp-lang = "python app.py"\n'
            ),
            "Dockerfile": (
                "RUN pip install --find-links warp-lang pytest\n"
            ),
        })
        self.addCleanup(negative.cleanup)
        rejected = scan_repo(
            "public/manifest-negatives",
            [warp],
            lambda _message: None,
            checkout=negative.name,
            include_history=False,
        )
        self.assertEqual({}, rejected)

    def test_environment_variant_is_parsed_as_declared_dependency(self):
        warp = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "warp"
        )
        temporary = _fixture({
            "environment.cuda.yaml": (
                "name: cuda\n"
                "dependencies:\n"
                "  - python=3.12\n"
                "  - pip:\n"
                "      - warp-lang>=1\n"
            ),
        })
        self.addCleanup(temporary.cleanup)
        result = scan_repo(
            "public/environment-variant",
            [warp],
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual(
            "bundled",
            result["libraries"]["warp"]["classification"],
        )

    def test_retired_nemo_and_cvcuda_package_guesses_do_not_qualify(self):
        libraries = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in {"nemo-curator", "cvcuda"}
        ]
        anchors = {
            library["id"]: {
                spec.anchor for spec in signal_specs(library)
            }
            for library in libraries
        }
        self.assertIn("nemo-curator", anchors["nemo-curator"])
        self.assertIn("cvcuda-cu12", anchors["cvcuda"])
        self.assertNotIn(
            "nvidia-nemo-curator", anchors["nemo-curator"]
        )
        self.assertNotIn("nvidia-cvcuda-cu12", anchors["cvcuda"])
        temporary = _fixture({
            "requirements.txt": (
                "nvidia-nemo-curator==1.0\n"
                "nvidia-cvcuda-cu12==1.0\n"
            ),
        })
        self.addCleanup(temporary.cleanup)
        rejected = scan_repo(
            "public/retired-package-guesses",
            libraries,
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual({}, rejected)

    def test_reviewed_cmake_targets_are_exact_targeted_evidence(self):
        libraries = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in TARGETED_IDS
        ]
        lines = []
        ordinal = 0
        for library in libraries:
            for signal_value in library["targeted_build_signals"]:
                lines.append(
                    "target_link_libraries(app%d PRIVATE %s)"
                    % (ordinal, signal_value)
                )
                ordinal += 1
            anchors = {spec.anchor for spec in signal_specs(library)}
            self.assertTrue(
                all(
                    any(
                        anchor in signal_value
                        for anchor in anchors
                    )
                    for signal_value in library[
                        "targeted_build_signals"
                    ]
                )
            )
        self.assertEqual(APPROVED_TARGET_COUNT, ordinal)
        temporary = _fixture({
            "CMakeLists.txt": "\n".join(lines) + "\n",
        })
        self.addCleanup(temporary.cleanup)
        result = scan_repo(
            "public/targeted",
            libraries,
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual(TARGETED_IDS, set(result["libraries"]))
        self.assertTrue(all(
            row["classification"] == "targeted"
            for row in result["libraries"].values()
        ))

        negative = _fixture({
            "CMakeLists.txt": "\n".join(
                [
                    "# " + line
                    for line in lines
                ]
                + [
                    'message("CUDA::cublas")',
                    "target_link_libraries(app PRIVATE CUDA::cublas_fake)",
                    (
                        "target_link_libraries("
                        "app PRIVATE CUDAToolkit::cublas)"
                    ),
                    "target_link_libraries(app PRIVATE nvinfer_helper)",
                ]
            ) + "\n",
            "vendor/CMakeLists.txt": "\n".join(lines) + "\n",
            "_build/CMakeLists.txt": "\n".join(lines) + "\n",
        })
        self.addCleanup(negative.cleanup)
        rejected = scan_repo(
            "public/targeted-negative",
            libraries,
            lambda _message: None,
            checkout=negative.name,
            include_history=False,
        )
        self.assertEqual({}, rejected)

    def test_reviewed_cmake_target_assignments_are_targeted_evidence(self):
        ids = {"cublas", "cublaslt", "gds", "npp"}
        libraries = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in ids
        ]
        temporary = _fixture({
            "CMakeLists.txt": (
                "list(APPEND runtime_libraries CUDA::cublas)\n"
                "list(APPEND libs CUDA::cublasLt${CUDA_LIB_EXT})\n"
                "if(TARGET CUDA::cuFile)\n"
                "  set(CUFILE_LIBS CUDA::cuFile)\n"
                "endif()\n"
                "set(CUDA_npp_LIBRARY CUDA::nppc CUDA::npps)\n"
            ),
        })
        self.addCleanup(temporary.cleanup)
        result = scan_repo(
            "public/cmake-assignments",
            libraries,
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual(ids, set(result["libraries"]))
        self.assertTrue(all(
            row["classification"] == "targeted"
            for row in result["libraries"].values()
        ))

        negative = _fixture({
            "CMakeLists.txt": (
                "#[=[ target_link_libraries(app CUDA::cublas) ]=]\n"
                'message("CUDA::cublasLt")\n'
                'set(DOC "CUDA::cuFile")\n'
                "list(APPEND documentation CUDA::nppc)\n"
                "target_link_libraries(app PRIVATE cuda::cublas)\n"
            ),
        })
        self.addCleanup(negative.cleanup)
        rejected = scan_repo(
            "public/cmake-assignment-negatives",
            libraries,
            lambda _message: None,
            checkout=negative.name,
            include_history=False,
        )
        self.assertEqual({}, rejected)

    def test_optical_flow_current_header_is_real_evidence(self):
        optical = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "optical-flow-sdk"
        )
        temporary = _fixture({
            "src/flow.cpp": (
                "#include <nvOpticalFlowCuda.h>\n"
                "void use_optical_flow() {}\n"
            )
        })
        self.addCleanup(temporary.cleanup)
        result = triage_tree(Path(temporary.name), [optical])
        self.assertEqual(
            ("src/flow.cpp",),
            result.direct_files["optical-flow-sdk"],
        )

    def test_copied_transformer_engine_is_not_cublasmp_adoption(self):
        cublasmp = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "cublasmp"
        )
        temporary = _fixture({
            "transformer_engine/common/CMakeLists.txt": "project(te)\n",
            "transformer_engine/common/common.h": "#pragma once\n",
            "transformer_engine/common/util/logging.h": "#pragma once\n",
            "transformer_engine/common/comm_gemm/comm_gemm.cpp": (
                "#include <cublasmp.h>\n"
            ),
            "host/use.cpp": "#include <cublasmp.h>\n",
        })
        self.addCleanup(temporary.cleanup)
        result = triage_tree(
            Path(temporary.name),
            [cublasmp],
            full_name="public/transformer-engine-copy",
        )
        self.assertEqual(
            ("host/use.cpp",), result.direct_files["cublasmp"]
        )

    def test_direct_libraries_do_not_invent_operator_labels(self):
        cublas = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "cublas"
        )
        temporary = _fixture({
            "src/use.cu": (
                "#include <cublas_v2.h>\n"
                "using Fake = Size<16>;\n"
            )
        })
        self.addCleanup(temporary.cleanup)
        result = direct_result_from_files(
            temporary.name,
            cublas,
            ["src/use.cu"],
        )
        self.assertEqual([], result["operators"])

    def test_nvcomp_python_surface_is_direct_and_local_shadow_safe(self):
        nvcomp = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "nvcomp"
        )
        external = _fixture({
            "app.py": (
                "from nvidia import nvcomp\n"
                'codec = nvcomp.Codec(algorithm="LZ4")\n'
            ),
        })
        self.addCleanup(external.cleanup)
        result = triage_tree(Path(external.name), [nvcomp])
        self.assertEqual(
            ("app.py",), result.direct_files["nvcomp"]
        )

        shadow = _fixture({
            "nvidia/nvcomp/__init__.py": (
                "class Codec:\n"
                "    pass\n"
            ),
            "app.py": (
                "from nvidia import nvcomp\n"
                "codec = nvcomp.Codec()\n"
            ),
        })
        self.addCleanup(shadow.cleanup)
        rejected = triage_tree(Path(shadow.name), [nvcomp])
        self.assertNotIn("nvcomp", rejected.direct_files)

    def test_low_level_nvcomp_and_cudss_wheels_remain_not_evaluated(self):
        libraries = [
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] in {"nvcomp", "cudss"}
        ]
        temporary = _fixture({
            "requirements.txt": (
                "nvidia-libnvcomp-cu12==5.1.0\n"
                "nvidia-cudss-cu12==0.8.0\n"
            ),
        })
        self.addCleanup(temporary.cleanup)
        result = scan_repo(
            "public/unapproved-low-level-wheels",
            libraries,
            lambda _message: None,
            checkout=temporary.name,
            include_history=False,
        )
        self.assertEqual({}, result)

    def test_adapter_named_for_external_package_is_not_its_own_shadow(self):
        cuopt = next(
            library
            for library in REQ14_DIRECT_LIBRARIES
            if library["id"] == "cuopt"
        )
        temporary = _fixture({
            "host/adapters/cuopt.py": (
                "import cuopt\n"
                "from cuopt.linear_programming import solver\n"
            )
        })
        self.addCleanup(temporary.cleanup)
        result = triage_tree(Path(temporary.name), [cuopt])
        self.assertEqual(
            ("host/adapters/cuopt.py",),
            result.direct_files["cuopt"],
        )

    def test_approved_detector_fingerprints_match_lock(self):
        self.assertTrue(
            FINGERPRINT_LOCK.exists(),
            "generate and review ops/req14_detector_fingerprints.json",
        )
        locked = json.loads(FINGERPRINT_LOCK.read_text())
        current = current_fingerprints()
        active = {library["id"] for library in REQ14_DIRECT_LIBRARIES}
        self.assertEqual(
            REQ14_EVIDENCE_CONTRACT["contract_id"],
            locked["contract_id"],
        )
        self.assertEqual(sorted(active), locked["approved_direct_ids"])
        self.assertEqual(
            {
                library_id: current.libraries[library_id].detector
                for library_id in sorted(active)
            },
            locked["detector_fingerprints"],
        )


if __name__ == "__main__":
    unittest.main()
