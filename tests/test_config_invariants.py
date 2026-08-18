"""Local-only structural checks for the detection registry."""
import re

from collector.discover import _owner_excluded
from collector.config import (
    EXCLUDED_ORGS,
    EXCLUDED_ORG_PREFIXES,
    EXCLUDED_REPOS,
    LIBRARIES,
)


def main():
    ids = [lib["id"] for lib in LIBRARIES]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"[a-z0-9_-]+", lib_id) for lib_id in ids)
    print("PASS library IDs are unique and URL-safe")

    for lib in LIBRARIES:
        for field in ("id", "name", "description", "token",
                      "released_on", "released_confidence", "tier"):
            assert lib.get(field), "%s missing %s" % (lib["id"], field)
        match = re.fullmatch(r"(\d{4})-(\d{2})", lib["released_on"])
        assert match and 1 <= int(match.group(2)) <= 12, lib
        if lib.get("language") == "python":
            assert lib.get("import_namespace") and lib.get("pip_pattern"), lib["id"]
        elif not lib.get("family"):
            assert (
                lib.get("header")
                or lib.get("cpp_headers")
                or lib.get("header_prefixes")
            ), lib["id"]
        if lib.get("cpp_headers"):
            assert all(isinstance(value, str) and value
                       for value in lib["cpp_headers"]), lib["id"]
        description = lib["description"].lower()
        assert "direct api integration" not in description, lib["id"]
        assert "direct python integration" not in description, lib["id"]
        assert "direct integration" not in description, lib["id"]
    print("PASS required fields and release dates are valid")

    child_ids = []
    for lib in LIBRARIES:
        labels = set((lib.get("components") or {}).values())
        for child in lib.get("component_children", []):
            assert child.get("id") and child.get("label") in labels, child
            child_ids.append(child["id"])
    assert len(child_ids) == len(set(child_ids))
    assert not set(ids) & set(child_ids)
    print("PASS component-child IDs and labels are consistent")

    assert all(value == value.lower() for value in EXCLUDED_ORGS)
    assert all(value == value.lower() for value in EXCLUDED_ORG_PREFIXES)
    assert all(value == value.lower() for value in EXCLUDED_REPOS)
    for lib in LIBRARIES:
        assert all(value == value.lower()
                   for value in lib.get("vendor_name_substr", ())), lib["id"]
    print("PASS case-normalized exclusion invariants hold")

    for full_name in (
        "NVIDIA/example",
        "NVIDIA-Research/example",
        "nv-internal/example",
        "CVCUDA/CV-CUDA",
    ):
        assert _owner_excluded(
            full_name,
            EXCLUDED_ORGS,
            EXCLUDED_ORG_PREFIXES,
            (),
        )
    assert not _owner_excluded(
        "public/example",
        EXCLUDED_ORGS,
        EXCLUDED_ORG_PREFIXES,
        (),
    )
    print("PASS NVIDIA-owned repositories are excluded from adoption")

    print("\n5 passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
